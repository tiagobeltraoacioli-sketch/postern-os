//! **Postern SMS** — the carrier-SMS app core.
//!
//! Send/receive text messages via the mobile operator, through the modem/SIM,
//! by driving ModemManager's `Modem.Messaging` + `Sms` D-Bus objects. This is
//! real client code, not a mock — but it can only *connect* on a Linux phone
//! with ModemManager, a modem, and a SIM registered on a network. On any
//! other host, [`SmsService::connect`] fails with [`TelephonyError::NoModem`].
//!
//! Privacy honesty: every SMS leaves the device in plaintext to the carrier.
//! This app hardens the LOCAL side only (encrypted store, no cloud, no
//! telemetry) and the UI labels the transport "Carrier SMS — not private".

use crate::mm::{MessagingProxy, MmObjectManagerProxy, SmsProxy};
use crate::store::TelephonyStore;
use crate::types::{Direction, SmsMessage, SmsState};
use crate::TelephonyError;
use std::collections::HashMap;
use zbus::zvariant::{OwnedObjectPath, Value};
use zbus::Connection;

/// Interface name a managed object must expose to count as a modem.
const MODEM_IFACE: &str = "org.freedesktop.ModemManager1.Modem";

/// Discover the first modem exported by ModemManager on the system bus.
pub(crate) async fn first_modem(conn: &Connection) -> Result<OwnedObjectPath, TelephonyError> {
    let om = MmObjectManagerProxy::new(conn).await?;
    let objects = om.get_managed_objects().await?;
    objects
        .into_iter()
        .find(|(_, ifaces)| ifaces.contains_key(MODEM_IFACE))
        .map(|(path, _)| path)
        .ok_or(TelephonyError::NoModem)
}

/// The SMS app's service handle: one modem's messaging surface.
pub struct SmsService {
    conn: Connection,
    modem: OwnedObjectPath,
}

impl SmsService {
    /// Connect to the system bus and bind the first modem.
    /// **Requires a real device** — errors with `NoModem`/`Dbus` elsewhere.
    pub async fn connect() -> Result<Self, TelephonyError> {
        let conn = Connection::system().await?;
        let modem = first_modem(&conn).await?;
        Ok(Self { conn, modem })
    }

    async fn messaging(&self) -> Result<MessagingProxy<'_>, TelephonyError> {
        Ok(MessagingProxy::builder(&self.conn)
            .path(self.modem.clone())?
            .build()
            .await?)
    }

    /// Send an SMS via the carrier: create the message object, then hand it
    /// to the network. On success the outgoing message is appended to the
    /// encrypted store so history survives only AEAD-sealed.
    pub async fn send_text(
        &self,
        number: &str,
        text: &str,
        store: &mut dyn TelephonyStore,
    ) -> Result<(), TelephonyError> {
        let messaging = self.messaging().await?;

        let number_v = Value::from(number);
        let text_v = Value::from(text);
        let mut props: HashMap<&str, &Value<'_>> = HashMap::new();
        props.insert("number", &number_v);
        props.insert("text", &text_v);

        let sms_path = messaging.create(props).await?;
        let sms = SmsProxy::builder(&self.conn).path(sms_path)?.build().await?;
        sms.send().await?; // ← the plaintext leaves for the operator here

        store.add_sms(SmsMessage {
            number: number.to_string(),
            body: text.to_string(),
            direction: Direction::Outgoing,
            state: SmsState::Sent,
            timestamp: None,
        });
        Ok(())
    }

    /// Read every message currently on the modem/SIM into the model —
    /// used on startup to sync the encrypted store, after which messages
    /// can be deleted from the (unencrypted!) modem/SIM storage.
    pub async fn fetch_all(&self) -> Result<Vec<SmsMessage>, TelephonyError> {
        let messaging = self.messaging().await?;
        let mut out = Vec::new();
        for path in messaging.list().await? {
            let sms = SmsProxy::builder(&self.conn).path(path)?.build().await?;
            let pdu = sms.pdu_type().await.unwrap_or(0);
            out.push(SmsMessage {
                number: sms.number().await?,
                body: sms.text().await?,
                // MMSmsPduType: 1 = deliver (incoming), 2 = submit (outgoing)
                direction: if pdu == 2 { Direction::Outgoing } else { Direction::Incoming },
                state: SmsState::from_mm(sms.state().await?),
                timestamp: sms.timestamp().await.ok().filter(|t| !t.is_empty()),
            });
        }
        Ok(out)
    }

    /// Block until the next incoming SMS arrives from the network, persist it
    /// to the encrypted store, and return it. The app's receive loop calls
    /// this forever; ModemManager signals `Added(path, received=true)`.
    pub async fn next_incoming(
        &self,
        store: &mut dyn TelephonyStore,
    ) -> Result<SmsMessage, TelephonyError> {
        use futures_util::StreamExt as _;
        let messaging = self.messaging().await?;
        let mut added = messaging.receive_added().await?;
        while let Some(sig) = added.next().await {
            let args = sig.args()?;
            if !args.received {
                continue; // our own outgoing create — not an arrival
            }
            let sms = SmsProxy::builder(&self.conn)
                .path(args.path.clone())?
                .build()
                .await?;
            let msg = SmsMessage {
                number: sms.number().await?,
                body: sms.text().await?,
                direction: Direction::Incoming,
                state: SmsState::from_mm(sms.state().await?),
                timestamp: sms.timestamp().await.ok().filter(|t| !t.is_empty()),
            };
            store.add_sms(msg.clone());
            return Ok(msg);
        }
        Err(TelephonyError::NotReady("signal stream ended".into()))
    }
}
