// SPDX-License-Identifier: MIT OR Apache-2.0
//! A **minimal, hand-rolled** DNS message codec — just enough of RFC 1035 +
//! RFC 6762 (mDNS) + RFC 6763 (DNS-SD) to advertise and browse the
//! `_postern-pair._tcp.local` service on the link-local subnet. No dependency,
//! no resolver — this only speaks the four record types DNS-SD needs (`PTR`,
//! `SRV`, `TXT`, `A`).
//!
//! This is a **byte codec only**. It carries no secrets and makes no security
//! decision; it exists so [`crate::mdns`] can find a `host:port` dial hint on
//! the LAN. All authentication happens later, in the pairing ceremony, off the
//! back of the QR-pin + SAS.
//!
//! Robustness notes (this parses attacker-influenced bytes off a multicast
//! socket, so it is written to never panic and never loop):
//! - Name decompression follows pointers but caps the jump count, so a
//!   pointer-loop cannot hang the browser.
//! - Every read is bounds-checked; a truncated or malformed packet yields
//!   `None`, never a panic.

use std::net::Ipv4Addr;

// DNS TYPE codes (the DNS-SD quartet).
pub const TYPE_A: u16 = 1;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_SRV: u16 = 33;

// CLASS IN, and the two mDNS high-bit overloads.
pub const CLASS_IN: u16 = 1;
/// mDNS "unicast-response requested" (QU) bit, set in a question's QCLASS.
pub const QU_BIT: u16 = 0x8000;
/// mDNS "cache-flush" bit, set in an answer's CLASS. Masked off on read.
pub const CACHE_FLUSH: u16 = 0x8000;

/// A pointer-loop / decompression guard: no sane name needs this many jumps.
const MAX_NAME_JUMPS: usize = 32;
/// A hard cap on labels in one name (defensive; DNS allows 127).
const MAX_LABELS: usize = 128;

/// A domain name as its sequence of labels, e.g. `["_postern-pair","_tcp","local"]`.
pub type Name = Vec<String>;

/// One parsed resource record. Unknown types are dropped on parse (we only need
/// the DNS-SD quartet), so the enum stays closed and small.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rdata {
    A(Ipv4Addr),
    Ptr(Name),
    Txt(Vec<Vec<u8>>),
    Srv { priority: u16, weight: u16, port: u16, target: Name },
}

#[derive(Clone, Debug)]
pub struct Record {
    pub name: Name,
    pub ttl: u32,
    pub data: Rdata,
}

#[derive(Clone, Debug)]
pub struct Question {
    pub name: Name,
    pub qtype: u16,
    /// QCLASS with the QU bit still present (caller may inspect it).
    pub qclass: u16,
}

/// A parsed message. We flatten all three RR sections (answer/authority/
/// additional) into one `records` list — a DNS-SD browser wants the SRV/A/TXT
/// wherever they land, and mDNS often ships them as "additionals".
#[derive(Clone, Debug, Default)]
pub struct Message {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question>,
    pub records: Vec<Record>,
}

impl Message {
    /// True if the header's QR bit says this is a response.
    pub fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

fn push_name(buf: &mut Vec<u8>, name: &[&str]) {
    // No compression on write — mDNS packets are tiny and clarity beats a few
    // saved bytes. Every label is length-prefixed; a zero byte terminates.
    for label in name {
        let bytes = label.as_bytes();
        // A label over 63 bytes is illegal; truncate defensively rather than
        // emit a corrupt packet.
        let n = bytes.len().min(63);
        buf.push(n as u8);
        buf.extend_from_slice(&bytes[..n]);
    }
    buf.push(0);
}

fn push_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}
fn push_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Build a one-shot mDNS PTR query for a service, with the QU bit set so
/// responders may unicast the answer straight back to our ephemeral port (this
/// is the "one-shot" browse mode — it does not require binding :5353).
pub fn encode_ptr_query(service: &[&str]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    push_u16(&mut buf, 0); // id (mDNS ignores it)
    push_u16(&mut buf, 0); // flags: standard query
    push_u16(&mut buf, 1); // QDCOUNT
    push_u16(&mut buf, 0); // ANCOUNT
    push_u16(&mut buf, 0); // NSCOUNT
    push_u16(&mut buf, 0); // ARCOUNT
    push_name(&mut buf, service);
    push_u16(&mut buf, TYPE_PTR);
    push_u16(&mut buf, CLASS_IN | QU_BIT);
    buf
}

/// Fields describing one advertised service instance, used to build the
/// announcement/response packet. All strings are label sequences.
pub struct Advertisement<'a> {
    /// e.g. `["MyInstance", "_postern-pair", "_tcp", "local"]`.
    pub instance: Vec<&'a str>,
    /// e.g. `["_postern-pair", "_tcp", "local"]`.
    pub service: Vec<&'a str>,
    /// e.g. `["my-host", "local"]`.
    pub host: Vec<&'a str>,
    pub addr: Ipv4Addr,
    pub port: u16,
    /// Minimal TXT (§2.3: no wallet address, no identity). Each entry is a
    /// `key=value` byte string.
    pub txt: Vec<Vec<u8>>,
    pub ttl: u32,
}

/// Build an mDNS response carrying PTR + SRV + TXT + A for one instance. Setting
/// `ttl = 0` produces a DNS-SD "goodbye" (cache eviction) packet.
pub fn encode_advertisement(ad: &Advertisement) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    push_u16(&mut buf, 0); // id
    push_u16(&mut buf, 0x8400); // flags: response + authoritative
    push_u16(&mut buf, 0); // QDCOUNT
    push_u16(&mut buf, 4); // ANCOUNT: PTR, SRV, TXT, A
    push_u16(&mut buf, 0); // NSCOUNT
    push_u16(&mut buf, 0); // ARCOUNT

    // PTR: service -> instance  (shared record: no cache-flush bit).
    push_name(&mut buf, &ad.service);
    push_u16(&mut buf, TYPE_PTR);
    push_u16(&mut buf, CLASS_IN);
    push_u32(&mut buf, ad.ttl);
    let mut rd = Vec::new();
    push_name(&mut rd, &ad.instance);
    push_u16(&mut buf, rd.len() as u16);
    buf.extend_from_slice(&rd);

    // SRV: instance -> host:port  (unique record: cache-flush bit set).
    push_name(&mut buf, &ad.instance);
    push_u16(&mut buf, TYPE_SRV);
    push_u16(&mut buf, CLASS_IN | CACHE_FLUSH);
    push_u32(&mut buf, ad.ttl);
    let mut rd = Vec::new();
    push_u16(&mut rd, 0); // priority
    push_u16(&mut rd, 0); // weight
    push_u16(&mut rd, ad.port);
    push_name(&mut rd, &ad.host);
    push_u16(&mut buf, rd.len() as u16);
    buf.extend_from_slice(&rd);

    // TXT: instance -> key/values (unique record).
    push_name(&mut buf, &ad.instance);
    push_u16(&mut buf, TYPE_TXT);
    push_u16(&mut buf, CLASS_IN | CACHE_FLUSH);
    push_u32(&mut buf, ad.ttl);
    let mut rd = Vec::new();
    if ad.txt.is_empty() {
        rd.push(0); // an empty TXT record is a single zero-length string.
    } else {
        for entry in &ad.txt {
            let n = entry.len().min(255);
            rd.push(n as u8);
            rd.extend_from_slice(&entry[..n]);
        }
    }
    push_u16(&mut buf, rd.len() as u16);
    buf.extend_from_slice(&rd);

    // A: host -> IPv4 (unique record).
    push_name(&mut buf, &ad.host);
    push_u16(&mut buf, TYPE_A);
    push_u16(&mut buf, CLASS_IN | CACHE_FLUSH);
    push_u32(&mut buf, ad.ttl);
    push_u16(&mut buf, 4);
    buf.extend_from_slice(&ad.addr.octets());

    buf
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Read a (possibly compressed) name starting at `pos`. Returns the labels and
/// the offset just past the name *in the record stream* (i.e. past the first
/// pointer, per DNS rules). Bounds- and loop-checked; returns `None` on any
/// malformed input.
fn read_name(buf: &[u8], mut pos: usize) -> Option<(Name, usize)> {
    let mut labels: Name = Vec::new();
    let mut jumps = 0usize;
    // The offset we return to the caller: fixed at the position right after the
    // first pointer we follow (or after the terminating zero if no pointer).
    let mut next: Option<usize> = None;

    loop {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        match len & 0xC0 {
            0x00 => {
                // A normal label.
                if labels.len() >= MAX_LABELS {
                    return None;
                }
                let start = pos + 1;
                let end = start.checked_add(len)?;
                let raw = buf.get(start..end)?;
                labels.push(String::from_utf8_lossy(raw).into_owned());
                pos = end;
            }
            0xC0 => {
                // A compression pointer: 14-bit offset from the two low bits +
                // the next byte.
                let b2 = *buf.get(pos + 1)? as usize;
                let target = ((len & 0x3F) << 8) | b2;
                if next.is_none() {
                    next = Some(pos + 2);
                }
                jumps += 1;
                if jumps > MAX_NAME_JUMPS {
                    return None; // pointer loop — refuse.
                }
                pos = target;
            }
            _ => return None, // 0x40/0x80 are reserved — reject.
        }
    }
    Some((labels, next.unwrap_or(pos)))
}

fn read_u16(buf: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes(buf.get(pos..pos + 2)?.try_into().ok()?))
}
fn read_u32(buf: &[u8], pos: usize) -> Option<u32> {
    Some(u32::from_be_bytes(buf.get(pos..pos + 4)?.try_into().ok()?))
}

/// Parse a whole DNS/mDNS message. Returns `None` (never panics) on truncation
/// or malformed structure. Unknown record types are skipped by rdlength.
pub fn parse(buf: &[u8]) -> Option<Message> {
    if buf.len() < 12 {
        return None;
    }
    let id = read_u16(buf, 0)?;
    let flags = read_u16(buf, 2)?;
    let qd = read_u16(buf, 4)? as usize;
    let an = read_u16(buf, 6)? as usize;
    let ns = read_u16(buf, 8)? as usize;
    let ar = read_u16(buf, 10)? as usize;
    let mut pos = 12;

    let mut msg = Message { id, flags, ..Default::default() };

    for _ in 0..qd {
        let (name, np) = read_name(buf, pos)?;
        pos = np;
        let qtype = read_u16(buf, pos)?;
        let qclass = read_u16(buf, pos + 2)?;
        pos += 4;
        msg.questions.push(Question { name, qtype, qclass });
    }

    let total_rr = an.saturating_add(ns).saturating_add(ar);
    for _ in 0..total_rr {
        let (name, np) = read_name(buf, pos)?;
        pos = np;
        let rtype = read_u16(buf, pos)?;
        let _class = read_u16(buf, pos + 2)?;
        let ttl = read_u32(buf, pos + 4)?;
        let rdlen = read_u16(buf, pos + 8)? as usize;
        let rdstart = pos + 10;
        let rdend = rdstart.checked_add(rdlen)?;
        if rdend > buf.len() {
            return None;
        }
        // Advance past this record regardless of whether we understand it.
        let next_pos = rdend;

        let data = match rtype {
            TYPE_A if rdlen == 4 => {
                let o = &buf[rdstart..rdend];
                Some(Rdata::A(Ipv4Addr::new(o[0], o[1], o[2], o[3])))
            }
            TYPE_PTR => read_name(buf, rdstart).map(|(n, _)| Rdata::Ptr(n)),
            TYPE_SRV if rdlen >= 6 => {
                let priority = read_u16(buf, rdstart)?;
                let weight = read_u16(buf, rdstart + 2)?;
                let port = read_u16(buf, rdstart + 4)?;
                let (target, _) = read_name(buf, rdstart + 6)?;
                Some(Rdata::Srv { priority, weight, port, target })
            }
            TYPE_TXT => {
                let mut entries = Vec::new();
                let mut p = rdstart;
                while p < rdend {
                    let l = buf[p] as usize;
                    p += 1;
                    let e = (p + l).min(rdend);
                    entries.push(buf[p..e].to_vec());
                    p = e;
                }
                Some(Rdata::Txt(entries))
            }
            _ => None, // unknown/other type: skip, keep parsing.
        };

        if let Some(data) = data {
            msg.records.push(Record { name, ttl, data });
        }
        pos = next_pos;
    }

    Some(msg)
}

/// Case-insensitive label-sequence comparison (DNS names are case-insensitive).
pub fn names_eq(a: &[String], b: &[&str]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE: &[&str] = &["_postern-pair", "_tcp", "local"];

    #[test]
    fn ptr_query_roundtrips() {
        let q = encode_ptr_query(SERVICE);
        let m = parse(&q).expect("parse query");
        assert!(!m.is_response());
        assert_eq!(m.questions.len(), 1);
        assert!(names_eq(&m.questions[0].name, SERVICE));
        assert_eq!(m.questions[0].qtype, TYPE_PTR);
        assert_eq!(m.questions[0].qclass & QU_BIT, QU_BIT);
    }

    #[test]
    fn advertisement_roundtrips_all_four_records() {
        let ad = Advertisement {
            instance: vec!["Tiago-ThinkPad", "_postern-pair", "_tcp", "local"],
            service: vec!["_postern-pair", "_tcp", "local"],
            host: vec!["thinkpad", "local"],
            addr: Ipv4Addr::new(192, 168, 1, 20),
            port: 47001,
            txt: vec![b"v=1".to_vec(), b"tag=abc123".to_vec()],
            ttl: 120,
        };
        let bytes = encode_advertisement(&ad);
        let m = parse(&bytes).expect("parse response");
        assert!(m.is_response());

        let mut saw_ptr = false;
        let mut saw_srv = false;
        let mut saw_txt = false;
        let mut saw_a = false;
        for r in &m.records {
            match &r.data {
                Rdata::Ptr(n) => {
                    saw_ptr = true;
                    assert!(names_eq(n, &["Tiago-ThinkPad", "_postern-pair", "_tcp", "local"]));
                }
                Rdata::Srv { port, target, .. } => {
                    saw_srv = true;
                    assert_eq!(*port, 47001);
                    assert!(names_eq(target, &["thinkpad", "local"]));
                }
                Rdata::Txt(entries) => {
                    saw_txt = true;
                    assert!(entries.iter().any(|e| e == b"tag=abc123"));
                }
                Rdata::A(ip) => {
                    saw_a = true;
                    assert_eq!(*ip, Ipv4Addr::new(192, 168, 1, 20));
                }
            }
        }
        assert!(saw_ptr && saw_srv && saw_txt && saw_a, "all four records must parse");
    }

    #[test]
    fn goodbye_is_ttl_zero() {
        let ad = Advertisement {
            instance: vec!["x", "_postern-pair", "_tcp", "local"],
            service: vec!["_postern-pair", "_tcp", "local"],
            host: vec!["h", "local"],
            addr: Ipv4Addr::LOCALHOST,
            port: 1,
            txt: vec![],
            ttl: 0,
        };
        let m = parse(&encode_advertisement(&ad)).unwrap();
        assert!(m.records.iter().all(|r| r.ttl == 0));
    }

    #[test]
    fn truncated_packet_is_none_not_panic() {
        let q = encode_ptr_query(SERVICE);
        for cut in 0..q.len() {
            // Must never panic, whatever the truncation point.
            let _ = parse(&q[..cut]);
        }
    }

    #[test]
    fn pointer_loop_is_refused() {
        // Header claiming one answer, whose name is a pointer to itself.
        let mut buf = Vec::new();
        push_u16(&mut buf, 0);
        push_u16(&mut buf, 0x8000);
        push_u16(&mut buf, 0); // qd
        push_u16(&mut buf, 1); // an
        push_u16(&mut buf, 0);
        push_u16(&mut buf, 0);
        let name_at = buf.len();
        // pointer to itself
        buf.push(0xC0);
        buf.push(name_at as u8);
        // Parsing must terminate (return None), not hang.
        assert!(parse(&buf).is_none());
    }
}
