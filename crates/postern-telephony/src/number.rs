//! Pure dial-string validation — no D-Bus, host-testable everywhere.
//!
//! The dialer must never hand an arbitrary string to the modem: a permissive
//! `dial()` lets any confused/compromised call site dial premium or
//! carrier-service numbers with garbage the modem may misinterpret. This
//! module normalizes user-entered numbers to a strict `+`-and-digits form and
//! recognizes the well-known emergency short codes, so the emergency-only
//! gate in [`crate::voice`] can FAIL CLOSED (deny non-emergency dialing when
//! the modem's state cannot be read) without ever blocking a genuine
//! emergency call.

/// Well-known emergency numbers. GSM (3GPP TS 22.101) mandates that 112 and
/// 911 always work — even without a SIM; the rest are the major regional
/// codes (UK/HK 999, AU 000, NZ 111, JP 110/118/119, EU 112). The SIM/carrier
/// may accept additional region-specific codes; this list only decides what
/// the *app* still allows when the modem reports (or cannot report)
/// emergency-only state — it never blocks numbers in normal service.
pub const EMERGENCY_NUMBERS: &[&str] = &["112", "911", "999", "000", "111", "110", "118", "119"];

/// True if `number` (already normalized or raw) is a recognized emergency
/// short code. A leading `+` never appears on emergency codes.
pub fn is_emergency_number(number: &str) -> bool {
    EMERGENCY_NUMBERS.contains(&number)
}

/// Normalize a user-entered dial string to strict `+`-and-digits form.
///
/// Accepts common visual separators (space, `-`, `.`, `(`, `)`) and strips
/// them; the result must then be an optional leading `+` followed by 2–15
/// ASCII digits (E.164 caps national significant numbers at 15). Anything
/// else — letters, DTMF pause characters, `*`/`#` service codes, empty input
/// — is rejected with `None`. `*#…#` MMI/supplementary-service codes are
/// deliberately not dialable through this API.
pub fn normalize_dial_string(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    for (idx, ch) in raw.trim().chars().enumerate() {
        match ch {
            '+' if idx == 0 => out.push('+'),
            '0'..='9' => out.push(ch),
            ' ' | '-' | '.' | '(' | ')' => {} // visual separators
            _ => return None,
        }
    }
    let digits = out.strip_prefix('+').unwrap_or(&out);
    if digits.len() < 2 || digits.len() > 15 || digits.is_empty() {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_common_formats() {
        assert_eq!(normalize_dial_string("+1 (555) 123-4567").as_deref(), Some("+15551234567"));
        assert_eq!(normalize_dial_string("555.123.4567").as_deref(), Some("5551234567"));
        assert_eq!(normalize_dial_string("911").as_deref(), Some("911"));
        assert_eq!(normalize_dial_string("  +49 30 901820  ").as_deref(), Some("+4930901820"));
    }

    #[test]
    fn rejects_garbage_and_service_codes() {
        assert_eq!(normalize_dial_string(""), None);
        assert_eq!(normalize_dial_string("+"), None);
        assert_eq!(normalize_dial_string("5"), None); // too short
        assert_eq!(normalize_dial_string("+1234567890123456"), None); // > 15 digits
        assert_eq!(normalize_dial_string("*#06#"), None); // MMI code
        assert_eq!(normalize_dial_string("555,1234"), None); // DTMF pause
        assert_eq!(normalize_dial_string("CALL ME"), None);
        assert_eq!(normalize_dial_string("55+512"), None); // + not leading
        assert_eq!(normalize_dial_string("javascript:alert(1)"), None);
    }

    #[test]
    fn emergency_codes_recognized() {
        for n in ["112", "911", "999", "000", "111", "110", "118", "119"] {
            assert!(is_emergency_number(n), "{n} must be emergency");
            assert!(normalize_dial_string(n).is_some(), "{n} must normalize");
        }
        assert!(!is_emergency_number("+15551234567"));
        assert!(!is_emergency_number("9111"));
        assert!(!is_emergency_number(""));
    }
}
