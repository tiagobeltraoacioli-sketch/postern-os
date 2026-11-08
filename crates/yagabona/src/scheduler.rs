//! The scheduler skeleton — parse a schedule, fire the task inside its grant.
//!
//! A [`Schedule`] is parsed from the manifest string (`"daily 02:30"`,
//! `"hourly"`, `"hourly :15"`, `"weekly mon 09:00"`). [`Schedule::next_fire`]
//! computes the next fire instant after a given time.
//!
//! A [`Runner`] ties together a [`Grant`], a schedule, a [`Task`], and a
//! [`Trail`]. On each [`Runner::poll`] it re-checks expiry and revocation
//! *before* running: an expired or revoked grant is treated as never given, and
//! the task never runs. When a task is due it runs strictly inside a
//! [`ScopedFs`] and every outcome is written to the trail.
//!
//! # Safety
//!
//! [`Task`] is a **trait**, not an exec of arbitrary commands. This crate never
//! spawns a shell or runs untrusted code. Real task bodies are implemented in
//! Rust against the scoped filesystem; the default here is a benign no-op.

use time::format_description::well_known::Rfc3339;
use time::{Date, Duration, OffsetDateTime, Time, Weekday};

use crate::fsboundary::ScopedFs;
use crate::threshold::Grant;
use crate::trail::{Record, Trail};

/// A parsed schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Schedule {
    /// Every day at the given wall-clock time (UTC).
    Daily { time: Time },
    /// Every hour at the given minute past the hour.
    Hourly { minute: u8 },
    /// Every week on `day` at `time` (UTC).
    Weekly { day: Weekday, time: Time },
}

/// Errors from parsing a schedule string.
#[derive(Debug, thiserror::Error)]
pub enum ScheduleError {
    #[error("empty schedule string")]
    Empty,
    #[error("unknown schedule kind {kind:?} (expected daily|hourly|weekly)")]
    UnknownKind { kind: String },
    #[error("malformed schedule {input:?}: {detail}")]
    Malformed { input: String, detail: String },
}

impl Schedule {
    /// Parse a schedule string such as `"daily 02:30"`.
    pub fn parse(input: &str) -> Result<Schedule, ScheduleError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(ScheduleError::Empty);
        }
        let mut parts = trimmed.split_whitespace();
        let kind = parts.next().unwrap().to_ascii_lowercase();
        match kind.as_str() {
            "daily" => {
                let hm = parts.next().ok_or_else(|| malformed(input, "expected HH:MM"))?;
                Ok(Schedule::Daily {
                    time: parse_hm(input, hm)?,
                })
            }
            "hourly" => {
                // "hourly" or "hourly :MM" or "hourly MM".
                let minute = match parts.next() {
                    None => 0u8,
                    Some(m) => {
                        let m = m.trim_start_matches(':');
                        m.parse::<u8>()
                            .ok()
                            .filter(|v| *v < 60)
                            .ok_or_else(|| malformed(input, "minute must be 0..=59"))?
                    }
                };
                Ok(Schedule::Hourly { minute })
            }
            "weekly" => {
                let dow = parts.next().ok_or_else(|| malformed(input, "expected weekday"))?;
                let hm = parts.next().ok_or_else(|| malformed(input, "expected HH:MM"))?;
                Ok(Schedule::Weekly {
                    day: parse_weekday(input, dow)?,
                    time: parse_hm(input, hm)?,
                })
            }
            other => Err(ScheduleError::UnknownKind {
                kind: other.to_string(),
            }),
        }
    }

    /// The next fire instant strictly after `after` (UTC).
    pub fn next_fire(&self, after: OffsetDateTime) -> OffsetDateTime {
        match self {
            Schedule::Daily { time } => {
                let today = after.date().with_time(*time).assume_utc();
                if today > after {
                    today
                } else {
                    after
                        .date()
                        .next_day()
                        .unwrap_or(after.date())
                        .with_time(*time)
                        .assume_utc()
                }
            }
            Schedule::Hourly { minute } => {
                let candidate = after
                    .replace_time(Time::from_hms(after.hour(), *minute, 0).unwrap_or(Time::MIDNIGHT));
                if candidate > after {
                    candidate
                } else {
                    candidate + Duration::hours(1)
                }
            }
            Schedule::Weekly { day, time } => {
                let mut date: Date = after.date();
                // Advance day-by-day until we land on the right weekday with a
                // fire time strictly after `after`.
                loop {
                    if date.weekday() == *day {
                        let candidate = date.with_time(*time).assume_utc();
                        if candidate > after {
                            return candidate;
                        }
                    }
                    date = match date.next_day() {
                        Some(d) => d,
                        None => return after, // saturated far future; unreachable in practice
                    };
                }
            }
        }
    }
}

fn malformed(input: &str, detail: &str) -> ScheduleError {
    ScheduleError::Malformed {
        input: input.to_string(),
        detail: detail.to_string(),
    }
}

fn parse_hm(input: &str, hm: &str) -> Result<Time, ScheduleError> {
    let (h, m) = hm
        .split_once(':')
        .ok_or_else(|| malformed(input, "time must be HH:MM"))?;
    let h: u8 = h.parse().map_err(|_| malformed(input, "bad hour"))?;
    let m: u8 = m.parse().map_err(|_| malformed(input, "bad minute"))?;
    Time::from_hms(h, m, 0).map_err(|_| malformed(input, "hour 0..=23, minute 0..=59"))
}

fn parse_weekday(input: &str, dow: &str) -> Result<Weekday, ScheduleError> {
    Ok(match dow.to_ascii_lowercase().as_str() {
        "mon" | "monday" => Weekday::Monday,
        "tue" | "tuesday" => Weekday::Tuesday,
        "wed" | "wednesday" => Weekday::Wednesday,
        "thu" | "thursday" => Weekday::Thursday,
        "fri" | "friday" => Weekday::Friday,
        "sat" | "saturday" => Weekday::Saturday,
        "sun" | "sunday" => Weekday::Sunday,
        other => {
            return Err(ScheduleError::Malformed {
                input: input.to_string(),
                detail: format!("unknown weekday {other:?}"),
            })
        }
    })
}

/// Error returned by a [`Task`] body.
#[derive(Debug, thiserror::Error)]
#[error("task failed: {0}")]
pub struct TaskError(pub String);

/// A schedulable unit of work. Implementors run strictly inside the scoped
/// filesystem and return a short result summary. This is deliberately a trait
/// and not an arbitrary command — Yagabona never execs untrusted code.
pub trait Task {
    /// Execute the task within `grant`, using `fs` for all filesystem access.
    /// Return a short human summary (e.g. `"indexed 128 notes"`).
    fn run(&mut self, grant: &Grant, fs: &ScopedFs) -> Result<String, TaskError>;
}

/// A safe default task that does nothing. Useful as a stand-in until a real
/// task body exists.
#[derive(Debug, Default)]
pub struct NoopTask;

impl Task for NoopTask {
    fn run(&mut self, _grant: &Grant, _fs: &ScopedFs) -> Result<String, TaskError> {
        Ok("noop".to_string())
    }
}

/// The result of polling a [`Runner`].
#[derive(Debug)]
pub enum PollResult {
    /// Not yet due; nothing happened.
    NotDue,
    /// The task fired; carries the trail entry written for the run.
    Fired(crate::trail::Entry),
    /// The grant has expired; the runner is done and wrote an `"expired"` entry.
    Expired(crate::trail::Entry),
    /// The grant was revoked; the runner is done and wrote a `"revoked"` entry.
    Revoked(crate::trail::Entry),
}

/// Ties a grant, schedule, task, and trail together and drives them forward.
pub struct Runner<'g, T: Task> {
    grant: &'g Grant,
    schedule: Schedule,
    task: T,
    trail: Trail,
    next_fire: OffsetDateTime,
    revoked: bool,
    done: bool,
}

impl<'g, T: Task> Runner<'g, T> {
    /// Build a runner. The schedule is parsed from the grant's manifest; the
    /// first fire is computed relative to `now`.
    pub fn new(grant: &'g Grant, task: T, trail: Trail, now: OffsetDateTime) -> Result<Self, ScheduleError> {
        let schedule = Schedule::parse(&grant.manifest.task.schedule)?;
        let next_fire = schedule.next_fire(now);
        Ok(Runner {
            grant,
            schedule,
            task,
            trail,
            next_fire,
            revoked: false,
            done: false,
        })
    }

    /// The instant the runner will next fire.
    pub fn next_fire(&self) -> OffsetDateTime {
        self.next_fire
    }

    /// Mark this grant revoked. The next [`poll`](Runner::poll) will stop.
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Advance the runner as of `now`.
    ///
    /// Re-checks revocation and expiry *before* running. If due and still valid,
    /// runs the task inside a [`ScopedFs`] and records the outcome. A finished
    /// runner (expired/revoked) returns [`PollResult::NotDue`] thereafter.
    pub fn poll(&mut self, now: OffsetDateTime) -> Result<PollResult, crate::trail::ChainError> {
        if self.done {
            return Ok(PollResult::NotDue);
        }

        if self.revoked {
            self.done = true;
            let entry = self.trail.append(self.mk_record(now, "revoked", &[], "grant revoked"))?;
            return Ok(PollResult::Revoked(entry));
        }

        if now >= self.grant.expires {
            self.done = true;
            let entry = self.trail.append(self.mk_record(now, "expired", &[], "grant expired"))?;
            return Ok(PollResult::Expired(entry));
        }

        if now < self.next_fire {
            return Ok(PollResult::NotDue);
        }

        // Due, valid, not revoked: run inside the scoped boundary.
        let fs = ScopedFs::new(self.grant);
        let (action, result) = match self.task.run(self.grant, &fs) {
            Ok(summary) => ("run".to_string(), summary),
            Err(e) => ("run".to_string(), format!("error: {e}")),
        };
        // Record what the task ACTUALLY touched through the boundary — never
        // the grant's whole `write_paths` list. Recording the granted list
        // OVERSTATED the audit trail: it claimed every granted path was
        // touched on every run, even by a task that opened nothing.
        // (Caveat kept honest: this sees only accesses made via `ScopedFs`;
        // it is a userland boundary, not an OS sandbox — see fsboundary.rs.)
        let paths: Vec<String> = fs.touched_paths();
        let entry = self.trail.append(self.mk_record(now, &action, &paths, &result))?;

        // Schedule the following fire strictly after this one.
        self.next_fire = self.schedule.next_fire(now);
        Ok(PollResult::Fired(entry))
    }

    fn mk_record(&self, now: OffsetDateTime, action: &str, paths: &[String], result: &str) -> Record {
        Record {
            ts: now.format(&Rfc3339).unwrap_or_else(|_| now.to_string()),
            task: self.grant.manifest.task.name.clone(),
            action: action.to_string(),
            paths_touched: paths.to_vec(),
            network_used: self.grant.network.destination().to_string(),
            result: result.to_string(),
        }
    }

    /// Block until the next fire, poll, and repeat — the real daemon loop.
    ///
    /// This is the aspirational always-on path. It sleeps in wall-clock time; it
    /// is intentionally *not* exercised by the unit tests (which drive
    /// [`poll`](Runner::poll) with injected `now`). Returns when the grant
    /// expires or is revoked.
    pub fn run_blocking(&mut self) -> Result<PollResult, crate::trail::ChainError> {
        loop {
            let now = OffsetDateTime::now_utc();
            match self.poll(now)? {
                PollResult::NotDue => {
                    let wait = self.next_fire.min(self.grant.expires) - now;
                    let secs = wait.whole_seconds().max(0) as u64;
                    std::thread::sleep(std::time::Duration::from_secs(secs.min(3600)));
                }
                terminal @ (PollResult::Expired(_) | PollResult::Revoked(_)) => {
                    return Ok(terminal);
                }
                PollResult::Fired(_) => {
                    // loop again; next_fire has advanced.
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_daily() {
        assert_eq!(
            Schedule::parse("daily 02:30").unwrap(),
            Schedule::Daily {
                time: Time::from_hms(2, 30, 0).unwrap()
            }
        );
    }

    #[test]
    fn daily_next_fire_rolls_to_tomorrow() {
        let sched = Schedule::parse("daily 02:30").unwrap();
        // now is 03:00 UTC, so the 02:30 fire is tomorrow.
        let now = OffsetDateTime::parse("2026-07-11T03:00:00Z", &Rfc3339).unwrap();
        let next = sched.next_fire(now);
        assert_eq!(next.date().to_string(), "2026-07-12");
        assert_eq!(next.hour(), 2);
        assert_eq!(next.minute(), 30);
    }

    #[test]
    fn daily_next_fire_is_today_when_earlier() {
        let sched = Schedule::parse("daily 02:30").unwrap();
        let now = OffsetDateTime::parse("2026-07-11T01:00:00Z", &Rfc3339).unwrap();
        let next = sched.next_fire(now);
        assert_eq!(next.date().to_string(), "2026-07-11");
    }

    #[test]
    fn rejects_unknown_kind() {
        assert!(matches!(
            Schedule::parse("fortnightly 02:30"),
            Err(ScheduleError::UnknownKind { .. })
        ));
    }
}
