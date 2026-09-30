//! Timeline Builder Module
//!
//! Aggregates and correlates forensic events from heterogeneous sources:
//! - Registry
//! - Eventlog
//! - Prefetch
//! - Browser history
//! - Shellbags
//! - Master File Table (MFT)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Supported forensic timeline sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TimelineSourceType {
    Registry,
    Eventlog,
    Prefetch,
    Browser,
    Shellbags,
    Mft,
}

impl std::fmt::Display for TimelineSourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimelineSourceType::Registry => write!(f, "REGISTRY"),
            TimelineSourceType::Eventlog => write!(f, "EVENTLOG"),
            TimelineSourceType::Prefetch => write!(f, "PREFETCH"),
            TimelineSourceType::Browser => write!(f, "BROWSER"),
            TimelineSourceType::Shellbags => write!(f, "SHELLBAGS"),
            TimelineSourceType::Mft => write!(f, "MFT"),
        }
    }
}

/// A normalized forensic timeline event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: String,
    pub source: TimelineSourceType,
    pub event_type: String,
    pub description: String,
    pub host: String,
    pub extra: HashMap<String, String>,
}

/// A complete forensic event timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timeline {
    pub host: String,
    pub from_time: String,
    pub to_time: String,
    pub events: Vec<TimelineEvent>,
}

impl Timeline {
    /// Create a new timeline for a specific host and time range.
    pub fn new(host: &str, from_time: &str, to_time: &str) -> Self {
        Self {
            host: host.to_string(),
            from_time: from_time.to_string(),
            to_time: to_time.to_string(),
            events: Vec::new(),
        }
    }

    /// Add an event to the timeline.
    pub fn add_event(&mut self, event: TimelineEvent) {
        self.events.push(event);
    }

    /// Sort events chronologically by ISO 8601 timestamp.
    pub fn sort_chronologically(&mut self) {
        self.events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    }

    /// Export the timeline to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Export events in CSV format.
    pub fn to_csv(&self) -> String {
        let mut csv = String::from("timestamp,source,event_type,host,description\n");
        for ev in &self.events {
            let desc_escaped = ev.description.replace('"', "\"\"");
            csv.push_str(&format!(
                "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
                ev.timestamp, ev.source, ev.event_type, ev.host, desc_escaped
            ));
        }
        csv
    }

    /// Filter events by source.
    pub fn filter_by_source(&self, source: TimelineSourceType) -> Vec<&TimelineEvent> {
        self.events.iter().filter(|e| e.source == source).collect()
    }
}

/// Build a forensic timeline from specified sources for a host.
pub fn build_timeline(
    host: &str,
    from_time: &str,
    to_time: &str,
    sources: &[TimelineSourceType],
) -> Result<Timeline, String> {
    let mut timeline = Timeline::new(host, from_time, to_time);

    // Mock/Stub extraction across sources
    for source in sources {
        match source {
            TimelineSourceType::Eventlog => {
                timeline.add_event(TimelineEvent {
                    timestamp: from_time.to_string(),
                    source: *source,
                    event_type: "LogonSuccess".into(),
                    description: format!("User logon event 4624 recorded on {host}"),
                    host: host.to_string(),
                    extra: HashMap::new(),
                });
            }
            TimelineSourceType::Prefetch => {
                timeline.add_event(TimelineEvent {
                    timestamp: to_time.to_string(),
                    source: *source,
                    event_type: "ProcessExecution".into(),
                    description: format!("Execution artifact detected for cmd.exe on {host}"),
                    host: host.to_string(),
                    extra: HashMap::new(),
                });
            }
            TimelineSourceType::Registry => {
                timeline.add_event(TimelineEvent {
                    timestamp: from_time.to_string(),
                    source: *source,
                    event_type: "KeyModification".into(),
                    description: format!("Run key persistence check on {host}"),
                    host: host.to_string(),
                    extra: HashMap::new(),
                });
            }
            TimelineSourceType::Browser => {
                timeline.add_event(TimelineEvent {
                    timestamp: from_time.to_string(),
                    source: *source,
                    event_type: "UrlVisit".into(),
                    description: format!("History navigation record on {host}"),
                    host: host.to_string(),
                    extra: HashMap::new(),
                });
            }
            TimelineSourceType::Shellbags => {
                timeline.add_event(TimelineEvent {
                    timestamp: from_time.to_string(),
                    source: *source,
                    event_type: "FolderAccess".into(),
                    description: format!("Shellbag folder interaction on {host}"),
                    host: host.to_string(),
                    extra: HashMap::new(),
                });
            }
            TimelineSourceType::Mft => {
                timeline.add_event(TimelineEvent {
                    timestamp: to_time.to_string(),
                    source: *source,
                    event_type: "FileCreated".into(),
                    description: format!("$MFT $STANDARD_INFORMATION record on {host}"),
                    host: host.to_string(),
                    extra: HashMap::new(),
                });
            }
        }
    }

    timeline.sort_chronologically();
    Ok(timeline)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeline_sorting_and_csv() {
        let mut tl = Timeline::new("WORKSTATION-01", "2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z");
        tl.add_event(TimelineEvent {
            timestamp: "2026-09-01T12:00:00Z".into(),
            source: TimelineSourceType::Prefetch,
            event_type: "Execution".into(),
            description: "powershell.exe executed".into(),
            host: "WORKSTATION-01".into(),
            extra: HashMap::new(),
        });
        tl.add_event(TimelineEvent {
            timestamp: "2026-09-01T08:00:00Z".into(),
            source: TimelineSourceType::Eventlog,
            event_type: "Logon".into(),
            description: "User admin logged on".into(),
            host: "WORKSTATION-01".into(),
            extra: HashMap::new(),
        });

        tl.sort_chronologically();
        assert_eq!(tl.events[0].source, TimelineSourceType::Eventlog);
        assert_eq!(tl.events[1].source, TimelineSourceType::Prefetch);

        let csv = tl.to_csv();
        assert!(csv.contains("powershell.exe executed"));
        assert!(csv.contains("EVENTLOG"));
    }
}
