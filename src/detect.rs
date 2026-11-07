use std::{collections::VecDeque, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};

use serde::Serialize;

use crate::rules::{Protocol, Rule};

#[derive(Clone, Copy)]
pub struct Traffic {
    pub protocol: Protocol,
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Serialize)]
pub struct Detection {
    pub rule: String,
    pub protocol: String,
    pub port: u16,
    pub packets: usize,
    pub threshold: usize,
    pub window_secs: u64,
    pub timestamp_unix: u64,
}

struct RuleState {
    rule: Rule,
    seen: VecDeque<Instant>,
    last_alert: Option<Instant>,
}

pub struct Detector {
    states: Vec<RuleState>,
}

impl Detector {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self {
            states: rules.into_iter().map(|rule| RuleState {
                rule,
                seen: VecDeque::new(),
                last_alert: None,
            }).collect(),
        }
    }

    pub fn observe(&mut self, packet: Traffic, now: Instant) -> Vec<Detection> {
        let mut detections = Vec::new();

        for state in &mut self.states {
            let rule = &state.rule;
            if packet.protocol != rule.protocol
                || (packet.src_port != rule.port && packet.dst_port != rule.port)
            {
                continue;
            }

            let window = Duration::from_secs(rule.window_secs);
            while state.seen.front().is_some_and(|first| now.duration_since(*first) >= window) {
                state.seen.pop_front();
            }
            state.seen.push_back(now);

            let cooled_down = state.last_alert
                .is_none_or(|last| now.duration_since(last) >= window);

            if state.seen.len() >= rule.threshold && cooled_down {
                state.last_alert = Some(now);
                detections.push(Detection {
                    rule: rule.name.clone(),
                    protocol: rule.protocol.to_string(),
                    port: rule.port,
                    packets: state.seen.len(),
                    threshold: rule.threshold,
                    window_secs: rule.window_secs,
                    timestamp_unix: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                });
            }
        }

        detections
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fires_at_threshold_and_suppresses_repeats() {
        let rule = Rule {
            name: "test".into(),
            protocol: Protocol::Tcp,
            port: 22,
            threshold: 3,
            window_secs: 5,
        };
        let mut detector = Detector::new(vec![rule]);
        let traffic = Traffic { protocol: Protocol::Tcp, src_port: 22, dst_port: 4000 };
        let start = Instant::now();

        assert!(detector.observe(traffic, start).is_empty());
        assert!(detector.observe(traffic, start + Duration::from_secs(1)).is_empty());
        assert_eq!(detector.observe(traffic, start + Duration::from_secs(2)).len(), 1);
        assert!(detector.observe(traffic, start + Duration::from_secs(3)).is_empty());
        assert!(detector.observe(traffic, start + Duration::from_secs(6)).is_empty());
        assert_eq!(detector.observe(traffic, start + Duration::from_secs(7)).len(), 1);
    }
}
