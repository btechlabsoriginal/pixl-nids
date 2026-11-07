use std::{collections::HashSet, error::Error, fmt, fs, path::Path};

use serde::Deserialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
        }
    }
}

#[derive(Debug)]
pub struct Rule {
    pub name: String,
    pub protocol: Protocol,
    pub port: u16,
    pub threshold: usize,
    pub window_secs: u64,
}

#[derive(Deserialize)]
struct RuleFile {
    rules: Vec<RuleSpec>,
}

#[derive(Deserialize)]
struct RuleSpec {
    name: String,
    protocol: String,
    port: u16,
    threshold: usize,
    window_secs: u64,
}

pub fn load(path: &Path) -> Result<Vec<Rule>, Box<dyn Error>> {
    let contents = fs::read_to_string(path)?;
    let parsed: RuleFile = toml::from_str(&contents)?;
    compile(parsed).map_err(Into::into)
}

fn compile(file: RuleFile) -> Result<Vec<Rule>, String> {
    if file.rules.is_empty() {
        return Err("rules file must contain at least one [[rules]] entry".into());
    }

    let mut names = HashSet::new();
    let mut compiled = Vec::with_capacity(file.rules.len());

    for spec in file.rules {
        let name = spec.name.trim().to_owned();
        if name.is_empty() {
            return Err("rule names cannot be empty".into());
        }
        if !names.insert(name.clone()) {
            return Err(format!("duplicate rule name: {name}"));
        }

        let protocol = match spec.protocol.to_ascii_lowercase().as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            other => return Err(format!("{name}: unsupported protocol '{other}'")),
        };

        if spec.port == 0 {
            return Err(format!("{name}: port must be between 1 and 65535"));
        }
        if spec.threshold == 0 || spec.window_secs == 0 {
            return Err(format!("{name}: threshold and window_secs must be positive"));
        }

        compiled.push(Rule {
            name,
            protocol,
            port: spec.port,
            threshold: spec.threshold,
            window_secs: spec.window_secs,
        });
    }

    Ok(compiled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_rules_compile() {
        let file: RuleFile = toml::from_str(include_str!("../rules/example.toml")).unwrap();
        let rules = compile(file).unwrap();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].protocol, Protocol::Tcp);
    }
}
