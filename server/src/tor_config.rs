use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TorConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error at line {line}: {message}")]
    Parse { line: usize, message: String },
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
pub enum TorValue {
    String(String),
    Integer(i64),
    Boolean(bool),
    Duration(String),   // e.g., "5 minutes", "1 hour"
    Bytes(String),      // e.g., "1 KB", "5 MB"
    PortList(Vec<u16>), // e.g., "80,443,8080"
}

impl TorValue {
    pub fn as_string(&self) -> Option<&str> {
        match self {
            TorValue::String(s) => Some(s),
            TorValue::Duration(s) => Some(s),
            TorValue::Bytes(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            TorValue::Boolean(b) => Some(*b),
            TorValue::Integer(n) => match *n {
                0 => Some(false),
                1 => Some(true),
                _ => None,
            },
            TorValue::String(s) => match s.to_lowercase().as_str() {
                "1" | "yes" | "true" | "on" => Some(true),
                "0" | "no" | "false" | "off" => Some(false),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            TorValue::Integer(n) => Some(*n),
            TorValue::String(s) => s.parse().ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TorConfig {
    pub directives: HashMap<String, Vec<TorValue>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TorLine {
    Directive(String, TorValue),
    Comment(String),
    Empty,
}

pub struct TorConfigParser;

impl TorConfigParser {
    pub fn parse_file(file_path: &str) -> Result<TorConfig, TorConfigError> {
        let content = std::fs::read_to_string(file_path)?;
        Self::parse(&content)
    }

    pub fn parse(content: &str) -> Result<TorConfig, TorConfigError> {
        let lines = Self::parse_lines(content)?;
        Self::build_config(lines)
    }

    fn parse_lines(content: &str) -> Result<Vec<TorLine>, TorConfigError> {
        lazy_static! {
            static ref COMMENT_RE: Regex = Regex::new(r"^\s*#").unwrap();
            static ref EMPTY_RE: Regex = Regex::new(r"^\s*$").unwrap();
            static ref DIRECTIVE_RE: Regex = Regex::new(r"^\s*(\S+)\s+(.+?)\s*$").unwrap();
        }

        let mut result = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();

            if EMPTY_RE.is_match(line) {
                result.push(TorLine::Empty);
                continue;
            }

            if COMMENT_RE.is_match(line) {
                result.push(TorLine::Comment(line.to_string()));
                continue;
            }

            if let Some(caps) = DIRECTIVE_RE.captures(line) {
                let key = caps[1].to_string();
                let value_str = caps[2].trim();

                let value = Self::parse_value(value_str).map_err(|e| TorConfigError::Parse {
                    line: line_num + 1,
                    message: e,
                })?;

                result.push(TorLine::Directive(key, value));
                continue;
            }

            return Err(TorConfigError::Parse {
                line: line_num + 1,
                message: format!("Invalid line format: '{}'", line),
            });
        }

        Ok(result)
    }

    fn parse_value(value: &str) -> Result<TorValue, String> {
        // Try to parse as boolean
        if let Ok(b) = value.parse::<bool>() {
            return Ok(TorValue::Boolean(b));
        }

        // Try to parse as integer
        if let Ok(n) = value.parse::<i64>() {
            return Ok(TorValue::Integer(n));
        }

        // Check for boolean strings
        match value.to_lowercase().as_str() {
            "1" | "yes" | "true" | "on" => return Ok(TorValue::Boolean(true)),
            "0" | "no" | "false" | "off" => return Ok(TorValue::Boolean(false)),
            _ => {}
        }

        // Check for port lists (comma-separated numbers)
        if value.contains(',')
            && value
                .chars()
                .all(|c| c.is_ascii_digit() || c == ',' || c.is_whitespace())
        {
            let ports: Result<Vec<u16>, _> =
                value.split(',').map(|s| s.trim().parse::<u16>()).collect();

            if let Ok(ports) = ports {
                return Ok(TorValue::PortList(ports));
            }
        }

        // Check for duration patterns
        if Self::is_duration(value) {
            return Ok(TorValue::Duration(value.to_string()));
        }

        // Check for byte patterns (KB, MB, GB, etc.)
        if Self::is_byte_value(value) {
            return Ok(TorValue::Bytes(value.to_string()));
        }

        // Default to string
        Ok(TorValue::String(value.to_string()))
    }

    fn is_duration(value: &str) -> bool {
        lazy_static! {
            static ref DURATION_RE: Regex =
                Regex::new(r"^\d+\s*(seconds?|minutes?|hours?|days?|weeks?|months?|years?)$")
                    .unwrap();
        }
        DURATION_RE.is_match(value.to_lowercase().as_str())
    }

    fn is_byte_value(value: &str) -> bool {
        lazy_static! {
            static ref BYTES_RE: Regex = Regex::new(
                r"(?i)^\d+\s*(b|kb|mb|gb|tb|bytes?|kilobytes?|megabytes?|gigabytes?|terabytes?)$"
            )
            .unwrap();
        }
        BYTES_RE.is_match(value)
    }

    fn build_config(lines: Vec<TorLine>) -> Result<TorConfig, TorConfigError> {
        let mut config = TorConfig {
            directives: HashMap::new(),
        };

        for line in lines {
            if let TorLine::Directive(key, value) = line {
                config.directives.entry(key).or_default().push(value);
            }
        }

        Ok(config)
    }
}

// Utility methods for common Tor configuration access
impl TorConfig {
    pub fn get_exit_policy(&self) -> Option<&Vec<TorValue>> {
        self.directives.get("ExitPolicy")
    }

    pub fn get_log(&self) -> Option<&Vec<TorValue>> {
        self.directives.get("Log")
    }

    pub fn get_data_directory(&self) -> Option<&TorValue> {
        self.directives.get("DataDirectory").and_then(|v| v.first())
    }

    pub fn get_socks_port(&self) -> Option<&TorValue> {
        self.directives.get("SocksPort").and_then(|v| v.first())
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl fmt::Display for TorValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TorValue::String(s) => write!(f, "{}", s),
            TorValue::Integer(n) => write!(f, "{}", n),
            TorValue::Boolean(b) => write!(f, "{}", b),
            TorValue::Duration(d) => write!(f, "{}", d),
            TorValue::Bytes(b) => write!(f, "{}", b),
            TorValue::PortList(ports) => {
                let ports_str: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
                write!(f, "{}", ports_str.join(","))
            }
        }
    }
}

// Example usage and tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_parsing() -> Result<(), TorConfigError> {
        let config_content = r#"
            # Basic Tor configuration
            ControlPort 9051
            Log notice file /var/log/tor/tor.log
            ExitPolicy reject *:*
            DataDirectory /var/lib/tor
        "#;

        let config = TorConfigParser::parse(config_content)?;

        assert_eq!(
            config.get_data_directory().unwrap().as_string(),
            Some("/var/lib/tor")
        );
        Ok(())
    }

    #[test]
    fn test_value_parsing() -> Result<(), TorConfigError> {
        let config_content = r#"
            SocksPort 9050
            Log notice file /var/log/tor/tor.log
            ExitPolicy reject *:*
            CircuitBuildTimeout 60 seconds
            MaxMemInQueues 512 MB
            Ports 80,443,8080
        "#;

        let config = TorConfigParser::parse(config_content)?;

        assert!(matches!(
            config.directives.get("SocksPort").unwrap()[0],
            TorValue::Integer(9050)
        ));
        assert!(matches!(
            config.directives.get("Log").unwrap()[0],
            TorValue::String(_)
        ));
        assert!(matches!(
            config.directives.get("CircuitBuildTimeout").unwrap()[0],
            TorValue::Duration(_)
        ));
        assert!(matches!(
            config.directives.get("MaxMemInQueues").unwrap()[0],
            TorValue::Bytes(_)
        ));
        assert!(matches!(
            config.directives.get("Ports").unwrap()[0],
            TorValue::PortList(_)
        ));
        Ok(())
    }

    #[test]
    fn test_error_handling() {
        let invalid_content = r#"
            SocksPort 9050
            InvalidLineWithoutValue
        "#;

        let result = TorConfigParser::parse(invalid_content);
        assert!(matches!(result, Err(TorConfigError::Parse { .. })));
    }

    #[test]
    fn test_real_torrc() -> Result<(), TorConfigError> {
        // Real torrc configuration
        let config_content = r#"
Nickname testnode

AvoidDiskWrites 1
DisableAllSwap 1

ORPort 192.0.2.10:9001
ORPort [2001:db8::1]:9001

RelayBandwidthRate 40 MB
RelayBandwidthBurst 80 MB

MaxMemInQueues 400 MB

ContactInfo email:info[]osservatorionessuno.org url:https://osservatorionessuno.org proof:uri-rsa abuse:exit[]osservatorionessuno.org mastodon:https://mastodon.cisti.org/@0n_odv donationurl:https://osservatorionessuno.org/participate/ ciissversion:2

MyFamily ABCD1234567890ABCDEF1234567890ABCDEF1234,1234567890ABCDEF1234567890ABCDEF12345678

ExitPolicy reject 0.0.0.0/8:*
ExitPolicy reject 169.254.0.0/16:*
ExitPolicy reject 10.0.0.0/8:*
ExitPolicy reject *:25
ExitPolicy accept *:*

ExitRelay 1
IPv6Exit 1
        "#;

        let config = TorConfigParser::parse(config_content)?;

        // Test Nickname parsing
        let nickname = config.directives.get("Nickname").unwrap();
        assert_eq!(nickname.len(), 1);
        assert_eq!(nickname[0].as_string(), Some("testnode"));

        // Test boolean values
        let avoid_disk_writes = config.directives.get("AvoidDiskWrites").unwrap();
        assert_eq!(avoid_disk_writes[0].as_bool(), Some(true));

        let disable_swap = config.directives.get("DisableAllSwap").unwrap();
        assert_eq!(disable_swap[0].as_bool(), Some(true));

        let exit_relay = config.directives.get("ExitRelay").unwrap();
        assert_eq!(exit_relay[0].as_bool(), Some(true));

        let ipv6_exit = config.directives.get("IPv6Exit").unwrap();
        assert_eq!(ipv6_exit[0].as_bool(), Some(true));

        // Test ORPort (multiple values)
        let or_ports = config.directives.get("ORPort").unwrap();
        assert_eq!(or_ports.len(), 2);
        assert_eq!(or_ports[0].as_string(), Some("192.0.2.10:9001"));
        assert_eq!(or_ports[1].as_string(), Some("[2001:db8::1]:9001"));

        // Test byte values
        let relay_bw_rate = config.directives.get("RelayBandwidthRate").unwrap();
        assert!(matches!(relay_bw_rate[0], TorValue::Bytes(_)));
        assert_eq!(relay_bw_rate[0].as_string(), Some("40 MB"));

        let relay_bw_burst = config.directives.get("RelayBandwidthBurst").unwrap();
        assert!(matches!(relay_bw_burst[0], TorValue::Bytes(_)));
        assert_eq!(relay_bw_burst[0].as_string(), Some("80 MB"));

        let max_mem = config.directives.get("MaxMemInQueues").unwrap();
        assert!(matches!(max_mem[0], TorValue::Bytes(_)));
        assert_eq!(max_mem[0].as_string(), Some("400 MB"));

        // Test ContactInfo (long string)
        let contact_info = config.directives.get("ContactInfo").unwrap();
        assert_eq!(contact_info.len(), 1);
        assert!(
            contact_info[0]
                .as_string()
                .unwrap()
                .contains("osservatorionessuno.org")
        );
        assert!(
            contact_info[0]
                .as_string()
                .unwrap()
                .contains("ciissversion:2")
        );

        // Test MyFamily (comma-separated fingerprints)
        let my_family = config.directives.get("MyFamily").unwrap();
        assert_eq!(my_family.len(), 1);
        let family_str = my_family[0].as_string().unwrap();
        assert!(family_str.contains("ABCD1234567890ABCDEF1234567890ABCDEF1234"));
        assert!(family_str.contains("1234567890ABCDEF1234567890ABCDEF12345678"));

        // Test ExitPolicy (multiple rules)
        let exit_policy = config.get_exit_policy().unwrap();
        assert_eq!(exit_policy.len(), 5);
        assert_eq!(exit_policy[0].as_string(), Some("reject 0.0.0.0/8:*"));
        assert_eq!(exit_policy[1].as_string(), Some("reject 169.254.0.0/16:*"));
        assert_eq!(exit_policy[2].as_string(), Some("reject 10.0.0.0/8:*"));
        assert_eq!(exit_policy[3].as_string(), Some("reject *:25"));
        assert_eq!(exit_policy[4].as_string(), Some("accept *:*"));

        // Test that all expected directives are present
        assert!(config.directives.contains_key("Nickname"));
        assert!(config.directives.contains_key("AvoidDiskWrites"));
        assert!(config.directives.contains_key("DisableAllSwap"));
        assert!(config.directives.contains_key("ORPort"));
        assert!(config.directives.contains_key("RelayBandwidthRate"));
        assert!(config.directives.contains_key("RelayBandwidthBurst"));
        assert!(config.directives.contains_key("MaxMemInQueues"));
        assert!(config.directives.contains_key("ContactInfo"));
        assert!(config.directives.contains_key("MyFamily"));
        assert!(config.directives.contains_key("ExitPolicy"));
        assert!(config.directives.contains_key("ExitRelay"));
        assert!(config.directives.contains_key("IPv6Exit"));

        // Test total number of directive types
        assert_eq!(config.directives.len(), 12);

        Ok(())
    }
}
