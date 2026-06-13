use std::fmt;

#[derive(Debug)]
pub enum ShoheError {
    DnsResolution(String),
    DnsProto(hickory_proto::ProtoError),
    DnssecValidation(String),
    Transport(String),
    Parse(String),
    Io(std::io::Error),
}

impl fmt::Display for ShoheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShoheError::DnsResolution(s)    => write!(f, "DNS resolution failed: {}", s),
            ShoheError::DnsProto(e)         => write!(f, "DNS protocol error: {}", e),
            ShoheError::DnssecValidation(s) => write!(f, "DNSSEC validation error: {}", s),
            ShoheError::Transport(s)        => write!(f, "Transport error: {}", s),
            ShoheError::Parse(s)            => write!(f, "Parse error: {}", s),
            ShoheError::Io(e)               => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for ShoheError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ShoheError::DnsProto(e) => Some(e),
            ShoheError::Io(e)       => Some(e),
            _ => None,
        }
    }
}

impl From<hickory_proto::ProtoError> for ShoheError {
    fn from(e: hickory_proto::ProtoError) -> Self { ShoheError::DnsProto(e) }
}

impl From<std::io::Error> for ShoheError {
    fn from(e: std::io::Error) -> Self { ShoheError::Io(e) }
}

impl From<hickory_resolver::net::NetError> for ShoheError {
    fn from(e: hickory_resolver::net::NetError) -> Self {
        ShoheError::DnsResolution(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ShoheError>;
