use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShoheError {
    #[error("DNS resolution failed: {0}")]
    DnsResolution(String),

    #[error("DNS protocol error: {0}")]
    DnsProto(#[from] hickory_proto::ProtoError),

    #[error("DNSSEC validation error: {0}")]
    DnssecValidation(String),

    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<hickory_resolver::net::NetError> for ShoheError {
    fn from(e: hickory_resolver::net::NetError) -> Self {
        ShoheError::DnsResolution(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ShoheError>;
