use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "shohei",
    version,
    about = "Next-generation DNS diagnostic CLI with DNSSEC chain-of-trust visualization",
    long_about = "shohei queries DNS records and can visualize the full DNSSEC chain of trust,\niterative resolution path, and supports modern transports like DoH and DoT."
)]
pub struct Args {
    /// Domain name to query
    pub domain: String,

    /// DNS record type to query
    #[arg(
        long = "type",
        short = 't',
        value_enum,
        default_value = "a",
        ignore_case = true
    )]
    pub record_type: RType,

    /// Show DNSSEC chain-of-trust validation tree
    #[arg(long, short = 'd')]
    pub dnssec: bool,

    /// Show iterative resolution path from root servers
    #[arg(long)]
    pub trace: bool,

    /// Use DNS-over-HTTPS (e.g. https://dns.google/dns-query)
    #[arg(long, value_name = "URL")]
    pub doh: Option<String>,

    /// Use DNS-over-TLS (e.g. 8.8.8.8:853)
    #[arg(long, value_name = "HOST:PORT")]
    pub dot: Option<String>,

    /// Custom DNS server address
    #[arg(long, short = 's', value_name = "ADDR")]
    pub server: Option<String>,

    /// Output format
    #[arg(long, short = 'o', value_enum, default_value = "colored")]
    pub output: OutputFormat,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum RType {
    A,
    Aaaa,
    Mx,
    Ns,
    Txt,
    Cname,
    Soa,
    Ptr,
    Srv,
    Dnskey,
    Ds,
    Rrsig,
    Any,
}

impl RType {
    pub fn to_record_type(&self) -> hickory_proto::rr::RecordType {
        use hickory_proto::rr::RecordType;
        match self {
            RType::A => RecordType::A,
            RType::Aaaa => RecordType::AAAA,
            RType::Mx => RecordType::MX,
            RType::Ns => RecordType::NS,
            RType::Txt => RecordType::TXT,
            RType::Cname => RecordType::CNAME,
            RType::Soa => RecordType::SOA,
            RType::Ptr => RecordType::PTR,
            RType::Srv => RecordType::SRV,
            RType::Dnskey => RecordType::DNSKEY,
            RType::Ds => RecordType::DS,
            RType::Rrsig => RecordType::RRSIG,
            RType::Any => RecordType::ANY,
        }
    }
}

#[derive(Debug, Clone, ValueEnum, PartialEq)]
pub enum OutputFormat {
    /// Colored table output (auto-disables in non-TTY environments)
    Colored,
    /// Plain text, no ANSI colors
    Plain,
    /// JSON output for scripting
    Json,
}
