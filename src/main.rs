mod cli;
mod display;
mod dnssec;
mod error;
mod resolver;
mod transport;
#[cfg(feature = "tui")]
mod tui;

use std::time::Duration;

use clap::Parser;
use futures_util::future::join_all;
use hickory_proto::rr::RecordType;
/// Minimal progress spinner that writes to stderr (replaces the `indicatif` crate).
struct Spinner { msg: std::sync::Mutex<String> }
impl Spinner {
    fn new() -> Self { Spinner { msg: std::sync::Mutex::new(String::new()) } }
    fn set_message(&self, m: impl Into<String>) {
        let m = m.into();
        eprint!("\r{:<80}", m);
        let _ = std::io::Write::flush(&mut std::io::stderr());
        *self.msg.lock().unwrap() = m;
    }
    fn finish_and_clear(&self) { eprint!("\r{:<80}\r", ""); }
}

use cli::args::{Args, OutputFormat};
use cli::output::{
    json::JsonRenderer, plain::PlainRenderer, short::ShortRenderer, table::ColoredRenderer, Render,
};
use resolver::QueryOptions;

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let renderer: Box<dyn Render> = if args.short {
        Box::new(ShortRenderer)
    } else {
        match args.output {
            OutputFormat::Json => Box::new(JsonRenderer),
            OutputFormat::Plain => Box::new(PlainRenderer),
            OutputFormat::Colored => Box::new(ColoredRenderer),
        }
    };

    // Validate that domain or reverse is provided; stdin/file are fallbacks.
    let stdin_mode = args.domain.as_deref() == Some("-")
        || (args.domain.is_none()
            && args.reverse.is_none()
            && args.file.is_none()
            && !std::io::IsTerminal::is_terminal(&std::io::stdin()));
    if args.domain.is_none() && args.reverse.is_none() && args.file.is_none() && !stdin_mode {
        eprintln!("Error: missing domain. Provide a domain name, use -x <IP> for reverse lookup, -f <file> for batch, or pipe domains via stdin.");
        std::process::exit(1);
    }

    #[cfg(feature = "tui")]
    if args.tui {
        let spinner = make_spinner();
        let (domain, rtypes) = match resolve_effective_args(&args, None) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        };
        // TUI only uses the first record type; warn if multiple were given
        let mut rtypes_iter = rtypes.into_iter();
        let record_type = rtypes_iter.next().unwrap_or(RecordType::A);
        if rtypes_iter.next().is_some() {
            eprintln!("Note: TUI mode uses only the first record type");
        }
        spinner.set_message(format!("Loading data for {}...", domain));
        let opts = match build_query_opts(&args, &domain, record_type).await {
            Ok(o) => o,
            Err(e) => {
                spinner.finish_and_clear();
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        };
        let resolver_ip = server_ip_from_args(&args);
        let (records_res, dnssec_res, trace_res) = tokio::join!(
            resolver::standard::query(&opts),
            dnssec::build_chain(&domain, record_type, resolver_ip, args.verbose),
            resolver::iterative::trace(&domain, record_type, resolver_ip),
        );
        spinner.finish_and_clear();
        let records = records_res.unwrap_or_else(|e| {
            eprintln!("Warning: DNS query failed: {e}");
            std::process::exit(1);
        });
        let dnssec_chain = dnssec_res.unwrap_or_else(|e| {
            eprintln!("Warning: DNSSEC chain failed: {e}");
            std::process::exit(1);
        });
        let trace = trace_res.unwrap_or_else(|e| {
            eprintln!("Warning: trace failed: {e}");
            std::process::exit(1);
        });
        if let Err(e) = tui::run(domain, records, dnssec_chain, trace).await {
            eprintln!("TUI error: {e}");
            std::process::exit(1);
        }
        return;
    }

    // File batch mode (-f): read domain names from a file, run once per domain
    if let Some(ref path) = args.file {
        use std::io::BufRead;
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Error: cannot open file '{}': {e}", path.display());
                std::process::exit(1);
            }
        };
        let domains: Vec<String> = std::io::BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        if domains.is_empty() {
            eprintln!("Error: no domains found in '{}'", path.display());
            std::process::exit(1);
        }
        if !run_batch(&args, &*renderer, domains).await {
            std::process::exit(1);
        }
        return;
    }

    // Stdin batch mode: read domain names line by line, run once per domain
    if stdin_mode {
        use std::io::BufRead;
        let domains: Vec<String> = std::io::stdin()
            .lock()
            .lines()
            .map_while(Result::ok)
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        if domains.is_empty() {
            eprintln!("Error: no domains read from stdin");
            std::process::exit(1);
        }
        if !run_batch(&args, &*renderer, domains).await {
            std::process::exit(1);
        }
        return;
    }

    // Watch loop — runs once when --watch is not set
    let mut iteration = 0u32;
    loop {
        iteration = iteration.saturating_add(1);
        if iteration > 1 && std::io::IsTerminal::is_terminal(&std::io::stdout()) {
            print!("\x1b[2J\x1b[H");
        }

        run_once(&args, &*renderer, None).await;

        // Continue watch loop even on transient query errors
        match args.watch {
            Some(secs) => {
                eprintln!("\n  Refreshing in {secs}s — Ctrl+C to stop");
                tokio::time::sleep(Duration::from_secs(secs)).await;
            }
            None => break,
        }
    }
}

// ---------------------------------------------------------------------------
// Batch helpers
// ---------------------------------------------------------------------------

/// Run the same query for each domain in `domains`.  Validates each domain
/// before querying.  Returns `true` if all queries succeeded.
async fn run_batch(args: &Args, renderer: &dyn Render, domains: Vec<String>) -> bool {
    let mut any_failed = false;
    for domain in &domains {
        if let Err(e) = cli::args::validate_domain(domain) {
            eprintln!("Error: invalid domain '{domain}': {e}");
            any_failed = true;
            continue;
        }
        if !run_once(args, renderer, Some(domain.as_str())).await {
            any_failed = true;
        }
    }
    !any_failed
}

// ---------------------------------------------------------------------------
// Core query loop
// ---------------------------------------------------------------------------

/// Finish the spinner, print an error, and return false (stops the watch loop).
fn bail(spinner: &Spinner, msg: &dyn std::fmt::Display) -> bool {
    spinner.finish_and_clear();
    eprintln!("Error: {msg}");
    false
}

/// Execute one query iteration. Returns false on fatal error (stops watch loop).
async fn run_once(args: &Args, renderer: &dyn Render, domain_override: Option<&str>) -> bool {
    let spinner = make_spinner();
    let resolver_ip = server_ip_from_args(args);

    let (domain, record_types) = match resolve_effective_args(args, domain_override) {
        Ok(v) => v,
        Err(e) => return bail(&spinner, &e),
    };
    let primary_type = record_types[0];

    if args.axfr {
        dispatch_axfr(args, renderer, &domain, &spinner).await
    } else if !args.compare.is_empty() {
        dispatch_compare(args, renderer, &domain, primary_type, &spinner).await
    } else if args.trace {
        dispatch_trace(renderer, &domain, primary_type, resolver_ip, &spinner).await
    } else if args.dnssec {
        dispatch_dnssec(args, renderer, &domain, primary_type, resolver_ip, &spinner).await
    } else {
        dispatch_standard(args, renderer, &domain, &record_types, &spinner).await
    }
}

// ---------------------------------------------------------------------------
// Dispatch functions (one per query mode)
// ---------------------------------------------------------------------------

async fn dispatch_axfr(
    args: &Args,
    renderer: &dyn Render,
    domain: &str,
    spinner: &Spinner,
) -> bool {
    let server = match &args.server {
        None => return bail(spinner, &"--axfr requires -s <server>"),
        Some(s) => {
            let addr_str = parse_server_addr(s);
            match addr_str.parse::<std::net::SocketAddr>() {
                Ok(a) => a,
                Err(e) => return bail(spinner, &format!("invalid --server address '{s}': {e}")),
            }
        }
    };
    spinner.set_message(format!("Fetching zone {} via AXFR from {}...", domain, server));
    match resolver::zone_transfer::axfr(domain, server, args.timeout).await {
        Ok(result) => {
            spinner.finish_and_clear();
            print!("{}", renderer.render_records(&result));
            true
        }
        Err(e) => bail(spinner, &e),
    }
}

async fn dispatch_compare(
    args: &Args,
    renderer: &dyn Render,
    domain: &str,
    primary_type: RecordType,
    spinner: &Spinner,
) -> bool {
    if args.compare.len() == 1 {
        dispatch_compare_two(args, renderer, domain, primary_type, spinner).await
    } else {
        dispatch_compare_nway(args, renderer, domain, primary_type, spinner).await
    }
}

async fn dispatch_compare_two(
    args: &Args,
    renderer: &dyn Render,
    domain: &str,
    primary_type: RecordType,
    spinner: &Spinner,
) -> bool {
    let compare_addr = &args.compare[0];
    spinner.set_message(format!("Comparing {} against {}...", domain, compare_addr));

    let opts_left = match build_query_opts(args, domain, primary_type).await {
        Ok(o) => o,
        Err(e) => return bail(spinner, &e),
    };

    let compare_addr_str = parse_server_addr(compare_addr);
    let compare_sock = match compare_addr_str.parse::<std::net::SocketAddr>() {
        Ok(a) => a,
        Err(e) => {
            return bail(
                spinner,
                &format!("invalid --compare address '{compare_addr}': {e}"),
            )
        }
    };
    let opts_right = QueryOptions {
        domain: domain.to_string(),
        record_type: primary_type,
        server: Some(compare_sock),
        transport: None,
        validate_dnssec: args.dnssec,
        force_tcp: false,
        no_recurse: args.no_recurse,
        timeout_secs: args.timeout,
        ipv4_only: args.ipv4_only,
        ipv6_only: args.ipv6_only,
    };

    let (left_res, right_res) = tokio::join!(
        resolver::standard::query(&opts_left),
        resolver::standard::query(&opts_right),
    );
    spinner.finish_and_clear();

    match (left_res, right_res) {
        (Ok(left), Ok(right)) => {
            let cmp = resolver::DnsComparison {
                domain: domain.to_string(),
                record_type: primary_type.to_string(),
                left,
                right,
            };
            print!("{}", renderer.render_compare(&cmp));
            true
        }
        (Err(e1), Err(e2)) => {
            eprintln!("Error (left): {e1}");
            eprintln!("Error (right): {e2}");
            false
        }
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("Error: {e}");
            false
        }
    }
}

async fn dispatch_compare_nway(
    args: &Args,
    renderer: &dyn Render,
    domain: &str,
    primary_type: RecordType,
    spinner: &Spinner,
) -> bool {
    let compare_addrs = args.compare.iter().map(|a| a.as_str()).collect::<Vec<_>>();
    spinner.set_message(format!(
        "Querying {} across {} servers...",
        domain,
        compare_addrs.len() + 1
    ));

    let opts_primary = match build_query_opts(args, domain, primary_type).await {
        Ok(o) => o,
        Err(e) => return bail(spinner, &e),
    };

    let mut all_opts = vec![opts_primary];
    for addr in &args.compare {
        let addr_str = parse_server_addr(addr);
        let sock = match addr_str.parse::<std::net::SocketAddr>() {
            Ok(a) => a,
            Err(e) => return bail(spinner, &format!("invalid --compare address '{addr}': {e}")),
        };
        all_opts.push(QueryOptions {
            domain: domain.to_string(),
            record_type: primary_type,
            server: Some(sock),
            transport: None,
            validate_dnssec: args.dnssec,
            force_tcp: false,
            no_recurse: args.no_recurse,
            timeout_secs: args.timeout,
            ipv4_only: args.ipv4_only,
            ipv6_only: args.ipv6_only,
        });
    }

    let results = join_all(all_opts.iter().map(|o| resolver::standard::query(o))).await;
    spinner.finish_and_clear();

    // Warn on per-server errors but continue with servers that succeeded
    let mut query_results = Vec::new();
    for (i, result) in results.into_iter().enumerate() {
        match result {
            Ok(r) => query_results.push(r),
            Err(e) => eprintln!("Warning: server {i} failed: {e}"),
        }
    }
    if query_results.is_empty() {
        eprintln!("Error: all servers failed");
        return false;
    }

    let multi = resolver::DnsMultiQuery {
        domain: domain.to_string(),
        record_type: primary_type.to_string(),
        results: query_results,
    };
    print!("{}", renderer.render_multi(&multi));
    true
}

async fn dispatch_trace(
    renderer: &dyn Render,
    domain: &str,
    primary_type: RecordType,
    resolver_ip: Option<std::net::IpAddr>,
    spinner: &Spinner,
) -> bool {
    spinner.set_message(format!("Tracing resolution path for {}...", domain));
    match resolver::iterative::trace(domain, primary_type, resolver_ip).await {
        Ok(trace) => {
            spinner.finish_and_clear();
            print!("{}", renderer.render_trace(&trace));
            true
        }
        Err(e) => bail(spinner, &e),
    }
}

async fn dispatch_dnssec(
    args: &Args,
    renderer: &dyn Render,
    domain: &str,
    primary_type: RecordType,
    resolver_ip: Option<std::net::IpAddr>,
    spinner: &Spinner,
) -> bool {
    spinner.set_message(format!("Validating DNSSEC chain for {}...", domain));
    match dnssec::build_chain(domain, primary_type, resolver_ip, args.verbose).await {
        Ok(chain) => {
            spinner.finish_and_clear();
            print!("{}", renderer.render_dnssec(&chain));
            true
        }
        Err(e) => bail(spinner, &e),
    }
}

/// Standard query mode — supports multiple record types queried concurrently.
///
/// The transport config (DoH/DoT/DoQ) is built once and shared across all
/// record types to avoid redundant async setup work.
async fn dispatch_standard(
    args: &Args,
    renderer: &dyn Render,
    domain: &str,
    record_types: &[RecordType],
    spinner: &Spinner,
) -> bool {
    spinner.set_message(format!("Querying {}...", domain));

    // Build the base opts once (expensive for DoH/DoT/DoQ transport setup).
    // Clone per additional record type — ResolverConfig: Clone, so this is cheap.
    let base_opts = match build_query_opts(args, domain, record_types[0]).await {
        Ok(o) => o,
        Err(e) => return bail(spinner, &e),
    };

    let all_opts: Vec<QueryOptions> = record_types
        .iter()
        .map(|&rtype| QueryOptions {
            record_type: rtype,
            ..base_opts.clone()
        })
        .collect();

    // All record types queried concurrently; join_all preserves insertion order.
    let results = join_all(all_opts.iter().map(|o| resolver::standard::query(o))).await;
    spinner.finish_and_clear();

    let mut success = true;
    for result in results {
        match result {
            Ok(r) => print!("{}", renderer.render_records(&r)),
            Err(e) => {
                eprintln!("Error: {e}");
                success = false;
            }
        }
    }
    success
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_spinner() -> Spinner {
    Spinner::new()
}

async fn build_query_opts(
    args: &Args,
    domain: &str,
    record_type: RecordType,
) -> error::Result<QueryOptions> {
    use std::net::SocketAddr;

    let transport = if let Some(url) = &args.doh {
        let (config, label) = transport::doh::build_doh_config(url).await?;
        Some((config, label))
    } else if let Some(addr) = &args.dot {
        let (config, label) = transport::dot::build_dot_config(addr).await?;
        Some((config, label))
    } else if let Some(addr) = &args.doq {
        let (config, label) = transport::doq::build_doq_config(addr).await?;
        Some((config, label))
    } else {
        None
    };

    let server: Option<SocketAddr> = if transport.is_none() {
        match &args.server {
            None => None,
            Some(s) => {
                let addr_str = parse_server_addr(s);
                match addr_str.parse::<SocketAddr>() {
                    Ok(addr) => Some(addr),
                    Err(e) => {
                        return Err(crate::error::ShoheError::Parse(format!(
                            "Invalid --server address '{s}': {e}. \
                             Use IP:PORT (e.g. 8.8.8.8:53) or bare IP."
                        )));
                    }
                }
            }
        }
    } else {
        None
    };

    Ok(QueryOptions {
        domain: domain.to_string(),
        record_type,
        server,
        transport,
        validate_dnssec: args.dnssec,
        force_tcp: args.tcp,
        no_recurse: args.no_recurse,
        timeout_secs: args.timeout,
        ipv4_only: args.ipv4_only,
        ipv6_only: args.ipv6_only,
    })
}

/// Resolve the effective (domain, record_types) from args, handling -x reverse flag.
/// `domain_override` (e.g. from stdin) takes precedence over `args.domain`.
fn resolve_effective_args(
    args: &Args,
    domain_override: Option<&str>,
) -> error::Result<(String, Vec<RecordType>)> {
    if let Some(ip_str) = &args.reverse {
        let ptr_domain = ip_to_ptr_domain(ip_str)?;
        Ok((ptr_domain, vec![RecordType::PTR]))
    } else {
        let domain = domain_override
            .map(str::to_string)
            .or_else(|| args.domain.clone())
            .expect("domain is required when -x is not set and no override given");
        let types = args.record_types.iter().map(|r| r.to_record_type()).collect();
        Ok((domain, types))
    }
}

/// Convert an IP address string to its PTR query domain (in-addr.arpa / ip6.arpa).
fn ip_to_ptr_domain(ip_str: &str) -> error::Result<String> {
    match ip_str.trim().parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let o = v4.octets();
            Ok(format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]))
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            let nibbles: String = v6
                .octets()
                .iter()
                .rev()
                .flat_map(|b| {
                    let lo = b & 0xf;
                    let hi = b >> 4;
                    [format!("{lo:x}."), format!("{hi:x}.")]
                })
                .collect();
            Ok(format!("{nibbles}ip6.arpa"))
        }
        Err(_) => Err(crate::error::ShoheError::Parse(format!(
            "'-x' expects an IP address (e.g. 1.1.1.1 or 2606:4700::1), got: '{ip_str}'"
        ))),
    }
}

/// Extract the server IP from --server for use as a DNSSEC/trace resolver override.
fn server_ip_from_args(args: &Args) -> Option<std::net::IpAddr> {
    args.server.as_ref().and_then(|s| {
        parse_server_addr(s)
            .parse::<std::net::SocketAddr>()
            .ok()
            .map(|sa| sa.ip())
    })
}

fn parse_server_addr(s: &str) -> String {
    if s.starts_with('[') {
        return s.to_string();
    }
    let colon_count = s.chars().filter(|&c| c == ':').count();
    if colon_count > 1 {
        return format!("[{s}]:53");
    }
    if colon_count == 0 {
        return format!("{s}:53");
    }
    s.to_string()
}
