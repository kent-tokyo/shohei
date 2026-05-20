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
use hickory_proto::rr::RecordType;
use indicatif::{ProgressBar, ProgressStyle};

use cli::args::{Args, OutputFormat};
use cli::output::{
    json::JsonRenderer, plain::PlainRenderer, short::ShortRenderer, table::ColoredRenderer, Render,
};

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

    // Validate that domain or reverse is provided; stdin is the fallback.
    let stdin_mode = args.domain.as_deref() == Some("-")
        || (args.domain.is_none()
            && args.reverse.is_none()
            && !std::io::IsTerminal::is_terminal(&std::io::stdin()));
    if args.domain.is_none() && args.reverse.is_none() && !stdin_mode {
        eprintln!("Error: missing domain. Provide a domain name, use -x <IP> for reverse lookup, or pipe domains via stdin.");
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
        let record_type = rtypes.into_iter().next().unwrap_or(RecordType::A);
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
        for domain in &domains {
            run_once(&args, &*renderer, Some(domain.as_str())).await;
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

        let ok = run_once(&args, &*renderer, None).await;

        match args.watch {
            Some(secs) if ok => {
                eprintln!(
                    "\n  Refreshing in {secs}s — Ctrl+C to stop",
                );
                tokio::time::sleep(Duration::from_secs(secs)).await;
            }
            _ => break,
        }
    }
}

/// Finish the spinner, print an error, and return false (stops the watch loop).
fn bail(spinner: &ProgressBar, msg: &dyn std::fmt::Display) -> bool {
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

    // Compare mode
    if let Some(ref compare_addr) = args.compare {
        spinner.set_message(format!("Comparing {} against {}...", domain, compare_addr));

        let opts_left = match build_query_opts(args, &domain, primary_type).await {
            Ok(o) => o,
            Err(e) => return bail(&spinner, &e),
        };

        let compare_addr_str = parse_server_addr(compare_addr);
        let compare_sock = match compare_addr_str.parse::<std::net::SocketAddr>() {
            Ok(a) => a,
            Err(e) => {
                return bail(
                    &spinner,
                    &format!("invalid --compare address '{compare_addr}': {e}"),
                )
            }
        };
        let opts_right = resolver::QueryOptions {
            domain: domain.clone(),
            record_type: primary_type,
            server: Some(compare_sock),
            transport: None,
            validate_dnssec: args.dnssec,
            force_tcp: false,
            no_recurse: args.no_recurse,
            timeout_secs: args.timeout,
        };

        let (left_res, right_res) = tokio::join!(
            resolver::standard::query(&opts_left),
            resolver::standard::query(&opts_right),
        );
        spinner.finish_and_clear();

        match (left_res, right_res) {
            (Ok(left), Ok(right)) => {
                let cmp = resolver::DnsComparison {
                    domain,
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
    } else if args.trace {
        spinner.set_message(format!("Tracing resolution path for {}...", domain));
        match resolver::iterative::trace(&domain, primary_type, resolver_ip).await {
            Ok(trace) => {
                spinner.finish_and_clear();
                print!("{}", renderer.render_trace(&trace));
                true
            }
            Err(e) => bail(&spinner, &e),
        }
    } else if args.dnssec {
        spinner.set_message(format!("Validating DNSSEC chain for {}...", domain));
        match dnssec::build_chain(&domain, primary_type, resolver_ip, args.verbose).await {
            Ok(chain) => {
                spinner.finish_and_clear();
                print!("{}", renderer.render_dnssec(&chain));
                true
            }
            Err(e) => bail(&spinner, &e),
        }
    } else {
        spinner.set_message(format!("Querying {}...", domain));
        let mut cleared = false;
        let mut success = true;
        for &rtype in &record_types {
            let opts = match build_query_opts(args, &domain, rtype).await {
                Ok(o) => o,
                Err(e) => return bail(&spinner, &e),
            };
            match resolver::standard::query(&opts).await {
                Ok(result) => {
                    if !cleared {
                        spinner.finish_and_clear();
                        cleared = true;
                    }
                    print!("{}", renderer.render_records(&result));
                }
                Err(e) => {
                    if !cleared {
                        spinner.finish_and_clear();
                        cleared = true;
                    }
                    eprintln!("Error: {e}");
                    success = false;
                }
            }
        }
        if !cleared {
            spinner.finish_and_clear();
        }
        success
    }
}

fn make_spinner() -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .expect("spinner template is a valid literal"),
    );
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

async fn build_query_opts(
    args: &Args,
    domain: &str,
    record_type: RecordType,
) -> error::Result<resolver::QueryOptions> {
    use std::net::SocketAddr;

    let transport = if let Some(url) = &args.doh {
        let (config, label) = transport::doh::build_doh_config(url).await?;
        Some((config, label))
    } else if let Some(addr) = &args.dot {
        let (config, label) = transport::dot::build_dot_config(addr).await?;
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

    Ok(resolver::QueryOptions {
        domain: domain.to_string(),
        record_type,
        server,
        transport,
        validate_dnssec: args.dnssec,
        force_tcp: args.tcp,
        no_recurse: args.no_recurse,
        timeout_secs: args.timeout,
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
