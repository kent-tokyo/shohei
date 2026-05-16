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

    #[cfg(feature = "tui")]
    if args.tui {
        let spinner = make_spinner();
        spinner.set_message(format!("Loading data for {}...", args.domain));
        let domain = args.domain.clone();
        let record_type = args.record_type.to_record_type();
        let opts = match build_query_opts(&args).await {
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
            dnssec::build_chain(&domain, record_type, resolver_ip),
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

    // Watch loop — runs once when --watch is not set
    let mut iteration = 0u32;
    loop {
        iteration = iteration.saturating_add(1);
        if iteration > 1 && std::io::IsTerminal::is_terminal(&std::io::stdout()) {
            print!("\x1b[2J\x1b[H");
        }

        let ok = run_once(&args, &*renderer).await;

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
async fn run_once(args: &Args, renderer: &dyn Render) -> bool {
    let spinner = make_spinner();
    let resolver_ip = server_ip_from_args(args);

    // Compare mode
    if let Some(ref compare_addr) = args.compare {
        spinner.set_message(format!(
            "Comparing {} against {}...",
            args.domain, compare_addr
        ));

        let record_type = args.record_type.to_record_type();
        let opts_left = match build_query_opts(args).await {
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
            domain: args.domain.clone(),
            record_type,
            server: Some(compare_sock),
            transport: None,
            validate_dnssec: args.dnssec,
        };

        let (left_res, right_res) = tokio::join!(
            resolver::standard::query(&opts_left),
            resolver::standard::query(&opts_right),
        );
        spinner.finish_and_clear();

        match (left_res, right_res) {
            (Ok(left), Ok(right)) => {
                let cmp = resolver::DnsComparison {
                    domain: args.domain.clone(),
                    record_type: record_type.to_string(),
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
        spinner.set_message(format!("Tracing resolution path for {}...", args.domain));
        let record_type = args.record_type.to_record_type();
        match resolver::iterative::trace(&args.domain, record_type, resolver_ip).await {
            Ok(trace) => {
                spinner.finish_and_clear();
                print!("{}", renderer.render_trace(&trace));
                true
            }
            Err(e) => bail(&spinner, &e),
        }
    } else if args.dnssec {
        spinner.set_message(format!("Validating DNSSEC chain for {}...", args.domain));
        let record_type = args.record_type.to_record_type();
        match dnssec::build_chain(&args.domain, record_type, resolver_ip).await {
            Ok(chain) => {
                spinner.finish_and_clear();
                print!("{}", renderer.render_dnssec(&chain));
                true
            }
            Err(e) => bail(&spinner, &e),
        }
    } else {
        spinner.set_message(format!("Querying {}...", args.domain));
        let opts = match build_query_opts(args).await {
            Ok(o) => o,
            Err(e) => return bail(&spinner, &e),
        };
        match resolver::standard::query(&opts).await {
            Ok(result) => {
                spinner.finish_and_clear();
                print!("{}", renderer.render_records(&result));
                true
            }
            Err(e) => bail(&spinner, &e),
        }
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

async fn build_query_opts(args: &Args) -> error::Result<resolver::QueryOptions> {
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
        domain: args.domain.clone(),
        record_type: args.record_type.to_record_type(),
        server,
        transport,
        validate_dnssec: args.dnssec,
    })
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
