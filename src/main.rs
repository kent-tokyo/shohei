mod cli;
mod display;
mod dnssec;
mod error;
mod resolver;
mod transport;

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

use cli::args::{Args, OutputFormat};
use cli::output::{json::JsonRenderer, plain::PlainRenderer, table::ColoredRenderer, Render};

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let renderer: Box<dyn Render> = match args.output {
        OutputFormat::Json => Box::new(JsonRenderer),
        OutputFormat::Plain => Box::new(PlainRenderer),
        OutputFormat::Colored => Box::new(ColoredRenderer),
    };

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    spinner.enable_steady_tick(Duration::from_millis(80));
    spinner.set_message(format!("Querying {}...", args.domain));

    if args.trace {
        spinner.set_message(format!("Tracing resolution path for {}...", args.domain));
        let record_type = args.record_type.to_record_type();
        match resolver::iterative::trace(&args.domain, record_type).await {
            Ok(trace) => {
                spinner.finish_and_clear();
                print!("{}", renderer.render_trace(&trace));
            }
            Err(e) => {
                spinner.finish_and_clear();
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    if args.dnssec {
        spinner.set_message(format!("Validating DNSSEC chain for {}...", args.domain));
        let record_type = args.record_type.to_record_type();
        match dnssec::build_chain(&args.domain, record_type).await {
            Ok(chain) => {
                spinner.finish_and_clear();
                print!("{}", renderer.render_dnssec(&chain));
            }
            Err(e) => {
                spinner.finish_and_clear();
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // Standard DNS query
    let opts = build_query_opts(&args);
    match resolver::standard::query(&opts).await {
        Ok(result) => {
            spinner.finish_and_clear();
            print!("{}", renderer.render_records(&result));
        }
        Err(e) => {
            spinner.finish_and_clear();
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}

fn build_query_opts(args: &Args) -> resolver::QueryOptions {
    use std::net::SocketAddr;

    let server = args.server.as_ref().and_then(|s| {
        let with_port = if s.contains(':') {
            s.clone()
        } else {
            format!("{s}:53")
        };
        with_port.parse::<SocketAddr>().ok()
    });

    resolver::QueryOptions {
        domain: args.domain.clone(),
        record_type: args.record_type.to_record_type(),
        server,
        validate_dnssec: args.dnssec,
    }
}
