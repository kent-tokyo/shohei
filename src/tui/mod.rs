use std::io;

use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use tokio::sync::mpsc;

use crate::dnssec::chain::DnssecChain;
use crate::error::Result;
use crate::resolver::{iterative::ResolutionTrace, DnsQueryResult};

mod app;
mod ui;

use app::{App, View};

/// Restores the terminal unconditionally on drop — covers `?`-returns and panics.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, cursor::Show);
    }
}

pub async fn run(
    domain: String,
    records: DnsQueryResult,
    dnssec: DnssecChain,
    trace: ResolutionTrace,
) -> Result<()> {
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    let _guard = TerminalGuard;

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(domain, records, dnssec, trace);
    let (tx, mut rx) = mpsc::channel::<Event>(32);

    std::thread::spawn(move || {
        loop {
            if let Ok(ev) = event::read() {
                if tx.blocking_send(ev).is_err() {
                    break;
                }
            }
        }
    });

    loop {
        terminal.draw(|f| ui::draw(f, &app))?;

        if let Some(ev) = rx.recv().await {
            if let Event::Key(key) = ev {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Char('r') => app.set_view(View::Records),
                        KeyCode::Char('d') => app.set_view(View::Dnssec),
                        KeyCode::Char('t') => app.set_view(View::Trace),
                        KeyCode::Down | KeyCode::Char('j') => app.scroll_down(),
                        KeyCode::Up | KeyCode::Char('k') => app.scroll_up(),
                        _ => {}
                    }
                }
            }
        } else {
            break;
        }
    }

    Ok(())
}
