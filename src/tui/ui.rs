use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Wrap},
};

use crate::display::table::format_record_data;
use crate::resolver::TrustState;
use crate::resolver::iterative::StepResponseType;

use super::app::{App, View};

fn trust_color(state: &TrustState) -> Color {
    match state {
        TrustState::Secure => Color::Green,
        TrustState::Insecure => Color::Yellow,
        TrustState::Bogus => Color::Red,
        TrustState::Indeterminate => Color::DarkGray,
    }
}

fn trust_label(state: &TrustState) -> &'static str {
    match state {
        TrustState::Secure => "✓ SECURE",
        TrustState::Insecure => "⚠ INSECURE",
        TrustState::Bogus => "✗ BOGUS",
        TrustState::Indeterminate => "? INDETERMINATE",
    }
}

pub fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(frame.area());

    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            " shohei ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("— "),
        Span::styled(
            app.domain.clone(),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
    ]));
    frame.render_widget(title, chunks[0]);

    let block_title = match app.view {
        View::Records => " Records ",
        View::Dnssec => " DNSSEC Chain of Trust ",
        View::Trace => " Iterative Resolution Trace ",
    };
    let content = match app.view {
        View::Records => render_records(app),
        View::Dnssec => render_dnssec(app),
        View::Trace => render_trace(app),
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(
            block_title,
            Style::default().fg(Color::Cyan),
        ));
    let paragraph = Paragraph::new(content)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((app.scroll, 0));
    frame.render_widget(paragraph, chunks[1]);

    let active = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let dim = Style::default().fg(Color::DarkGray);
    let status = Paragraph::new(Line::from(vec![
        Span::raw(" "),
        Span::styled(
            "[r] Records",
            if app.view == View::Records { active } else { dim },
        ),
        Span::raw("  "),
        Span::styled(
            "[d] DNSSEC",
            if app.view == View::Dnssec { active } else { dim },
        ),
        Span::raw("  "),
        Span::styled(
            "[t] Trace",
            if app.view == View::Trace { active } else { dim },
        ),
        Span::styled("  [↑↓/jk] Scroll  [q] Quit", dim),
    ]));
    frame.render_widget(status, chunks[2]);
}

fn render_records(app: &App) -> Text<'static> {
    let result = &app.records;
    let mut lines: Vec<Line<'static>> = Vec::new();

    lines.push(Line::from(vec![
        Span::styled("Query: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            result.query.name.clone(),
            Style::default().fg(Color::White),
        ),
        Span::styled(
            format!(" ({} {})", result.query.record_type, result.query.class),
            Style::default().fg(Color::DarkGray),
        ),
    ]));
    lines.push(Line::default());

    if result.answers.is_empty() {
        lines.push(Line::from(Span::styled(
            "No records found.",
            Style::default().fg(Color::DarkGray),
        )));
        return Text::from(lines);
    }

    lines.push(Line::from(Span::styled(
        format!("{:<38} {:>6}  {:<8} DATA", "NAME", "TTL", "TYPE"),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(Span::styled(
        "─".repeat(72),
        Style::default().fg(Color::DarkGray),
    )));

    for record in &result.answers {
        let data_str = format_record_data(&record.data);
        let tc = trust_color(&record.trust);
        let tl = trust_label(&record.trust);
        lines.push(Line::from(vec![
            Span::styled(
                format!(
                    "{:<38} {:>6}  {:<8} ",
                    record.name, record.ttl, record.record_type
                ),
                Style::default().fg(Color::White),
            ),
            Span::styled(data_str, Style::default().fg(Color::White)),
            Span::raw("  "),
            Span::styled(tl, Style::default().fg(tc)),
        ]));
    }

    lines.push(Line::default());
    lines.push(Line::from(Span::styled(
        format!(
            "Resolved in {}ms via {}",
            result.duration_ms, result.server_addr
        ),
        Style::default().fg(Color::DarkGray),
    )));

    Text::from(lines)
}

fn render_dnssec(app: &App) -> Text<'static> {
    let chain = &app.dnssec;
    let mut lines: Vec<Line<'static>> = Vec::new();

    let oc = trust_color(&chain.overall);
    let ol = trust_label(&chain.overall);
    lines.push(Line::from(vec![
        Span::styled("Domain: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            chain.domain.clone(),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(ol, Style::default().fg(oc).add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::default());

    for (i, step) in chain.steps.iter().enumerate() {
        let indent = if i == 0 {
            String::new()
        } else {
            "  ".to_string()
        };
        let connector = if i == 0 { "" } else { "└─ " };
        let sc = trust_color(&step.status);
        let sl = trust_label(&step.status);
        lines.push(Line::from(vec![
            Span::raw(format!("{indent}{connector}")),
            Span::styled(sl, Style::default().fg(sc)),
            Span::raw(" "),
            Span::styled(
                format!("[{}]", step.step_type),
                Style::default().fg(Color::DarkGray),
            ),
            Span::raw(" "),
            Span::styled(
                step.label.clone(),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" — {}", step.detail),
                Style::default().fg(Color::DarkGray),
            ),
        ]));
    }

    Text::from(lines)
}

fn render_trace(app: &App) -> Text<'static> {
    let trace = &app.trace;
    let mut lines: Vec<Line<'static>> = Vec::new();

    lines.push(Line::from(vec![
        Span::styled("Trace: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            trace.record_type.clone(),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw(" "),
        Span::styled(
            trace.target.clone(),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(Line::default());

    for (i, step) in trace.steps.iter().enumerate() {
        let (status_text, status_color) = match &step.response_type {
            StepResponseType::Answer => ("✓ ANSWER", Color::Green),
            StepResponseType::Referral => ("→ REFERRAL", Color::Cyan),
            StepResponseType::Nxdomain => ("✗ NXDOMAIN", Color::Red),
            StepResponseType::Error(_) => ("✗ ERROR", Color::Red),
        };
        let indent = "  ".repeat(i);

        lines.push(Line::from(vec![
            Span::raw(indent.clone()),
            Span::styled(
                format!("[{}] ", status_text),
                Style::default().fg(status_color),
            ),
            Span::styled(step.server_name.clone(), Style::default().fg(Color::White)),
            Span::styled(
                format!(" @ {}", step.server_addr),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format!(" ({}ms)", step.duration_ms),
                Style::default().fg(Color::DarkGray),
            ),
        ]));

        if let Some(refs) = &step.referral_to {
            lines.push(Line::from(vec![
                Span::raw(format!("{indent}    ")),
                Span::styled("→ Referred to: ", Style::default().fg(Color::DarkGray)),
                Span::styled(refs.join(", "), Style::default().fg(Color::Yellow)),
            ]));
        }
    }

    if let Some(msg) = &trace.truncated {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            format!("⚠ {msg}"),
            Style::default().fg(Color::Yellow),
        )));
    }

    Text::from(lines)
}
