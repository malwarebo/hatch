use std::io;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use hatch_ipc::{AuditEventEnvelope, AuditFilter, ClientRequest, Codec, DaemonResponse};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::Terminal;
use tokio::net::UnixStream;

pub struct TuiState {
    events: Vec<AuditEventEnvelope>,
    list_state: ListState,
    search: String,
    paused: bool,
}

impl TuiState {
    fn new() -> Self {
        let mut state = ListState::default();
        state.select(Some(0));
        Self {
            events: Vec::new(),
            list_state: state,
            search: String::new(),
            paused: false,
        }
    }

    fn selected_event(&self) -> Option<&AuditEventEnvelope> {
        let idx = self.list_state.selected()?;
        self.events.get(idx)
    }

    fn move_up(&mut self) {
        if let Some(i) = self.list_state.selected() {
            if i > 0 {
                self.list_state.select(Some(i - 1));
            }
        }
    }

    fn move_down(&mut self) {
        if let Some(i) = self.list_state.selected() {
            if i + 1 < self.events.len() {
                self.list_state.select(Some(i + 1));
            }
        }
    }

    fn filtered_indices(&self) -> Vec<usize> {
        if self.search.is_empty() {
            return (0..self.events.len()).collect();
        }
        let needle = self.search.to_ascii_lowercase();
        self.events
            .iter()
            .enumerate()
            .filter(|(_, ev)| {
                ev.event.to_ascii_lowercase().contains(&needle)
                    || ev.server.to_ascii_lowercase().contains(&needle)
                    || serde_json::to_string(&ev.fields)
                        .map(|s| s.to_ascii_lowercase().contains(&needle))
                        .unwrap_or(false)
            })
            .map(|(i, _)| i)
            .collect()
    }
}

pub async fn run_tui(socket: PathBuf, server_filter: Option<String>) -> Result<()> {
    let initial = fetch_audit(&socket, server_filter.clone(), 500).await?;
    let mut state = TuiState::new();
    state.events = initial;

    enable_raw_mode().context("enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("enter alt screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("init terminal")?;

    let result = main_loop(&mut terminal, &mut state, &socket, &server_filter).await;

    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();

    result
}

async fn main_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    state: &mut TuiState,
    socket: &PathBuf,
    server_filter: &Option<String>,
) -> Result<()> {
    let mut tick = tokio::time::interval(Duration::from_millis(750));
    let mut search_mode = false;

    loop {
        terminal
            .draw(|f| draw(f, state, search_mode))
            .map_err(|e| anyhow::anyhow!("draw: {e:?}"))?;

        tokio::select! {
            _ = tick.tick() => {
                if !state.paused {
                    if let Ok(events) = fetch_audit(socket, server_filter.clone(), 500).await {
                        state.events = events;
                        if state.list_state.selected().unwrap_or(0) >= state.events.len() {
                            state.list_state.select(Some(state.events.len().saturating_sub(1)));
                        }
                    }
                }
            }
            ev = tokio::task::spawn_blocking(|| {
                event::poll(Duration::from_millis(100)).ok().and_then(|p| if p { event::read().ok() } else { None })
            }) => {
                match ev.unwrap_or(None) {
                    Some(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                        if search_mode {
                            match key.code {
                                KeyCode::Esc => { search_mode = false; }
                                KeyCode::Enter => { search_mode = false; }
                                KeyCode::Backspace => { state.search.pop(); }
                                KeyCode::Char(c) => { state.search.push(c); }
                                _ => {}
                            }
                        } else {
                            match key.code {
                                KeyCode::Char('q') => return Ok(()),
                                KeyCode::Down | KeyCode::Char('j') => state.move_down(),
                                KeyCode::Up | KeyCode::Char('k') => state.move_up(),
                                KeyCode::Char('/') => {
                                    state.search.clear();
                                    search_mode = true;
                                }
                                KeyCode::Char('p') => { state.paused = !state.paused; }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

fn draw(f: &mut ratatui::Frame, state: &TuiState, search_mode: bool) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(5),
            Constraint::Length(8),
            Constraint::Length(2),
        ])
        .split(area);

    draw_events(f, chunks[0], state);
    draw_detail(f, chunks[1], state);
    draw_footer(f, chunks[2], state, search_mode);
}

fn draw_events(f: &mut ratatui::Frame, area: Rect, state: &TuiState) {
    let indices = state.filtered_indices();
    let items: Vec<ListItem> = indices
        .iter()
        .map(|idx| {
            let ev = &state.events[*idx];
            let line = format!(
                "{}  {:<22} {:<18} {}",
                short_ts(&ev.ts),
                ev.event,
                ev.server,
                short_fields(&ev.fields)
            );
            ListItem::new(Line::from(Span::raw(line)))
        })
        .collect();

    let mut list_state = ListState::default();
    list_state.select(state.list_state.selected());

    let title = format!(
        " hatch audit  ({}/{}{}) ",
        indices.len(),
        state.events.len(),
        if state.paused { " paused" } else { "" }
    );
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );

    f.render_stateful_widget(list, area, &mut list_state);
}

fn draw_detail(f: &mut ratatui::Frame, area: Rect, state: &TuiState) {
    let text: Vec<Line> = match state.selected_event() {
        Some(ev) => {
            let mut lines = vec![
                Line::from(format!("ts:        {}", ev.ts)),
                Line::from(format!("event:     {}", ev.event)),
                Line::from(format!("server:    {}", ev.server)),
                Line::from(format!(
                    "server_id: {}",
                    ev.server_id.clone().unwrap_or_default()
                )),
            ];
            if let Ok(s) = serde_json::to_string_pretty(&ev.fields) {
                for line in s.lines() {
                    lines.push(Line::from(line.to_string()));
                }
            }
            lines
        }
        None => vec![Line::from("no event selected")],
    };
    let p = Paragraph::new(text).block(Block::default().borders(Borders::ALL).title(" detail "));
    f.render_widget(p, area);
}

fn draw_footer(f: &mut ratatui::Frame, area: Rect, state: &TuiState, search_mode: bool) {
    let text = if search_mode {
        format!(
            " /  search: {}_   (Enter to apply, Esc to cancel) ",
            state.search
        )
    } else {
        format!(
            " q quit   / search ({})   p pause ({})   j/k move   ",
            state.search,
            if state.paused { "on" } else { "off" }
        )
    };
    let p = Paragraph::new(text).style(Style::default().bg(Color::Blue).fg(Color::White));
    f.render_widget(p, area);
}

fn short_ts(s: &str) -> String {
    s.chars().take(19).collect()
}

fn short_fields(fields: &std::collections::BTreeMap<String, serde_json::Value>) -> String {
    let mut s = serde_json::to_string(fields).unwrap_or_default();
    if s.len() > 80 {
        s.truncate(80);
        s.push_str("...");
    }
    s
}

async fn fetch_audit(
    socket: &PathBuf,
    server: Option<String>,
    limit: usize,
) -> Result<Vec<AuditEventEnvelope>> {
    let mut stream = UnixStream::connect(socket).await?;
    let (mut r, mut w) = stream.split();
    Codec::write_message(
        &mut w,
        &ClientRequest::Audit {
            filter: AuditFilter {
                server,
                event_type: None,
                since_seconds: None,
                limit: Some(limit),
            },
            follow: false,
        },
    )
    .await?;
    let resp: DaemonResponse = Codec::read_message(&mut r).await?;
    match resp {
        DaemonResponse::AuditEvents { events, .. } => Ok(events),
        DaemonResponse::Error { message, .. } => Err(anyhow::anyhow!(message)),
        other => Err(anyhow::anyhow!("unexpected: {other:?}")),
    }
}
