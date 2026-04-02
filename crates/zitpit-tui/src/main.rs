#[tokio::main]
async fn main() -> anyhow::Result<()> {
    zitpit_tui::run_terminal_app().await
}
