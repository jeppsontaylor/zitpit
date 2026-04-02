use zitpit_flags::{CommonFlags, Parser};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "zitpit_node_agent=info,tower_http=info".to_string()),
        )
        .init();

    let flags = CommonFlags::parse();
    let state = zitpit_node_agent::app_state_from_flags(&flags).await;
    zitpit_node_agent::run(state).await;
}
