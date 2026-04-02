use anyhow::Result;
use clap::{Parser, Subcommand};
use zitpit_battle_runner::{BattleRunner, BrowserMode};
use zitpit_battle_types::BattleSuite;

#[derive(Debug, Parser)]
#[command(name = "zitpit-battle-cli")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Lint,
    Fast,
    GitCore,
    Actions,
    Artifact,
    Browser,
    Queue,
    Controls,
    PublicCore,
    All,
    Vm,
    Go,
    Cargo,
    Shell,
    Workspace,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let runner = BattleRunner::default();
    match cli.command {
        Command::Lint => {
            let packs = runner.lint()?;
            println!("validated {} battle packs", packs.len());
        }
        Command::Fast => print_report(
            runner
                .run_suite(BattleSuite::Fast, BrowserMode::SkipIfUnavailable)
                .await?,
        )?,
        Command::GitCore => print_report(
            runner
                .run_suite(BattleSuite::GitCore, BrowserMode::SkipIfUnavailable)
                .await?,
        )?,
        Command::Actions => print_report(
            runner
                .run_suite(BattleSuite::Actions, BrowserMode::SkipIfUnavailable)
                .await?,
        )?,
        Command::Artifact => print_report(
            runner
                .run_suite(BattleSuite::Artifact, BrowserMode::SkipIfUnavailable)
                .await?,
        )?,
        Command::Browser => print_report(
            runner
                .run_suite(BattleSuite::Browser, BrowserMode::Require)
                .await?,
        )?,
        Command::Queue => print_report(
            runner
                .run_suite(BattleSuite::Queue, BrowserMode::SkipIfUnavailable)
                .await?,
        )?,
        Command::Controls => print_report(
            runner
                .run_suite(BattleSuite::Controls, BrowserMode::SkipIfUnavailable)
                .await?,
        )?,
        Command::PublicCore => print_report(
            runner
                .run_suite(BattleSuite::PublicCore, BrowserMode::SkipIfUnavailable)
                .await?,
        )?,
        Command::Vm => print_report(
            runner
                .run_suite(BattleSuite::Vm, BrowserMode::SkipIfUnavailable)
                .await?,
        )?,
        Command::Go => print_report(
            runner
                .run_suite(BattleSuite::Go, BrowserMode::SkipIfUnavailable)
                .await?,
        )?,
        Command::Cargo => print_report(
            runner
                .run_suite(BattleSuite::Cargo, BrowserMode::SkipIfUnavailable)
                .await?,
        )?,
        Command::Shell => print_report(
            runner
                .run_suite(BattleSuite::Shell, BrowserMode::SkipIfUnavailable)
                .await?,
        )?,
        Command::Workspace => print_report(
            runner
                .run_suite(BattleSuite::Workspace, BrowserMode::SkipIfUnavailable)
                .await?,
        )?,
        Command::All => {
            for suite in [
                BattleSuite::Fast,
                BattleSuite::GitCore,
                BattleSuite::Actions,
                BattleSuite::Artifact,
                BattleSuite::Browser,
                BattleSuite::Queue,
                BattleSuite::Controls,
                BattleSuite::PublicCore,
                BattleSuite::Go,
                BattleSuite::Cargo,
                BattleSuite::Shell,
                BattleSuite::Workspace,
            ] {
                print_report(
                    runner
                        .run_suite(suite, BrowserMode::SkipIfUnavailable)
                        .await?,
                )?;
            }
        }
    }
    Ok(())
}

fn print_report(report: zitpit_battle_types::BattleSuiteReport) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
