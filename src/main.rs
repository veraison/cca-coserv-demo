// Copyright 2022-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use std::process::ExitCode;

use clap::Parser;
use clap_verbosity_flag::{InfoLevel, Verbosity};
use log::{error, info};

mod error;
mod query;
mod store;
mod verify;

use verify::verify;

/// A command-line utility to show how CoVer can be used
/// to appraise a CCA evidence using CoSERV as the source
/// of trust anchors and reference values.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Path to the CBOR-encoded ARM CCA EAT profile token.
    #[arg(short, long)]
    evidence: String,

    /// The base URL to a CoSERV service.
    #[arg(short = 'c', long)]
    coserv_server: String,

    /// The path to an X509 certificate to bootstrap TLS handshakes with the CoSERV service.
    #[arg(short = 't', long)]
    ca_cert: Option<String>,

    /// The path into which the command output will be written. If not specified, it will be
    /// generated based on the name of the evidence file.
    #[arg(short, long)]
    output: Option<String>,

    /// Pretty print the EAR.
    #[arg(short, long, default_value_t = false, global = true)]
    pretty: bool,

    /// Force overwrite output if exists.
    #[arg(short, long, default_value_t = false, global = true)]
    force: bool,

    #[command(flatten)]
    verbosity: Verbosity<InfoLevel>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Cli::parse();

    env_logger::builder()
        .filter_level(args.verbosity.log_level_filter())
        .init();

    match verify(&args).await {
        Ok(()) => {
            info!("verification done.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("verification failed: {e}");
            ExitCode::FAILURE
        }
    }
}
