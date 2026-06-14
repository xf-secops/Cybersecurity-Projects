// ©AngelaMos | 2026
// cli.rs

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use tlsfp_core::{FingerprintEvent, PcapFileSource, Pipeline, PipelineConfig, SourceError};

use crate::live::{DEFAULT_BPF_FILTER, LiveConfig, LiveSource};

/// JA3/JA4 TLS fingerprinting tool.
///
/// Fingerprints TLS clients and servers from live capture or packet captures,
/// matches them against a local intelligence database, and flags anomalies such
/// as a fingerprint that disagrees with its own User-Agent.
#[derive(Debug, Parser)]
#[command(name = "tlsfp", version, about, long_about = None)]
pub struct Cli {
    /// Increase log verbosity (repeat for more detail).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Fingerprint every TLS and QUIC handshake in a packet capture file.
    Pcap {
        /// Path to a pcap or pcapng file.
        path: std::path::PathBuf,

        /// Emit one JSON object per event instead of readable lines.
        #[arg(long)]
        json: bool,
    },

    /// Capture live from a network interface and fingerprint in real time.
    ///
    /// Live capture opens a raw socket, which an unprivileged user cannot
    /// do. Rather than running the whole tool as root, grant the binary the
    /// two capabilities libpcap needs:
    ///
    ///   sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tlsfp)"
    ///
    /// cap_net_raw opens the capture socket, cap_net_admin covers
    /// promiscuous mode, and =eip marks both permitted, inheritable, and
    /// effective when the binary runs. File capabilities live on the binary
    /// itself, so repeat the grant after every rebuild, and point it at
    /// target/debug/tlsfp or target/release/tlsfp when running from cargo.
    ///
    /// The default --filter keeps all TCP (TLS lives on any port, JA4T
    /// wants the SYNs) plus UDP 443 for QUIC, and drops everything else in
    /// the kernel. Tighten it on busy links, for example:
    ///
    ///   tlsfp live eth0 --filter "tcp port 443"
    ///
    /// Stop with ctrl-c: the first one drains and prints final counters, a
    /// second one exits immediately.
    #[command(verbatim_doc_comment)]
    Live {
        /// Interface name, for example eth0, or any for every interface.
        interface: String,

        /// Emit one JSON object per event instead of readable lines.
        #[arg(long)]
        json: bool,

        /// BPF filter compiled into the kernel before capture begins.
        #[arg(long, default_value = DEFAULT_BPF_FILTER)]
        filter: String,

        /// Capture only traffic the interface would normally receive
        /// instead of switching it to promiscuous mode.
        #[arg(long)]
        no_promisc: bool,
    },

    /// Serve the web dashboard and HTTP API.
    Serve {
        /// Address to bind, for example 127.0.0.1:8080.
        #[arg(default_value = "127.0.0.1:8080")]
        bind: String,
    },
}

impl Cli {
    pub fn init_tracing(&self) {
        let default = match self.verbose {
            0 => "tlsfp=info",
            1 => "tlsfp=debug",
            _ => "tlsfp=trace",
        };
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .init();
    }

    pub fn run(self) -> Result<()> {
        match self.command {
            Command::Pcap { path, json } => run_pcap(&path, json),
            Command::Live {
                interface,
                json,
                filter,
                no_promisc,
            } => run_live(&interface, json, filter, !no_promisc),
            Command::Serve { bind } => {
                anyhow::bail!("dashboard on {bind} is not wired up yet")
            }
        }
    }
}

/// Fingerprints a capture file and prints one event per line on stdout.
///
/// The summary goes to the log rather than stdout so that piping the output
/// into a tool sees only events, while a human still learns how much of the
/// capture was readable and whether the file was cut short mid packet.
fn run_pcap(path: &std::path::Path, json: bool) -> Result<()> {
    let mut source = PcapFileSource::open(path)
        .with_context(|| format!("cannot open capture {}", path.display()))?;
    let mut pipeline = Pipeline::new(PipelineConfig::default());

    let stdout = std::io::stdout().lock();
    let mut out = std::io::BufWriter::new(stdout);
    let mut write_failure = None;
    pipeline.run(&mut source, |event| {
        use std::io::Write as _;
        let result = if json {
            serde_json::to_writer(&mut out, &event)
                .map_err(anyhow::Error::from)
                .and_then(|()| writeln!(out).map_err(anyhow::Error::from))
        } else {
            writeln!(out, "{event}").map_err(anyhow::Error::from)
        };
        if write_failure.is_none() {
            if let Err(error) = result {
                write_failure = Some(error);
            }
        }
    })?;
    if let Some(error) = write_failure {
        return Err(error.context("writing events to stdout"));
    }
    {
        use std::io::Write as _;
        out.flush().context("flushing events to stdout")?;
    }

    let counters = pipeline.counters();
    tracing::info!(
        frames = counters.frames,
        tcp_segments = counters.tcp_segments,
        udp_datagrams = counters.udp_datagrams,
        events = counters.events,
        flows = counters.flows_created,
        quic_initials = counters.quic_initials,
        quic_decrypted = counters.quic_decrypted,
        quic_version_unsupported = counters.quic_version_unsupported,
        unfinished_tls_streams = counters.unfinished_tls_streams,
        segments_dropped = counters.segments_dropped,
        "capture processed"
    );
    if source.truncated() {
        tracing::warn!("capture file ended mid packet; the tail was not read");
    }
    Ok(())
}

/// Captures from an interface until ctrl-c and fingerprints in real time.
///
/// The capture itself runs on a dedicated OS thread inside [`LiveSource`];
/// this function owns the tokio side of the bridge. The runtime is built
/// here rather than in main so the file path stays a plain synchronous
/// program.
fn run_live(interface: &str, json: bool, filter: String, promiscuous: bool) -> Result<()> {
    let config = LiveConfig {
        filter,
        promiscuous,
    };
    let source = LiveSource::open(interface, &config)?;
    tracing::info!(interface, filter = %config.filter, "live capture started");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the async runtime")?;
    runtime.block_on(drive_live(source, json))
}

/// Drains the live source through the same pipeline the file path uses.
///
/// Events flush per line so the stream is followable as it happens. The
/// first ctrl-c asks the capture thread to stop and lets the channel
/// drain, which makes the final counters trustworthy; a second ctrl-c
/// exits without ceremony. A closed stdout pipe is a normal way for a
/// live session to end, so it stops the capture instead of reporting an
/// error.
async fn drive_live(mut source: LiveSource, json: bool) -> Result<()> {
    let stop = source.stop_handle();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::info!("ctrl-c received; draining capture");
            stop.stop();
        }
        if tokio::signal::ctrl_c().await.is_ok() {
            std::process::exit(130);
        }
    });

    let mut pipeline = Pipeline::new(PipelineConfig::default());
    let stdout = std::io::stdout().lock();
    let mut out = std::io::BufWriter::new(stdout);
    let mut write_failure: Option<std::io::Error> = None;

    let capture_failure: Option<SourceError> = loop {
        let received = source.next_frame_async().await;
        let frame = match received {
            Ok(Some(frame)) => frame,
            Ok(None) => break None,
            Err(error) => break Some(error),
        };
        pipeline.feed(&frame, &mut |event| {
            write_live_event(&mut out, &event, json, &mut write_failure);
        });
        if write_failure.is_some() {
            break None;
        }
    };
    pipeline.finish();

    let counters = pipeline.counters();
    tracing::info!(
        frames = counters.frames,
        tcp_segments = counters.tcp_segments,
        udp_datagrams = counters.udp_datagrams,
        events = counters.events,
        flows = counters.flows_created,
        quic_initials = counters.quic_initials,
        quic_decrypted = counters.quic_decrypted,
        quic_version_unsupported = counters.quic_version_unsupported,
        unfinished_tls_streams = counters.unfinished_tls_streams,
        segments_dropped = counters.segments_dropped,
        "live capture stopped"
    );

    if let Some(stats) = source.close() {
        tracing::info!(
            received = stats.received,
            kernel_dropped = stats.kernel_dropped,
            interface_dropped = stats.interface_dropped,
            "kernel capture statistics"
        );
        if stats.kernel_dropped > 0 || stats.interface_dropped > 0 {
            tracing::warn!(
                "the kernel dropped frames; an absent fingerprint is not proof of an absent handshake"
            );
        }
    }

    match (write_failure, capture_failure) {
        (Some(error), _) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        (Some(error), _) => Err(anyhow::Error::from(error).context("writing events to stdout")),
        (None, Some(error)) => Err(anyhow::Error::from(error).context("live capture failed")),
        (None, None) => Ok(()),
    }
}

/// Writes one event and flushes it immediately, recording the first
/// failure instead of panicking inside the pipeline's sink. Later calls
/// become no-ops once a write has failed.
fn write_live_event(
    out: &mut impl std::io::Write,
    event: &FingerprintEvent,
    json: bool,
    failure: &mut Option<std::io::Error>,
) {
    if failure.is_some() {
        return;
    }
    let result = if json {
        serde_json::to_writer(&mut *out, event)
            .map_err(std::io::Error::from)
            .and_then(|()| writeln!(out))
            .and_then(|()| out.flush())
    } else {
        writeln!(out, "{event}").and_then(|()| out.flush())
    };
    if let Err(error) = result {
        *failure = Some(error);
    }
}
