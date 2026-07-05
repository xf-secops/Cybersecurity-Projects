# Nadezhda

A concurrent security-news and CVE aggregation engine, written in Go.

Nadezhda ingests cybersecurity news from reliable RSS feeds, enriches every
referenced CVE with authoritative exploit intelligence (NVD, CISA KEV, FIRST
EPSS), clusters the same story across outlets, ranks items by real-world
significance, and surfaces content angles. It ships as a single static binary
with a local SQLite store, a colorful terminal UI, and Markdown/JSON export.

## Status

Early development. The scaffold is in place: configuration, source registry,
SQLite store with forward-only migrations, and the command skeleton.

```
nadezhda version     # print version
nadezhda sources     # list configured feeds and persist them to the store
```

Ingestion, CVE enrichment, ranking, the TUI, and the AI ideation layer land in
subsequent milestones.

## Build

```
just build     # -> ./nadezhda
just test
```

Requires Go 1.25+.

---

Full documentation lands in `learn/` as the project matures.
