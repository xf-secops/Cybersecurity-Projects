# AngelusVigil

IN PROGRESS

AI-powered threat detection engine that analyzes web server access logs using machine learning to classify HTTP traffic as benign or malicious in real-time.

Deploys as a Docker sidecar alongside any nginx-based infrastructure. Zero code changes to the monitored application.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| API | FastAPI (async) |
| ML | PyTorch autoencoder + scikit-learn (RF + IF) |
| Inference | ONNX Runtime (CPU) |
| Database | PostgreSQL 18 |
| Cache | Redis 7.4 |
| GeoIP | MaxMind GeoLite2 |

## Quick Start

```bash
just setup
just dev-up
```

## Architecture

3-model ensemble (autoencoder + Random Forest + Isolation Forest) scores each request through a weighted fusion producing a unified threat score [0.0, 1.0]:

- **HIGH** (0.7+): Store + alert + block recommendation
- **MEDIUM** (0.5-0.7): Store + monitor
- **LOW** (<0.5): Log only

See `learn/` for detailed documentation.

## License

AGPLv3 - See [LICENSE](LICENSE)
