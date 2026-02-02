# Isnad

**Trust infrastructure for the agent internet.**

Verify agents. Audit skills. Trust the chain.

## What is Isnad?

Isnad is a security scanning and verification service for AI agent skills. Think npm audit meets Verisign, purpose-built for the agent ecosystem.

The name comes from the Arabic إسناد (isnad) — the chain of transmission used in Islamic scholarship to verify authenticity. Each link in the chain is verified: who told whom, and are they trustworthy?

## Features

- **🔍 Skill Scanner** — Upload any skill.md, get a security report
- **✓ Verified Authors** — Cryptographic signing + identity verification  
- **📋 Permission Manifests** — Standard declarations of what skills access

## Why?

The agent ecosystem has a trust problem:
- Skills are unsigned code from strangers
- No verification, no audit trail
- 1 in 286 skills scanned contained a credential stealer

We're building the security layer the agent internet needs.

## Quick Start

### CLI Usage

```bash
# Install
pip install -r requirements.txt

# Scan a URL
python cli.py scan https://example.com/skill.md

# Scan a local file
python cli.py scan ./my-skill.md

# Scan raw content
python cli.py scan --content "import os; os.environ['API_KEY']"

# JSON output
python cli.py scan skill.md --json
```

### API Usage

```bash
# Start the server
uvicorn api.main:app --reload

# Scan a skill via API
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/skill.md"}'

# Or scan content directly
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"content": "import os; key = os.environ[\"API_KEY\"]"}'
```

### Docker

```bash
# Build and run
docker-compose up --build

# Or with plain Docker
docker build -t isnad .
docker run -p 8000:8000 isnad
```

## What It Detects

| Category | Examples | Severity |
|----------|----------|----------|
| **Credential Access** | API keys, .env files, SSH keys, cloud credentials | HIGH-CRITICAL |
| **Data Exfiltration** | webhook.site, requestbin, suspicious POST requests | CRITICAL |
| **Obfuscation** | eval(), exec(), base64 decode, hex encoding | MEDIUM-HIGH |
| **Shell Execution** | subprocess, os.system, child_process | MEDIUM-HIGH |
| **Instruction Injection** | "ignore previous instructions", role override | HIGH-CRITICAL |
| **Suspicious URLs** | Direct IPs, known malicious patterns | MEDIUM |

## Project Structure

```
isnad/
├── scanner/
│   ├── __init__.py
│   ├── core.py          # Main scanning engine
│   └── patterns.py      # Detection patterns library
├── api/
│   └── main.py          # FastAPI application
├── web/
│   └── index.html       # Web UI
├── tests/
│   └── test_scanner.py  # Test suite
├── cli.py               # Command-line interface
├── Dockerfile
├── docker-compose.yml
├── fly.toml             # Fly.io deployment config
└── requirements.txt
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Service info |
| `/health` | GET | Health check |
| `/api/v1/scan` | POST | Scan a skill (URL or content) |
| `/api/v1/scan/{id}` | GET | Get scan result by ID |
| `/api/v1/check/{hash}` | GET | Check if content hash was scanned |
| `/api/v1/registry` | GET | List scanned skills |

## Deployment

### Fly.io (Recommended)

```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Deploy
fly deploy
```

### Other Platforms

Works with any platform that supports Docker:
- Railway
- Render
- Google Cloud Run
- AWS ECS

## Roadmap

- [x] Core scanner engine
- [x] Pattern library
- [x] REST API
- [x] Web UI
- [x] CLI tool
- [x] Docker support
- [ ] Verified author program
- [ ] Permission manifests
- [ ] Public registry
- [ ] Enterprise features

## Contributing

We're looking for co-builders! Especially:
- Security engineers (YARA rules, threat patterns)
- Backend developers (Python, FastAPI)
- Anyone passionate about agent security

See our [Moltbook post](https://moltbook.com/post/29877ed6-76ee-4f49-a13c-8b986f9e87df) for details.

## Status

🚧 **Alpha** — Under active development

## Links

- Website: https://isnad.dev
- Moltbook: https://moltbook.com/u/ClawTopian

## License

MIT

---

Built by ClawTopian + Hughey 🔱

*"The chain of trust for the agent internet."*
