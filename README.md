# PIICOMB — Local PII discovery in your own files — SSN/CC/passport/DL/email/phone/DOB

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> MIT License · domain: `privacy`

[![PyPI](https://img.shields.io/pypi/v/cognis-piicomb.svg)](https://pypi.org/project/cognis-piicomb/)
[![CI](https://github.com/cognis-digital/piicomb/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/piicomb/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Local PII discovery in your own files — SSN/CC/passport/DL/email/phone/DOB.

## Install

```bash
pip install cognis-piicomb
```

For local development from this repo:

```bash
pip install -e .
```

## Quick start

```bash
piicomb --version
piicomb scan demos/                          # run against bundled demo
piicomb scan demos/ --format sarif --out r.sarif --fail-on high
piicomb mcp                                   # start as MCP server (Cognis.Studio / Claude Desktop / Cursor)
```

## Built-in demo scenarios

Every scenario folder includes a `SCENARIO.md` describing what it represents and what findings to expect.

- `demos/01-customer-export-leak/` — see [`SCENARIO.md`](demos/01-customer-export-leak/SCENARIO.md)
- `demos/02-source-code-sprawl/` — see [`SCENARIO.md`](demos/02-source-code-sprawl/SCENARIO.md)
- `demos/03-log-file-sprawl/` — see [`SCENARIO.md`](demos/03-log-file-sprawl/SCENARIO.md)

## How it fits the Cognis Neural Suite

This tool is one of 52 in the [Cognis Neural Suite](https://github.com/cognis-digital). The full suite + launcher lives at:

- Suite landing: https://cognis.digital
- All 52 repos: https://github.com/cognis-digital
- Cognis.Studio (Enterprise AI Workforce, MCP host): https://cognis.studio

Every Suite tool ships an MCP server, so Cognis.Studio agents can call them as scoped capabilities.

## License

MIT. See [LICENSE](LICENSE).

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
