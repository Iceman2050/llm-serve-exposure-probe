# llm-serve-exposure-probe

**Your inference server may be one unauthenticated request away from RCE.**

On 2026-10-07, JFrog disclosed **CVE-2026-105192** (CVSS 9.8) in LMCache: a single ZeroMQ network message executes code as the cache user with no login — and no fixed version exists yet (THN). Operators routinely bind inference infra to routable addresses by mistake.

Port scanners don't speak AI-inference protocols. This probe does:
- **HTTP probes** — vLLM `/v1/models`, Ollama `/api/tags`, Triton `/v2/health/ready` (proves unauthenticated access, not just an open port)
- **ZMTP greeting** — raw-socket ZeroMQ handshake detection (the LMCache attack surface)

## Authorized testing ONLY
Point this at infrastructure you own or are explicitly authorized to test. Scanning third-party hosts you don't own is unauthorized access — don't.

## What it does NOT detect
Authenticated misconfigurations, or vulnerabilities beyond unauthenticated exposure. A clean scan means "no exposed endpoints on probed ports", never a safety certification.

## Usage
```
python -m llm_serve_exposure_probe 10.0.0.5 --ports 8000,11434,8001,5555
```

## Built by Ingenious AI

This tool is built and maintained by **Ingenious AI**. Get early access to our AI security platforms:

- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI

