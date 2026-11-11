# llm-serve-exposure-probe

**CVE-2026-105192 (LMCache, Oct 2026): LLM-serving endpoints exposed to the internet with no auth.**

Teams stand up vLLM / Ollama / LMCache for internal use and forget the port is reachable. This prober checks the common LLM-serving ports on infrastructure you own and tells you what's listening.

## 30-second quickstart
```
python llm_serve_exposure_probe.py 10.0.4.21
```

## Example output
```
{
  "host": "127.0.0.1",
  "ports_scanned": [8000, 11434, 8001, 8002, 5555],
  "findings": [],
  "verdict": "CLEAN — no exposed LLM-serving endpoints detected on probed ports",
  "notice": "AUTHORIZED TESTING ONLY — only scan infrastructure you own or are explicitly authorized to test."
}
```

`--ports` to customize, `--timeout` per-port (default 5s).

## What it does NOT do
A port prober, not a vulnerability scanner — it finds exposed endpoints, it doesn't exploit them. **Only scan infrastructure you own or are authorized to test.**

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



> Built by Ingenious AI
