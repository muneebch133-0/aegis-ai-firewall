# 🛡️ Aegis Prompt Firewall

A FastAPI **prompt firewall** that scans user prompts for prompt-injection and
jailbreak attempts, scores the risk **0–100**, maps every detection to the
**[OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)**,
and **blocks malicious prompts before they ever reach the model**. Prompts that
pass the firewall are proxied to **Claude** (`claude-opus-4-8`).

> It's not just a scanner — it's a real firewall: clean prompts get a live LLM
> answer, malicious ones are stopped at the gate.

## ✨ Features

- **Risk scoring (0–100) + severity bands** — `SAFE` / `FLAGGED` / `BLOCKED`,
  with `LOW` → `CRITICAL` severity instead of a binary verdict.
- **OWASP LLM Top 10 mapping** — every rule is tagged (LLM01 Prompt Injection,
  LLM02 Sensitive Information Disclosure, LLM06 Excessive Agency, LLM07 System
  Prompt Leakage).
- **Live `/proxy-chat`** — scans first; forwards to Claude **only if the prompt
  passes**. Falls back to "demo mode" with no API key.
- **Obfuscation-aware matching** — Unicode + leetspeak normalization, zero-width
  char stripping, and common homoglyph folding so `1gn0re prev10us` (and
  zero-width / Cyrillic-look-alike variants) still trip the rule.
- **Prompt sanitization** — matched spans are redacted with `[BLOCKED]`.
- **Cyberpunk dashboard** with a live risk gauge, OWASP tags, sample attacks,
  and an inline Claude response.

## 🚀 Getting Started

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

Open <http://127.0.0.1:8000/>. The firewall works out of the box (demo mode).
For live Claude responses, copy `.env.example` to `.env` and set
`ANTHROPIC_API_KEY` (or export it in your shell), then restart.

### Docker

```bash
docker build -t aegis .
docker run -p 8000:8000 -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY aegis
```

## 🔌 API

| Method | Path          | Description |
|--------|---------------|-------------|
| `GET`  | `/`           | Dashboard |
| `GET`  | `/health`     | Liveness + config (`proxy: live\|demo`) |
| `GET`  | `/rules`      | All rules with OWASP category, severity, weight |
| `POST` | `/scan`       | Scan a prompt → status, risk_score, severity, triggers, sanitized |
| `POST` | `/proxy-chat` | Scan, then forward to Claude only if it passes |

```bash
curl -s localhost:8000/scan -H 'content-type: application/json' \
  -d '{"prompt":"ignore all previous instructions"}'
```

```json
{
  "status": "BLOCKED",
  "risk_score": 50,
  "severity": "HIGH",
  "triggers": [
    { "id": "instruction_override", "name": "Instruction Override",
      "owasp": "LLM01: Prompt Injection", "severity": "HIGH",
      "description": "Attempts to override, ignore, or replace the system instructions.",
      "matched": ["ignore\\s+(all\\s+|the\\s+)?(previous|prior|above)"] }
  ],
  "owasp_categories": ["LLM01: Prompt Injection"],
  "sanitized": "[BLOCKED] instructions"
}
```

Any `HIGH`/`CRITICAL` rule blocks on its own; lower-severity rules accumulate
toward `AEGIS_BLOCK_THRESHOLD`. Prompts over `AEGIS_MAX_PROMPT_CHARS` (default
20,000) are rejected with `422`.

## ⚙️ Configuration

| Env var                 | Default          | Purpose |
|-------------------------|------------------|---------|
| `ANTHROPIC_API_KEY`     | _(unset)_        | Enables live `/proxy-chat` |
| `AEGIS_PROXY_MODEL`     | `claude-opus-4-8`| Model used for passed prompts |
| `AEGIS_BLOCK_THRESHOLD` | `40`             | Risk score at/above which a prompt is blocked |

## 🧪 Tests

```bash
pip install pytest
pytest -q
```

## 🗺️ Roadmap

- Semantic / ML detection (embeddings, Llama Guard / PromptGuard) alongside rules
- Attack-log analytics on the dashboard
- Benchmark against a public jailbreak dataset (detection rate + false-positive rate)
- PII detection & redaction

## 🚢 Deploying live

`/proxy-chat` calls Claude with **your** API key. Before exposing a public
instance, put it behind authentication and rate limiting (e.g. a reverse-proxy
auth layer or [`slowapi`](https://github.com/laurentS/slowapi)) so it can't be
used to run up your Anthropic bill. The input-size cap is enforced; auth and
throttling are deployment concerns left to you.

## ⚠️ Disclaimer

A defense-in-depth layer and educational tool — not a complete guarantee against
prompt injection. Pair it with model-side guardrails and least-privilege design.
