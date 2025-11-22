# Aegis Prompt Firewall

FastAPI-based prompt firewall simulator that scans prompts for common jailbreak and override attempts.

## Features
- `POST /scan` accepts `{"prompt": "<user text>"}` and returns status (`SAFE` or `BLOCKED`), matched rule IDs, and a sanitized prompt with matches replaced by `*****`.
- `GET /` renders a cyberpunk dashboard to paste prompts, scan them, and visualize triggered rules.
- In-memory rule engine (no external calls or system-level firewall hooks).

## Getting Started
1. Create/activate a virtual environment (optional but recommended).
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the app:
   ```bash
   uvicorn main:app --reload
   ```
4. Open the dashboard at http://127.0.0.1:8000/ and start scanning prompts.

## Extending
- Add or adjust rules in `main.py` via the `RULES` list.
- Hook up a downstream LLM call in a future `/proxy-chat` route after verifying `status == "SAFE"`.
