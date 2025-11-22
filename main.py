from __future__ import annotations

import re
from typing import List, Literal, Tuple

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel


class ScanRequest(BaseModel):
    prompt: str


class ScanResponse(BaseModel):
    status: Literal["SAFE", "BLOCKED"]
    triggers: List[str]
    sanitized: str


Rule = Tuple[str, List[str]]


RULES: List[Rule] = [
    ("ignore_previous", ["ignore previous", "ignore all previous", "disregard previous"]),
    ("system_prompt_disclosure", ["delete system", "show system prompt"]),
    ("jailbreak", ["jailbreak", "developer mode"]),
    ("bypass", ["bypass", "override instructions"]),
]

app = FastAPI(title="Aegis Prompt Firewall")
templates = Jinja2Templates(directory="templates")


def scan_prompt(prompt: str) -> Tuple[Literal["SAFE", "BLOCKED"], List[str], str]:
    lowered = prompt.lower()
    triggers: List[str] = []
    sanitized = prompt

    for rule_id, patterns in RULES:
        matched = False
        for pattern in patterns:
            if pattern in lowered:
                matched = True
                sanitized = re.sub(re.escape(pattern), "*****", sanitized, flags=re.IGNORECASE)
        if matched:
            triggers.append(rule_id)

    status: Literal["SAFE", "BLOCKED"] = "BLOCKED" if triggers else "SAFE"
    return status, triggers, sanitized


@app.get("/", response_class=HTMLResponse)
async def home(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "rules": RULES,
            "title": "Aegis Prompt Firewall",
        },
    )


@app.post("/scan", response_model=ScanResponse)
async def scan(payload: ScanRequest) -> ScanResponse:
    status, triggers, sanitized = scan_prompt(payload.prompt)
    return ScanResponse(status=status, triggers=triggers, sanitized=sanitized)
