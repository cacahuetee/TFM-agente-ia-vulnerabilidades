"""Flujo de extremo a extremo: parseo -> (CVE + ATT&CK/OWASP) -> prompt ->
selección de modelo -> consulta -> respuesta con trazabilidad."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from src.parsers.dispatch import parse_scan
from src.llm.router import ModelRouter
from src.llm.factory import make_client
from src.llm.openrouter_client import LLMResponse
from src.knowledge.cve import CVELookup
from src.knowledge.attack_owasp import attack_owasp_context
from src.schema import ScanResult

TASK = "interpret_scan"
PROMPT_PATH = Path(__file__).resolve().parent.parent.parent / "prompts" / "interpret_scan.md"


def _load_prompt() -> tuple[str, str]:
    text = PROMPT_PATH.read_text(encoding="utf-8")
    m = re.search(r"SYSTEM:\s*(.*?)\s*USER:\s*(.*)", text, re.DOTALL)
    if not m:
        raise ValueError("La plantilla debe contener las marcas SYSTEM: y USER:")
    return m.group(1).strip(), m.group(2).strip()


@dataclass
class InterpretationResult:
    scan: ScanResult
    model: str
    response: LLMResponse


def interpret_scan_file(path: str, enrich: bool = False,
                        client=None, router: ModelRouter | None = None,
                        cve_lookup: CVELookup | None = None) -> InterpretationResult:
    router = router or ModelRouter()
    scan = parse_scan(path)
    if enrich:
        scan = (cve_lookup or CVELookup()).enrich_scan(scan)

    system, user_template = _load_prompt()
    context = attack_owasp_context(scan)
    summary = scan.summary() + ("\n\n" + context if context else "")
    user = user_template.format(scan_summary=summary)

    model = router.select(TASK)
    client = client or make_client(model)
    response = client.chat(model=model, system=system, user=user, task=TASK)
    return InterpretationResult(scan=scan, model=model, response=response)
