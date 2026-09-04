"""Tarea de análisis de logs (módulo de ampliación).

Sigue el mismo patrón que la interpretación de escaneos: parsea, construye la
instrucción y consulta al modelo, con las mismas salvaguardas.
"""
from __future__ import annotations

from dataclasses import dataclass

from src.parsers.log_parser import parse_logs
from src.llm.router import ModelRouter
from src.llm.factory import make_client
from src.llm.openrouter_client import LLMResponse

TASK = "analyze_logs"

SYSTEM = (
    "Eres un analista de seguridad que revisa registros de actividad. Trabaja "
    "solo con las líneas proporcionadas. Señala indicios de interés (accesos "
    "fallidos repetidos, patrones anómalos, posibles ataques) y di explícitamente "
    "cuando algo no pueda determinarse a partir de los datos. Responde en español."
)
USER_TMPL = (
    "Analiza los siguientes registros e indica: 1) resumen, 2) indicios de "
    "interés y su gravedad, 3) recomendaciones.\n\n--- LOGS ---\n{logs}\n--- FIN ---"
)


@dataclass
class LogAnalysis:
    model: str
    response: LLMResponse


def analyze_logs_file(path: str, client=None, router: ModelRouter | None = None) -> LogAnalysis:
    router = router or ModelRouter()
    logs = parse_logs(path)
    model = router.select(TASK)
    client = client or make_client(model)
    resp = client.chat(model=model, system=SYSTEM, user=USER_TMPL.format(logs=logs.summary()), task=TASK)
    return LogAnalysis(model=model, response=resp)
