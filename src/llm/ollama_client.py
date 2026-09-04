"""Cliente para modelos locales vía Ollama (para el análisis privacidad/rendimiento).

Mantiene la misma interfaz que OpenRouterClient (método chat -> LLMResponse),
de modo que el resto del sistema no distingue entre uno y otro. Requiere tener
Ollama instalado y en ejecución localmente (https://ollama.com).
"""
from __future__ import annotations

import time

import requests

from src.llm.openrouter_client import LLMResponse
from src.trace import log_call

OLLAMA_URL = "http://localhost:11434/api/chat"


class OllamaClient:
    def __init__(self, base_url: str = OLLAMA_URL):
        self.base_url = base_url

    def chat(self, model: str, system: str, user: str,
             temperature: float = 0.2, max_tokens: int = 1200, timeout: int = 300,
             task: str = "chat") -> LLMResponse:
        # el identificador puede venir como "ollama:llama3" -> se usa "llama3"
        name = model.split(":", 1)[1] if model.startswith("ollama:") else model
        payload = {
            "model": name,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "options": {"temperature": temperature},
            "stream": False,
        }
        start = time.perf_counter()
        r = requests.post(self.base_url, json=payload, timeout=timeout)
        latency = time.perf_counter() - start
        r.raise_for_status()
        data = r.json()
        text = data.get("message", {}).get("content", "")
        resp = LLMResponse(text=text, model=model, latency_s=latency,
                           prompt_tokens=data.get("prompt_eval_count"),
                           completion_tokens=data.get("eval_count"), raw=data)
        log_call(task=task, model=model, latency_s=latency,
                 prompt_tokens=resp.prompt_tokens, completion_tokens=resp.completion_tokens)
        return resp
