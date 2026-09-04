"""Cliente para OpenRouter con reintentos y registro de trazabilidad.

Devuelve el texto y metadatos (latencia, tokens). Reintenta ante errores de
límite (429) y de servidor (5xx) con espera creciente, y registra cada
llamada para la trazabilidad exigida por el objetivo 6.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

import requests

from src import config
from src.trace import log_call


@dataclass
class LLMResponse:
    text: str
    model: str
    latency_s: float
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    raw: Optional[dict] = None


class OpenRouterClient:
    def __init__(self, api_key: str | None = None, base_url: str | None = None,
                 max_retries: int = 4):
        self.api_key = api_key or config.get_api_key()
        self.base_url = base_url or config.OPENROUTER_BASE_URL
        self.max_retries = max_retries
        if not self.api_key:
            raise ValueError("No hay clave de OpenRouter. Introdúcela al entrar en la web "
                             "o define OPENROUTER_API_KEY en el entorno.")

    def chat(self, model: str, system: str, user: str,
             temperature: float = 0.2, max_tokens: int = 1200, timeout: int = 120,
             task: str = "chat") -> LLMResponse:
        url = f"{self.base_url}/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        payload = {
            "model": model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        start = time.perf_counter()
        data = self._post_with_retries(url, headers, payload, timeout)
        latency = time.perf_counter() - start

        text = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        resp = LLMResponse(text=text, model=model, latency_s=latency,
                           prompt_tokens=usage.get("prompt_tokens"),
                           completion_tokens=usage.get("completion_tokens"), raw=data)
        log_call(task=task, model=model, latency_s=latency,
                 prompt_tokens=resp.prompt_tokens, completion_tokens=resp.completion_tokens)
        return resp

    def _post_with_retries(self, url, headers, payload, timeout) -> dict:
        last_err = None
        for attempt in range(self.max_retries):
            try:
                r = requests.post(url, headers=headers, json=payload, timeout=timeout)
                if r.status_code == 429 or r.status_code >= 500:
                    wait = 2 ** attempt * 3  # 3, 6, 12, 24 s
                    print(f"  (límite/servidor {r.status_code}; reintento en {wait}s...)")
                    time.sleep(wait)
                    last_err = requests.HTTPError(f"HTTP {r.status_code}")
                    continue
                if r.status_code in (400, 404):
                    # petición inválida o modelo inexistente: no tiene sentido reintentar
                    msg = self._extract_error(r)
                    raise ValueError(f"modelo no disponible o petición inválida ({r.status_code}): {msg}")
                r.raise_for_status()
                return r.json()
            except (requests.Timeout, requests.ConnectionError) as e:
                wait = 2 ** attempt * 3
                print(f"  (red inestable; reintento en {wait}s...)")
                time.sleep(wait)
                last_err = e
        raise RuntimeError(f"No se pudo completar la petición tras {self.max_retries} intentos: {last_err}")

    @staticmethod
    def _extract_error(r) -> str:
        try:
            data = r.json()
            return data.get("error", {}).get("message") or str(data)[:200]
        except Exception:  # noqa: BLE001
            return (r.text or "")[:200]

    def list_models(self, timeout: int = 30) -> list[dict]:
        """Devuelve los modelos disponibles en OpenRouter (id y nombre)."""
        url = f"{self.base_url}/models"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        r = requests.get(url, headers=headers, timeout=timeout)
        r.raise_for_status()
        data = r.json().get("data", [])
        return [{"id": m.get("id"), "name": m.get("name", m.get("id"))} for m in data if m.get("id")]
