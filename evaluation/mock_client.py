"""
Cliente simulado (mock) para validar el runner de evaluación sin red ni API.

Genera una respuesta plausible a partir del propio contenido del prompt, de
modo que la cobertura resulte alta, e introduce de forma controlada un CVE
inventado para comprobar que la métrica de CVEs no fundamentados lo detecta.
Su único fin es probar la maquinaria de evaluación de forma reproducible.
"""
from __future__ import annotations

import random
import re
import time

from src.llm.openrouter_client import LLMResponse


class MockClient:
    def __init__(self, seed: int = 7):
        self.rng = random.Random(seed)

    def chat(self, model: str, system: str, user: str, **kwargs) -> LLMResponse:
        # Extrae del prompt los puertos/servicios para "mencionarlos"
        summary = user.split("--- DATOS DEL ESCANEO ---")[-1]
        mentioned = summary  # el mock repite el resumen: cobertura alta

        # Inserta un CVE inventado en algunos modelos para probar la métrica
        extra = ""
        if "llama" in model or "mistral" in model:
            extra = " Posible vulnerabilidad asociada: CVE-2099-0001."

        text = ("Resumen del análisis (simulado).\n" + mentioned +
                "\nServicios a revisar por versiones antiguas o exposición." + extra)

        # Latencia y tokens simulados
        time.sleep(0.01)
        ptok = len(user.split())
        ctok = len(text.split())
        return LLMResponse(
            text=text, model=model, latency_s=self.rng.uniform(0.5, 2.5),
            prompt_tokens=ptok, completion_tokens=ctok, raw={"mock": True},
        )
