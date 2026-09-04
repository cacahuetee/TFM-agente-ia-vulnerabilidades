"""Selecciona el cliente adecuado según el identificador de modelo.

Los modelos locales usan el prefijo 'ollama:'; el resto van por OpenRouter.
La clave de OpenRouter puede pasarse explícitamente (web: clave de la sesión
del usuario) o, si no, se toma del entorno (CLI / Docker).
"""
from __future__ import annotations


def make_client(model_id: str, api_key: str | None = None):
    if model_id.startswith("ollama:"):
        from src.llm.ollama_client import OllamaClient
        return OllamaClient()
    from src.llm.openrouter_client import OpenRouterClient
    return OpenRouterClient(api_key=api_key)
