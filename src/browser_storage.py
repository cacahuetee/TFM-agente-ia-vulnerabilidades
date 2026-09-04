"""
Persistencia en el navegador (para que un F5 no borre la sesión).

Streamlit pierde su estado al recargar la página. Para no volver a pedir el
usuario y la clave tras cada recarga, se guardan en el almacenamiento del
propio navegador del usuario, con dos niveles de seguridad:

  - Nombre de usuario      -> localStorage (persiste entre visitas)
  - Clave de OpenRouter    -> localStorage, asociada a cada usuario, para no
                              volver a pedirla. El usuario puede borrarla en
                              cualquier momento con el botón «Borrar mi clave».

La herramienta sigue sin escribir la clave en ningún fichero del servidor.
El JavaScript se ejecuta con el componente `streamlit_js_eval`; si no está
disponible, la web funciona igual pero sin recordar nada.
"""
from __future__ import annotations

import json
import os

import streamlit as st

try:
    from streamlit_js_eval import streamlit_js_eval
except ImportError:  # pragma: no cover
    streamlit_js_eval = None

# Permite desactivar la persistencia (p. ej. en pruebas) con una variable de entorno.
DISABLED = os.environ.get("TFM_NO_BROWSER_STORAGE") == "1"

# El componente corre en un iframe del mismo origen: usamos el almacenamiento
# de la ventana principal para que sea el mismo en toda la aplicación.
_P = "(window.parent || window)"
K_USER, K_KEYS, K_NOKEY = "tfm_user", "tfm_keys", "tfm_nokey"
# tfm_keys guarda un objeto JSON {usuario_slug: clave}


def available() -> bool:
    return streamlit_js_eval is not None and not DISABLED


def read_saved() -> dict | None:
    """Lee lo guardado en el navegador. Devuelve None mientras el componente
    aún no ha respondido (primera pasada), o un dict con las claves
    user / key / nokey (valores posiblemente None)."""
    empty = {"user": None, "keys": {}, "nokey": None}
    if not available():
        return empty
    js = (f"JSON.stringify({{user: {_P}.localStorage.getItem('{K_USER}'), "
          f"keys: JSON.parse({_P}.localStorage.getItem('{K_KEYS}') || '{{}}'), "
          f"nokey: {_P}.sessionStorage.getItem('{K_NOKEY}')}})")
    raw = streamlit_js_eval(js_expressions=js, key="tfm_restore")
    if raw is None:
        return None
    try:
        data = json.loads(raw)
        if not isinstance(data.get("keys"), dict):
            data["keys"] = {}
        return data
    except (TypeError, ValueError, AttributeError):
        return empty


def _queue(js: str) -> None:
    st.session_state.setdefault("_js_queue", []).append(js)


def flush() -> None:
    """Ejecuta el JavaScript pendiente. Llamar una vez por pasada, al principio."""
    if not available():
        st.session_state.pop("_js_queue", None)
        return
    for js in st.session_state.pop("_js_queue", []):
        n = st.session_state.get("_js_counter", 0) + 1
        st.session_state["_js_counter"] = n
        streamlit_js_eval(js_expressions=js, key=f"tfm_js_{n}", want_output=False)


def save_user(name: str) -> None:
    _queue(f"{_P}.localStorage.setItem('{K_USER}', {json.dumps(name)})")


def _keys_update_js(user_slug: str, key: str | None) -> str:
    """JS que añade (o quita, si key es None) la clave de un usuario en tfm_keys."""
    return (f"(function(){{var m=JSON.parse({_P}.localStorage.getItem('{K_KEYS}')||'{{}}');"
            + (f"m[{json.dumps(user_slug)}]={json.dumps(key)};" if key else f"delete m[{json.dumps(user_slug)}];")
            + f"{_P}.localStorage.setItem('{K_KEYS}',JSON.stringify(m));}})()")


def save_key(user_slug: str, key: str) -> None:
    _queue(_keys_update_js(user_slug, key) + f"; {_P}.sessionStorage.removeItem('{K_NOKEY}')")


def save_nokey() -> None:
    """El usuario entra sin clave: se recuerda solo durante la pestaña."""
    _queue(f"{_P}.sessionStorage.setItem('{K_NOKEY}', '1')")


def clear_key(user_slug: str) -> None:
    """Borra la clave guardada de ese usuario (botón «Borrar mi clave»)."""
    _queue(_keys_update_js(user_slug, None) + f"; {_P}.sessionStorage.removeItem('{K_NOKEY}')")


def clear_user() -> None:
    """Olvida quién estaba conectado (las claves de cada usuario se conservan)."""
    _queue(f"{_P}.localStorage.removeItem('{K_USER}'); {_P}.sessionStorage.removeItem('{K_NOKEY}')")
