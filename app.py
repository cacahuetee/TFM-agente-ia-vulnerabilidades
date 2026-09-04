"""
Interfaz web (Streamlit) sobre el núcleo del proyecto.

Flujo al abrir la herramienta:
  1. Pantalla de usuario: elegir quién eres (o darte de alta la primera vez).
     El nombre firma los informes que se descargan.
  2. Pantalla de clave: cada usuario introduce su clave de OpenRouter. Se
     valida contra la API y se guarda SOLO en memoria durante la sesión.
  3. Herramienta, en cuatro pestañas: análisis de escaneo, análisis de logs,
     evaluación y comparativa de modelos, e historial del usuario.

Comparte el mismo núcleo que la CLI (main.py): no duplica lógica.

Ejecución:
    streamlit run app.py
"""
from __future__ import annotations

import csv
import tempfile
from datetime import datetime
from pathlib import Path

import streamlit as st

from src.parsers.dispatch import parse_scan
from src.parsers.log_parser import parse_logs
from src.knowledge.cve import CVELookup
from src.knowledge.attack_owasp import attack_owasp_context
from src.tasks.prioritize import prioritized_findings
from src.llm.router import ModelRouter
from src.llm.factory import make_client
from src import users as users_db
from src import history
from src import browser_storage as bstore
from src.config import ROOT

# ----------------------------------------------------------------------------
# Constantes de presentación
# ----------------------------------------------------------------------------
NAVY, NAVY_2, GOLD, LIGHT = "#1B2A4A", "#2E4372", "#C9A227", "#DEE6F1"
SEV_COLOR = {"CRITICAL": "#b91c1c", "HIGH": "#ea580c", "MEDIUM": "#d97706", "LOW": "#65a30d"}
SEV_LABEL = {"CRITICAL": "Crítica", "HIGH": "Alta", "MEDIUM": "Media", "LOW": "Baja"}
SEV_RANGE = {"CRITICAL": "9.0 – 10.0", "HIGH": "7.0 – 8.9", "MEDIUM": "4.0 – 6.9", "LOW": "0.1 – 3.9"}
NEW_USER_OPTION = "➕ Añadir un usuario nuevo"
LOGO_PATH = ROOT / "assets" / "logo.png"
SAMPLES = ROOT / "data" / "samples"
EXAMPLE_SCAN = SAMPLES / "sample_nmap_completo.xml"
EXAMPLE_LOGS = SAMPLES / "sample_logs.txt"
# Tokens típicos por caso de evaluación (medias observadas en la evaluación real)
EST_PROMPT_TOKENS, EST_COMPLETION_TOKENS = 1300, 1200

_user_for_title = st.session_state.get("user")
st.set_page_config(
    page_title=(f"{_user_for_title} · Agente TFM" if _user_for_title else "Agente de auditoría (TFM)"),
    page_icon="🛡️", layout="wide", initial_sidebar_state="expanded",
)

CSS = f"""
<style>
  /* Cabecera */
  .tfm-header {{ display:flex; align-items:center; gap:18px; padding:10px 0 14px 0;
                 border-bottom: 3px solid {NAVY}; margin-bottom: 18px; }}
  .tfm-header .title {{ font-size:1.55rem; font-weight:700; color:{NAVY}; line-height:1.15; }}
  .tfm-header .sub   {{ font-size:0.9rem; color:#5A6B8C; margin-top:2px; }}
  .tfm-header .rule  {{ width:6px; height:44px; background:{GOLD}; border-radius:3px; }}
  /* Tarjeta de las pantallas de entrada */
  .tfm-card {{ background:#F3F6FA; border:1px solid {LIGHT}; border-top:5px solid {GOLD};
               border-radius:10px; padding:26px 30px 8px 30px; margin-top:8px; }}
  .tfm-card h3 {{ color:{NAVY}; margin:0 0 6px 0; }}
  /* Métricas */
  [data-testid="stMetric"] {{ background:#F3F6FA; border:1px solid {LIGHT}; border-left:5px solid {NAVY};
                              border-radius:8px; padding:10px 14px; }}
  [data-testid="stMetricLabel"] p {{ color:#5A6B8C; font-size:0.85rem; }}
  [data-testid="stMetricValue"] {{ color:{NAVY}; }}
  /* Pasos del estado vacío */
  .tfm-steps {{ display:grid; grid-template-columns:repeat(3,1fr); gap:14px; margin:14px 0 6px 0; }}
  .tfm-step {{ background:#F3F6FA; border:1px solid {LIGHT}; border-radius:8px; padding:14px 16px; }}
  .tfm-step b {{ color:{NAVY}; display:block; margin-bottom:4px; }}
  .tfm-step span {{ color:#4B5563; font-size:0.92rem; }}
  /* Leyenda de severidad */
  .sev {{ display:inline-block; padding:1px 8px; border-radius:10px; color:#fff; font-size:0.82em; margin-right:6px; }}
  /* Pestañas */
  button[data-baseweb="tab"] p {{ font-size:1rem; }}
  /* Barra lateral */
  section[data-testid="stSidebar"] {{ border-right: 1px solid {LIGHT}; }}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


# ----------------------------------------------------------------------------
# Utilidades de presentación
# ----------------------------------------------------------------------------
def header(compact: bool = False) -> None:
    cols = st.columns([1, 12]) if LOGO_PATH.exists() else None
    if cols:
        cols[0].image(str(LOGO_PATH), width=72)
        target = cols[1]
    else:
        target = st
    target.markdown(
        "<div class='tfm-header'><div class='rule'></div><div>"
        "<div class='title'>Agente de apoyo al análisis de vulnerabilidades</div>"
        "<div class='sub'>Trabajo Fin de Máster · Elsa Ferreras Patón · "
        "Escuela Internacional de Posgrados</div></div></div>",
        unsafe_allow_html=True)


def cve_badges(vulns) -> str:
    if not vulns:
        return "—"
    out = []
    for v in vulns:
        sev = (v.severity or "N/D").upper()
        color = SEV_COLOR.get(sev, "#6b7280")
        score = f"{v.cvss:.1f}" if v.cvss is not None else "N/D"
        out.append(f"<span class='sev' style='background:{color}'>{v.id} · {score}</span>")
    return " ".join(out)


def severity_legend() -> None:
    with st.expander("¿Qué significan los colores? (escala CVSS)"):
        items = "".join(
            f"<div style='margin:4px 0'><span class='sev' style='background:{SEV_COLOR[k]}'>"
            f"{SEV_LABEL[k]}</span> CVSS {SEV_RANGE[k]}</div>" for k in SEV_COLOR)
        st.markdown(items + "<div style='color:#6B7280;font-size:0.9em;margin-top:6px'>"
                    "CVSS es la puntuación estándar (0 a 10) de gravedad de una vulnerabilidad. "
                    "Cuanto más alta, más urgente es revisarla.</div>", unsafe_allow_html=True)


def model_label(router: ModelRouter, alias: str) -> str:
    """Etiqueta legible para el selector: alias, coste y nota del YAML."""
    info = router.models.get(alias)
    if not info:
        return alias
    if info.get("id", "").startswith("ollama:"):
        tier = "local, sin coste"
    elif info.get("price_in") is None:
        tier = "gratis"
    else:
        p = float(info.get("price_out") or 0)
        tier = "coste bajo" if p < 1 else ("coste medio" if p < 4 else "coste alto")
    note = info.get("notes", "")
    note = (note[:48] + "…") if len(note) > 50 else note
    return f"{alias} · {tier}" + (f" · {note}" if note else "")


def estimate_cost(router: ModelRouter, aliases: list[str], n_cases: int) -> tuple[float, list[str]]:
    """Coste estimado de una evaluación real y lista de modelos sin coste."""
    total, free = 0.0, []
    for a in aliases:
        m = router.models.get(a, {})
        pin, pout = m.get("price_in"), m.get("price_out")
        if pin is None or pout is None:
            free.append(a)
            continue
        total += n_cases * (EST_PROMPT_TOKENS / 1e6 * pin + EST_COMPLETION_TOKENS / 1e6 * pout)
    return total, free


def _save_upload(uploaded, suffix: str) -> str:
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(uploaded.read())
        return tmp.name


# ----------------------------------------------------------------------------
# Pantalla 1: ¿quién eres?
# ----------------------------------------------------------------------------
def screen_user() -> None:
    header()
    _, mid, _ = st.columns([1, 1.4, 1])
    with mid:
        st.markdown("<div class='tfm-card'><h3>¿Quién va a usar la herramienta?</h3>"
                    "<p style='color:#4B5563'>Tu nombre aparecerá como autor en los informes "
                    "que descargues y organizará tu historial.</p></div>", unsafe_allow_html=True)
        known = users_db.load_users()
        if not known:
            st.info("Todavía no hay ningún usuario en este equipo. Añade el tuyo para empezar.")
            name = st.text_input("Tu nombre", placeholder="Ej.: Gino Alberto Veronesse",
                                 max_chars=users_db.MAX_NAME_LEN)
            if st.button("Empezar", type="primary"):
                _set_user(name)
            return
        choice = st.selectbox("Elige tu usuario", options=known + [NEW_USER_OPTION])
        if choice == NEW_USER_OPTION:
            name = st.text_input("Tu nombre", max_chars=users_db.MAX_NAME_LEN)
            if st.button("Añadir y empezar", type="primary"):
                _set_user(name)
        elif st.button("Continuar", type="primary"):
            st.session_state["user"] = choice
            bstore.save_user(choice)
            _apply_saved_key(choice)
            st.rerun()


def _set_user(name: str) -> None:
    try:
        st.session_state["user"] = users_db.add_user(name)
        bstore.save_user(st.session_state["user"])
        _apply_saved_key(st.session_state["user"])
        st.rerun()
    except ValueError as exc:
        st.warning(str(exc))


def _apply_saved_key(user: str) -> None:
    """Si este usuario ya tiene clave guardada en el navegador, se salta la pantalla de clave."""
    saved = st.session_state.get("_saved_keys") or {}
    key = saved.get(users_db.slug(user))
    if key:
        st.session_state["api_key"] = key
        st.session_state["key_step_done"] = True


# ----------------------------------------------------------------------------
# Pantalla 2: clave de OpenRouter (solo en memoria)
# ----------------------------------------------------------------------------
def screen_api_key() -> None:
    header()
    _, mid, _ = st.columns([1, 1.4, 1])
    with mid:
        st.markdown(
            f"<div class='tfm-card'><h3>Hola, {st.session_state['user']}</h3>"
            "<p style='color:#4B5563'>Introduce tu clave de OpenRouter. Hace falta para que la IA "
            "redacte la interpretación. Consíguela gratis en "
            "<a href='https://openrouter.ai/keys' target='_blank'>openrouter.ai/keys</a> "
            "(<i>API Keys → Create API Key</i>); empieza por <code>sk-or-</code>.</p>"
            "<p style='color:#1B2A4A'><b>Solo tendrás que introducirla una vez.</b> Se guarda en el "
            "navegador de este equipo, asociada a tu usuario, y nunca en un archivo de la "
            "herramienta. Podrás borrarla cuando quieras con el botón «Borrar mi clave».</p></div>",
            unsafe_allow_html=True)
        key = st.text_input("Clave de OpenRouter", type="password", placeholder="sk-or-v1-...")
        c1, c2 = st.columns(2)
        if c1.button("Validar y entrar", type="primary"):
            _validate_and_enter(key)
        if c2.button("Continuar sin clave"):
            st.session_state["api_key"] = ""
            st.session_state["key_step_done"] = True
            bstore.save_nokey()
            st.rerun()
        st.caption("Sin clave podrás ver servicios, vulnerabilidades (CVE) y priorización, pero no "
                   "la interpretación redactada por la IA (salvo con un modelo local Ollama).")


def _validate_and_enter(key: str) -> None:
    key = (key or "").strip()
    if not key:
        st.warning("Pega tu clave o pulsa «Continuar sin clave».")
        return
    from src.llm.openrouter_client import OpenRouterClient
    import requests
    try:
        with st.spinner("Comprobando la clave con OpenRouter..."):
            live = OpenRouterClient(api_key=key).list_models()
        st.session_state["live_models"] = [m["id"] for m in live]
    except requests.HTTPError as exc:
        status = getattr(exc.response, "status_code", None)
        if status in (401, 403):
            st.error("La clave no es válida. Revísala en openrouter.ai/keys y vuelve a pegarla.")
            return
        st.warning(f"OpenRouter respondió con un error ({status}). Se usará la clave igualmente.")
    except Exception as exc:  # noqa: BLE001  (sin red, timeout, etc.)
        st.warning(f"No se pudo comprobar la clave ({exc}). Se usará igualmente.")
    st.session_state["api_key"] = key
    st.session_state["key_step_done"] = True
    bstore.save_key(users_db.slug(st.session_state['user']), key)
    st.rerun()


# ----------------------------------------------------------------------------
# Barra lateral
# ----------------------------------------------------------------------------
def sidebar(router: ModelRouter) -> dict:
    api_key = st.session_state.get("api_key", "")
    with st.sidebar:
        if LOGO_PATH.exists():
            st.image(str(LOGO_PATH), width=120)
        st.markdown(f"### 👤 {st.session_state['user']}")
        st.markdown("🔑 **Clave OpenRouter:** " + ("lista ✅" if api_key else "no introducida ⚠️"))
        if api_key:
            st.caption("Guardada en este navegador para tu usuario. No se volverá a pedir.")
        c1, c2 = st.columns(2)
        if c1.button("Borrar mi clave" if api_key else "Introducir clave",
                     help="Elimina la clave guardada en este navegador y vuelve a pedirla."):
            for k in ("api_key", "key_step_done"):
                st.session_state.pop(k, None)
            slug_ = users_db.slug(st.session_state["user"])
            bstore.clear_key(slug_)
            st.session_state.setdefault("_saved_keys", {}).pop(slug_, None)
            st.rerun()
        if c2.button("Cambiar usuario"):
            for k in ("user", "api_key", "key_step_done", "interpretation", "log_analysis"):
                st.session_state.pop(k, None)
            bstore.clear_user()
            st.rerun()

        st.divider()
        st.markdown("### ⚙️ Modelo de IA")
        aliases = router.aliases()
        options = aliases + [m for m in st.session_state.get("live_models", []) if m not in aliases]
        default_alias = router.routing.get("interpret_scan", router.default)
        idx = options.index(default_alias) if default_alias in options else 0
        chosen_alias = st.selectbox(
            "Modelo que redactará la interpretación", options=options, index=idx,
            format_func=lambda a: model_label(router, a) if a in aliases else a,
            help="Los alias vienen de config/models.yaml. Si uno da error, pulsa «Cargar modelos» "
                 "y elige un identificador de la lista completa de OpenRouter.")
        chosen_model = router.id_of(chosen_alias) if chosen_alias in aliases else chosen_alias
        st.caption(f"Identificador: `{chosen_model}`")
        best = router.select_by_metrics("cobertura")
        if best:
            st.caption(f"📈 Mejor cobertura en la última evaluación: **{best}**. "
                       "En el TFM, **deepseek** dio el mejor equilibrio coste/calidad.")

        if st.button("Cargar modelos de OpenRouter",
                     help="Trae la lista de modelos válidos (evita errores de identificador)"):
            if not api_key:
                st.warning("Necesitas una clave para consultar la lista.")
            else:
                try:
                    from src.llm.openrouter_client import OpenRouterClient
                    live = OpenRouterClient(api_key=api_key).list_models()
                    st.session_state["live_models"] = [m["id"] for m in live]
                    st.caption(f"{len(live)} modelos cargados de OpenRouter.")
                except Exception as exc:  # noqa: BLE001
                    st.warning(f"No se pudo cargar la lista: {exc}")

        st.divider()
        st.markdown("### 🧩 Datos de vulnerabilidades")
        enrich = st.checkbox("Enriquecer con CVEs (NVD)", value=True)
        offline = st.checkbox("Solo caché (sin consultar la NVD)", value=True,
                              help="Con la caché los resultados son instantáneos y reproducibles. "
                                   "Desmárcalo para consultar la NVD en vivo (más lento).")
    return {"api_key": api_key, "model": chosen_model, "alias": chosen_alias,
            "enrich": enrich, "offline": offline}


def can_interpret(opts: dict) -> bool:
    return bool(opts["api_key"]) or opts["model"].startswith("ollama:")


def no_key_warning() -> None:
    st.warning("Sin clave de OpenRouter no se puede pedir la interpretación. Pulsa «Introducir clave» "
               "en la barra lateral, o elige un modelo local (ollama).")


# ----------------------------------------------------------------------------
# Pestaña 1: análisis de escaneo
# ----------------------------------------------------------------------------
def tab_scan(opts: dict) -> None:
    uploaded = st.file_uploader("Sube un escaneo de Nmap (XML) o Nessus (.nessus)",
                                type=["xml", "nessus"], key="scan_upload")

    if uploaded is not None:
        name = uploaded.name
        path = _save_upload(uploaded, ".nessus" if name.endswith(".nessus") else ".xml")
        st.session_state.pop("scan_example", None)
    elif st.session_state.get("scan_example"):
        name, path = EXAMPLE_SCAN.name, str(EXAMPLE_SCAN)
        st.caption(f"Analizando el ejemplo incluido: `{name}`.")
    else:
        _empty_state_scan()
        return

    if st.session_state.get("last_file") != name:
        st.session_state["last_file"] = name
        st.session_state.pop("interpretation", None)

    scan = parse_scan(path)
    if opts["enrich"]:
        with st.spinner("Consultando vulnerabilidades..."):
            scan = CVELookup(use_network=not opts["offline"]).enrich_scan(scan)

    # --- Tarjetas resumen ---
    services = [s for h in scan.hosts for s in h.services]
    vulns = [v for s in services for v in s.vulnerabilities]
    highest = max(vulns, key=lambda v: v.cvss or 0, default=None)
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Hosts analizados", len(scan.hosts))
    m2.metric("Servicios expuestos", len(services))
    m3.metric("Vulnerabilidades conocidas", len(vulns))
    if highest and highest.severity:
        m4.metric("Severidad máxima", f"{SEV_LABEL.get(highest.severity.upper(), highest.severity)}",
                  f"CVSS {highest.cvss:.1f}" if highest.cvss is not None else None, delta_color="inverse")
    else:
        m4.metric("Severidad máxima", "Ninguna")
    st.caption(f"Origen: **{scan.source_tool}**" + (f" · comando: `{scan.command}`" if scan.command else ""))

    # --- Detalle por host ---
    st.subheader("Servicios detectados")
    for host in scan.hosts:
        label = host.address + (f" ({host.hostname})" if host.hostname else "")
        st.markdown(f"**Host {label}** — estado: {host.state}")
        html = ["<table style='width:100%;border-collapse:collapse'>",
                f"<tr style='background:{LIGHT}'>"
                "<th style='text-align:left;padding:5px 8px'>Puerto</th>"
                "<th style='text-align:left;padding:5px 8px'>Servicio</th>"
                "<th style='text-align:left;padding:5px 8px'>Producto/versión</th>"
                "<th style='text-align:left;padding:5px 8px'>Vulnerabilidades (CVSS)</th></tr>"]
        for s in host.services:
            prod = " ".join(x for x in (s.product, s.version) if x)
            html.append(
                f"<tr style='border-bottom:1px solid #e5e7eb'>"
                f"<td style='padding:5px 8px'>{s.port}/{s.protocol}</td>"
                f"<td style='padding:5px 8px'>{s.service or ''}</td>"
                f"<td style='padding:5px 8px'>{prod}</td>"
                f"<td style='padding:5px 8px'>{cve_badges(s.vulnerabilities)}</td></tr>")
        html.append("</table>")
        st.markdown("\n".join(html), unsafe_allow_html=True)

    findings = prioritized_findings(scan)
    if findings:
        st.markdown("**Vulnerabilidades ordenadas por riesgo**")
        st.markdown(" ".join(
            f"<div style='margin:3px 0'>{i}. {cve_badges([f.cve])} "
            f"<span style='color:#555'>→ {f.host} {f.port}/{f.service}</span></div>"
            for i, f in enumerate(findings, 1)), unsafe_allow_html=True)
    severity_legend()

    ctx = attack_owasp_context(scan)
    if ctx:
        with st.expander("Contexto MITRE ATT&CK / OWASP"):
            st.text(ctx)

    # --- Interpretación ---
    st.subheader("Interpretación asistida por IA")
    model = opts["model"]
    if not can_interpret(opts):
        no_key_warning()
    elif st.button("🤖 Interpretar con el modelo", type="primary"):
        from src.tasks.interpret_scan import _load_prompt, TASK
        system, user_template = _load_prompt()
        summary = scan.summary() + ("\n\n" + ctx if ctx else "")
        user_msg = user_template.format(scan_summary=summary)
        try:
            with st.spinner(f"Consultando a {model}..."):
                resp = make_client(model, api_key=opts["api_key"]).chat(
                    model=model, system=system, user=user_msg, task=TASK)
            st.session_state["interpretation"] = resp.text
            st.session_state["interpretation_meta"] = (
                f"Modelo: {resp.model} · Latencia: {resp.latency_s:.2f}s · "
                f"Tokens: {resp.prompt_tokens}+{resp.completion_tokens}")
            # Guardar en el historial del usuario (con el informe completo)
            from src.reporting.report import build_context, render_html
            ctx_rep = build_context(scan, interpretation=resp.text,
                                    meta={"author": st.session_state["user"]})
            history.save_entry(st.session_state["user"], "escaneo", name, resp.model, resp.text,
                               report_html=render_html(ctx_rep),
                               extra={"latencia_s": round(resp.latency_s, 2),
                                      "hosts": len(scan.hosts), "vulnerabilidades": len(vulns)})
        except Exception as exc:  # noqa: BLE001
            st.error(f"No se pudo obtener la interpretación: {exc}")

    if st.session_state.get("interpretation"):
        st.caption(st.session_state.get("interpretation_meta", ""))
        st.markdown(st.session_state["interpretation"])

    # --- Informe ---
    st.subheader("Informe")
    from src.reporting.report import build_context, render_html, render_markdown
    report_ctx = build_context(scan, interpretation=st.session_state.get("interpretation"),
                               meta={"author": st.session_state["user"]})
    stamp = datetime.now().strftime("%Y%m%d_%H%M")
    base = f"informe_{users_db.slug(st.session_state['user'])}_{stamp}"
    st.caption(f"Firmado por **{st.session_state['user']}** · {datetime.now().strftime('%d/%m/%Y %H:%M')}. "
               "El HTML se imprime a PDF desde el navegador (Ctrl+P).")
    c1, c2 = st.columns(2)
    c1.download_button("⬇️ Descargar informe (HTML)", data=render_html(report_ctx),
                       file_name=f"{base}.html", mime="text/html")
    c2.download_button("⬇️ Descargar informe (Markdown)", data=render_markdown(report_ctx),
                       file_name=f"{base}.md", mime="text/markdown")
    if not st.session_state.get("interpretation"):
        st.caption("Sugerencia: lanza la interpretación antes de descargar para incluirla en el informe.")


def _empty_state_scan() -> None:
    st.markdown(
        "<div class='tfm-steps'>"
        "<div class='tfm-step'><b>1. Sube un escaneo</b><span>Un XML de Nmap "
        "(<code>nmap -sV -oX salida.xml objetivo</code>) o un fichero .nessus.</span></div>"
        "<div class='tfm-step'><b>2. Revisa los hallazgos</b><span>Servicios expuestos, CVEs con su "
        "gravedad en color y la lista ordenada por riesgo, con contexto MITRE ATT&amp;CK / OWASP.</span></div>"
        "<div class='tfm-step'><b>3. Interpreta y descarga</b><span>La IA redacta el análisis y lo "
        "descargas como informe firmado con tu nombre.</span></div></div>",
        unsafe_allow_html=True)
    if st.button("▶️ Probar con el escaneo de ejemplo", type="primary"):
        st.session_state["scan_example"] = True
        st.rerun()


# ----------------------------------------------------------------------------
# Pestaña 2: análisis de logs
# ----------------------------------------------------------------------------
def tab_logs(opts: dict) -> None:
    from src.tasks.analyze_logs import SYSTEM, USER_TMPL, TASK

    uploaded = st.file_uploader("Sube un fichero de registros (syslog o JSON por líneas)",
                                type=["txt", "log", "json", "jsonl"], key="logs_upload")
    if uploaded is not None:
        name, path = uploaded.name, _save_upload(uploaded, ".log")
        st.session_state.pop("logs_example", None)
    elif st.session_state.get("logs_example"):
        name, path = EXAMPLE_LOGS.name, str(EXAMPLE_LOGS)
        st.caption(f"Analizando el ejemplo incluido: `{name}`.")
    else:
        st.markdown(
            "<div class='tfm-steps'>"
            "<div class='tfm-step'><b>1. Sube los registros</b><span>Líneas syslog "
            "(<code>/var/log/auth.log</code>, etc.) o JSON por líneas.</span></div>"
            "<div class='tfm-step'><b>2. Vista previa</b><span>Se normalizan las entradas: fecha, "
            "equipo y mensaje.</span></div>"
            "<div class='tfm-step'><b>3. Análisis por IA</b><span>Resumen, indicios de interés con su "
            "gravedad y recomendaciones, trabajando solo con las líneas aportadas.</span></div></div>",
            unsafe_allow_html=True)
        if st.button("▶️ Probar con los logs de ejemplo", type="primary"):
            st.session_state["logs_example"] = True
            st.rerun()
        return

    if st.session_state.get("last_logs") != name:
        st.session_state["last_logs"] = name
        st.session_state.pop("log_analysis", None)

    logs = parse_logs(path)
    hosts = {e.host for e in logs.entries if e.host}
    m1, m2, m3 = st.columns(3)
    m1.metric("Líneas de registro", len(logs.entries))
    m2.metric("Equipos distintos", len(hosts))
    m3.metric("Con marca temporal", sum(1 for e in logs.entries if e.timestamp))

    st.subheader("Vista previa")
    st.dataframe([{"Fecha": e.timestamp or "", "Equipo": e.host or "", "Mensaje": e.message}
                  for e in logs.entries[:200]], hide_index=True)
    if len(logs.entries) > 60:
        st.caption("Al modelo se le envían las primeras 60 líneas normalizadas.")

    st.subheader("Análisis asistido por IA")
    model = opts["model"]
    if not can_interpret(opts):
        no_key_warning()
    elif st.button("🤖 Analizar los registros con el modelo", type="primary"):
        try:
            with st.spinner(f"Consultando a {model}..."):
                resp = make_client(model, api_key=opts["api_key"]).chat(
                    model=model, system=SYSTEM, user=USER_TMPL.format(logs=logs.summary()), task=TASK)
            st.session_state["log_analysis"] = resp.text
            st.session_state["log_analysis_meta"] = (
                f"Modelo: {resp.model} · Latencia: {resp.latency_s:.2f}s · "
                f"Tokens: {resp.prompt_tokens}+{resp.completion_tokens}")
            history.save_entry(st.session_state["user"], "logs", name, resp.model, resp.text,
                               extra={"latencia_s": round(resp.latency_s, 2), "lineas": len(logs.entries)})
        except Exception as exc:  # noqa: BLE001
            st.error(f"No se pudo obtener el análisis: {exc}")

    if st.session_state.get("log_analysis"):
        st.caption(st.session_state.get("log_analysis_meta", ""))
        st.markdown(st.session_state["log_analysis"])
        stamp = datetime.now().strftime("%Y%m%d_%H%M")
        md = (f"# Análisis de registros\n\n**Autor:** {st.session_state['user']}  \n"
              f"**Fecha:** {datetime.now().strftime('%d/%m/%Y %H:%M')}  \n**Fichero:** {name}  \n"
              f"**Modelo:** {model}\n\n{st.session_state['log_analysis']}\n")
        st.download_button("⬇️ Descargar análisis (Markdown)", data=md,
                           file_name=f"logs_{users_db.slug(st.session_state['user'])}_{stamp}.md",
                           mime="text/markdown")


# ----------------------------------------------------------------------------
# Pestaña 3: evaluación y comparativa
# ----------------------------------------------------------------------------
def tab_evaluation(router: ModelRouter, opts: dict) -> None:
    st.markdown("Ejecuta la comparativa de modelos sobre los **cuatro casos de prueba** del TFM y "
                "consulta los resultados sin salir de aquí.")
    from evaluation.run_eval import load_cases, EVAL_DIR
    cases = load_cases()
    with st.expander(f"Ver los {len(cases)} casos de prueba"):
        for c in cases:
            st.markdown(f"- **{c['name']}** — {c.get('descripcion', '')}")

    eval_models = st.multiselect(
        "Modelos a comparar", options=router.aliases(),
        default=[a for a in ["free"] if a in router.aliases()] or router.aliases()[:1],
        format_func=lambda a: model_label(router, a))
    modo = st.radio("Modo", ["Simulada (sin gastar, sin clave)", "Real (usa tu clave)"], horizontal=True)
    is_mock = modo.startswith("Simulada")

    if not is_mock and eval_models:
        cost, free = estimate_cost(router, eval_models, len(cases))
        n = len(cases) * len(eval_models)
        msg = f"Vas a lanzar **{n} consultas** ({len(cases)} casos × {len(eval_models)} modelos). "
        msg += f"Coste estimado: **${cost:.4f}**" if cost > 0 else "Coste estimado: **$0**"
        if free:
            msg += f" (sin coste: {', '.join(free)})"
        msg += ". Los modelos gratuitos son más lentos y tienen un tope diario."
        st.info(msg)

    c_run, c_info = st.columns([1, 3])
    run_clicked = c_run.button("▶️ Ejecutar evaluación", type="primary")
    c_info.caption("La simulada usa un cliente ficticio para ver cómo funciona la maquinaria. "
                   "La real llama a los modelos elegidos con tu clave.")

    if run_clicked:
        if not eval_models:
            st.warning("Elige al menos un modelo.")
        elif not is_mock and not opts["api_key"]:
            st.warning("La evaluación real necesita tu clave de OpenRouter (barra lateral → «Introducir clave»).")
        else:
            from evaluation.run_eval import run as run_eval
            bar = st.progress(0.0, text="Preparando...")

            def _progress(done, total, label):
                bar.progress(done / total, text=f"Evaluando: {label}  ({done}/{total})")

            try:
                with st.spinner("Ejecutando evaluación..."):
                    result = run_eval(eval_models, offline=True, mock=is_mock,
                                      out_dir=Path(EVAL_DIR) / "resultados",
                                      progress=_progress, api_key=opts["api_key"] or None)
                bar.progress(1.0, text="Completado")
                if result["failed"]:
                    st.warning("Algunos modelos se omitieron (identificador no válido o límite): "
                               + ", ".join(f["modelo"] for f in result["failed"]))
                    with st.expander("Detalle de los modelos omitidos"):
                        for f in result["failed"]:
                            st.text(f"{f['modelo']} ({f['id']}): {f['error']}")
                if result["summary"]:
                    st.success("Evaluación terminada.")
                    st.session_state["eval_summary"] = result["summary"]
            except Exception as exc:  # noqa: BLE001
                st.error(f"La evaluación no pudo completarse: {exc}")
                st.caption("Consejo: prueba primero solo con el modelo 'free', o pulsa «Cargar modelos de "
                           "OpenRouter» en la barra lateral para elegir identificadores válidos.")

    summary_rows = st.session_state.get("eval_summary")
    if not summary_rows:
        p = Path(EVAL_DIR) / "resultados" / "resultados_resumen.csv"
        if p.exists():
            with open(p, encoding="utf-8") as f:
                summary_rows = list(csv.DictReader(f))
    if summary_rows:
        st.subheader("Resumen por modelo")
        st.dataframe(summary_rows, hide_index=True)
        c1, c2 = st.columns(2)
        try:
            c1.caption("Cobertura media (más alta es mejor)")
            c1.bar_chart({r["modelo"]: float(r["cobertura_media"]) for r in summary_rows})
            c2.caption("CVEs no fundamentados (más bajo es mejor)")
            c2.bar_chart({r["modelo"]: float(r["cves_no_fundamentados_total"]) for r in summary_rows})
        except Exception:  # noqa: BLE001
            pass
        st.caption("Los resultados completos se guardan en evaluation/resultados/ como CSV.")


# ----------------------------------------------------------------------------
# Pestaña 4: historial del usuario
# ----------------------------------------------------------------------------
def tab_history() -> None:
    user = st.session_state["user"]
    entries = history.list_entries(user)
    if not entries:
        st.info(f"Todavía no hay análisis guardados para **{user}**. Cada interpretación que pidas "
                "(de un escaneo o de unos logs) aparecerá aquí con su informe.")
        return
    st.caption(f"{len(entries)} análisis guardados para **{user}** en este equipo.")
    kinds = sorted({e["tipo"] for e in entries})
    filt = st.multiselect("Filtrar por tipo", kinds, default=kinds)
    for e in entries:
        if e["tipo"] not in filt:
            continue
        icon = "🔍" if e["tipo"] == "escaneo" else "📜"
        with st.expander(f"{icon} {e['fecha']} · {e['fichero']} · {e['modelo']}"):
            c1, c2, c3 = st.columns([2, 1, 1])
            c1.markdown(f"**Tipo:** {e['tipo']} · **Latencia:** {e.get('latencia_s', '—')} s")
            if e.get("_html_path") and Path(e["_html_path"]).exists():
                c2.download_button("⬇️ Informe HTML", data=Path(e["_html_path"]).read_text(encoding="utf-8"),
                                   file_name=Path(e["_html_path"]).name, mime="text/html",
                                   key=f"dl_{e['_json']}")
            if c3.button("🗑️ Borrar", key=f"del_{e['_json']}"):
                history.delete_entry(user, e["_json"])
                st.rerun()
            st.markdown(e["interpretacion"])


# ----------------------------------------------------------------------------
# Herramienta principal
# ----------------------------------------------------------------------------
def main_app() -> None:
    header()
    router = ModelRouter()
    opts = sidebar(router)
    t1, t2, t3, t4 = st.tabs(["🔍 Análisis de escaneo", "📜 Análisis de logs",
                              "📊 Evaluación de modelos", "🕘 Mi historial"])
    with t1:
        tab_scan(opts)
    with t2:
        tab_logs(opts)
    with t3:
        tab_evaluation(router, opts)
    with t4:
        tab_history()


# ----------------------------------------------------------------------------
# Enrutado de pantallas
# ----------------------------------------------------------------------------
def restore_from_browser() -> None:
    """Tras una recarga (F5) recupera usuario y clave guardados en el navegador."""
    if st.session_state.get("_restored"):
        return
    saved = bstore.read_saved()
    if saved is None:
        return  # el componente aún no ha respondido; se reintenta en la siguiente pasada
    st.session_state["_restored"] = True
    st.session_state["_saved_keys"] = saved.get("keys") or {}
    user = (saved.get("user") or "").strip()
    if user and not st.session_state.get("user") and user in users_db.load_users():
        st.session_state["user"] = user
        key = st.session_state["_saved_keys"].get(users_db.slug(user))
        if key:
            st.session_state["api_key"] = key
            st.session_state["key_step_done"] = True
        elif saved.get("nokey"):
            st.session_state["api_key"] = ""
            st.session_state["key_step_done"] = True


bstore.flush()
restore_from_browser()

if not st.session_state.get("user"):
    screen_user()
elif not st.session_state.get("key_step_done"):
    screen_api_key()
else:
    main_app()
