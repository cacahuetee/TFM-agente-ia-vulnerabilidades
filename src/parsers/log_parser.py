"""Parser básico de registros de actividad (logs).

Admite líneas de tipo syslog y líneas JSON. Normaliza a una lista de entradas
con marca temporal (si se detecta) y mensaje, para su posterior análisis.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

SYSLOG_RE = re.compile(r"^(?P<ts>\w{3}\s+\d+\s[\d:]+)\s+(?P<host>\S+)\s+(?P<msg>.*)$")


@dataclass
class LogEntry:
    raw: str
    timestamp: str | None = None
    host: str | None = None
    message: str = ""


@dataclass
class LogSet:
    source: str = "logs"
    entries: list[LogEntry] = field(default_factory=list)

    def summary(self, limit: int = 60) -> str:
        lines = [f"{e.timestamp or ''} {e.host or ''} {e.message}".strip()
                 for e in self.entries[:limit]]
        extra = f"\n... (+{len(self.entries) - limit} líneas más)" if len(self.entries) > limit else ""
        return "\n".join(lines) + extra


def parse_logs(path: str) -> LogSet:
    ls = LogSet()
    for raw in open(path, encoding="utf-8", errors="replace"):
        raw = raw.rstrip("\n")
        if not raw.strip():
            continue
        # JSON estructurado
        if raw.lstrip().startswith("{"):
            try:
                obj = json.loads(raw)
                ls.entries.append(LogEntry(
                    raw=raw,
                    timestamp=str(obj.get("timestamp") or obj.get("time") or ""),
                    host=str(obj.get("host") or obj.get("source") or ""),
                    message=str(obj.get("message") or obj.get("msg") or raw),
                ))
                continue
            except json.JSONDecodeError:
                pass
        # syslog
        m = SYSLOG_RE.match(raw)
        if m:
            ls.entries.append(LogEntry(raw=raw, timestamp=m.group("ts"),
                                       host=m.group("host"), message=m.group("msg")))
        else:
            ls.entries.append(LogEntry(raw=raw, message=raw))
    return ls
