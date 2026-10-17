from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
import csv
import io
import json
import sqlite3
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "firewall.db"
STATIC_DIR = BASE_DIR / "static"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                dst_port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                action TEXT NOT NULL CHECK(action IN ('ALLOW', 'BLOCK')),
                bytes INTEGER NOT NULL DEFAULT 0,
                interface TEXT NOT NULL DEFAULT 'Ethernet',
                note TEXT NOT NULL DEFAULT ''
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                description TEXT NOT NULL,
                event_count INTEGER NOT NULL DEFAULT 1
            )
        """)
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        if count == 0:
            seed_sample_data(conn)


def seed_sample_data(conn):
    now = datetime.now(timezone.utc)
    sample = [
        ("192.168.1.12", "10.0.0.10", 51432, 443, "TCP", "ALLOW", 14820, "Ethernet", "HTTPS session"),
        ("192.168.1.15", "10.0.0.20", 52111, 53, "UDP", "ALLOW", 512, "Wi-Fi", "DNS lookup"),
        ("203.0.113.44", "192.168.1.10", 41001, 22, "TCP", "BLOCK", 0, "WAN", "SSH attempt denied"),
        ("203.0.113.44", "192.168.1.10", 41002, 23, "TCP", "BLOCK", 0, "WAN", "Telnet attempt denied"),
        ("203.0.113.44", "192.168.1.10", 41003, 3389, "TCP", "BLOCK", 0, "WAN", "RDP attempt denied"),
        ("198.51.100.72", "192.168.1.25", 45001, 445, "TCP", "BLOCK", 0, "WAN", "SMB connection denied"),
        ("192.168.1.18", "10.0.0.12", 53000, 443, "TCP", "ALLOW", 28400, "Ethernet", "HTTPS session"),
        ("192.168.1.21", "10.0.0.18", 53001, 80, "TCP", "ALLOW", 3200, "Wi-Fi", "HTTP request"),
        ("198.51.100.72", "192.168.1.25", 45002, 139, "TCP", "BLOCK", 0, "WAN", "NetBIOS attempt denied"),
        ("192.168.1.33", "10.0.0.22", 5353, 5353, "UDP", "ALLOW", 800, "Wi-Fi", "Local discovery"),
        ("203.0.113.44", "192.168.1.10", 41004, 5900, "TCP", "BLOCK", 0, "WAN", "VNC attempt denied"),
        ("192.168.1.12", "10.0.0.10", 51433, 443, "TCP", "ALLOW", 19200, "Ethernet", "HTTPS session"),
        ("198.51.100.88", "192.168.1.40", 38000, 21, "TCP", "BLOCK", 0, "WAN", "FTP attempt denied"),
        ("192.168.1.15", "10.0.0.20", 52112, 53, "UDP", "ALLOW", 620, "Wi-Fi", "DNS lookup"),
        ("203.0.113.44", "192.168.1.10", 41005, 8080, "TCP", "BLOCK", 0, "WAN", "Unusual port denied"),
    ]
    # Cluster several blocked attempts from one source in a short period for demo alerting.
    for i, row in enumerate(sample):
        age = (len(sample) - i) * 2
        ts = (now - timedelta(minutes=age)).isoformat(timespec="seconds")
        conn.execute("""
            INSERT INTO events(timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                                action, bytes, interface, note)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ts, *row))
    conn.commit()


class EventIn(BaseModel):
    timestamp: Optional[str] = None
    src_ip: str = Field(min_length=1, max_length=64)
    dst_ip: str = Field(min_length=1, max_length=64)
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: str = Field(default="TCP", pattern="^(TCP|UDP|ICMP|OTHER)$")
    action: str = Field(pattern="^(ALLOW|BLOCK)$")
    bytes: int = Field(default=0, ge=0)
    interface: str = Field(default="Ethernet", max_length=80)
    note: str = Field(default="", max_length=250)


def make_alerts():
    """Rebuild simple demo alerts from the recent event history."""
    with get_db() as conn:
        conn.execute("DELETE FROM alerts")
        rows = conn.execute("""
            SELECT src_ip, COUNT(*) AS n, MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen
            FROM events
            WHERE action = 'BLOCK'
              AND timestamp >= ?
            GROUP BY src_ip
            HAVING COUNT(*) >= 3
        """, ((datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(),)).fetchall()
        for row in rows:
            conn.execute("""
                INSERT INTO alerts(timestamp, severity, title, src_ip, description, event_count)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                row["last_seen"], "HIGH", "Repeated blocked connections",
                row["src_ip"],
                f"{row['n']} blocked connection attempts observed in the last 24 hours. Review the source and firewall policy.",
                row["n"],
            ))
        # Flag denied attempts to commonly sensitive administrative services.
        sensitive = conn.execute("""
            SELECT id, timestamp, src_ip, dst_port FROM events
            WHERE action = 'BLOCK' AND dst_port IN (22, 23, 3389, 445, 5900)
            ORDER BY timestamp DESC LIMIT 8
        """).fetchall()
        for row in sensitive:
            conn.execute("""
                INSERT INTO alerts(timestamp, severity, title, src_ip, description, event_count)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                row["timestamp"], "MEDIUM", "Blocked administrative-service access",
                row["src_ip"],
                f"A connection to destination port {row['dst_port']} was blocked. This is a rule-based signal, not proof of an attack.",
                1,
            ))
        conn.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    make_alerts()
    yield


app = FastAPI(
    title="Firewall Monitoring API",
    version="1.0.0",
    description="Local demo dashboard backed by sample firewall events."
    , lifespan=lifespan
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "mode": "sample-data", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/api/events")
def list_events(
    action: Optional[str] = Query(default=None, pattern="^(ALLOW|BLOCK)$"),
    protocol: Optional[str] = Query(default=None, pattern="^(TCP|UDP|ICMP|OTHER)$"),
    search: Optional[str] = Query(default=None, max_length=100),
    limit: int = Query(default=100, ge=1, le=500),
):
    sql = "SELECT * FROM events WHERE 1=1"
    params = []
    if action:
        sql += " AND action = ?"
        params.append(action)
    if protocol:
        sql += " AND protocol = ?"
        params.append(protocol)
    if search:
        term = f"%{search}%"
        sql += " AND (src_ip LIKE ? OR dst_ip LIKE ? OR note LIKE ? OR interface LIKE ?)"
        params.extend([term, term, term, term])
    sql += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    with get_db() as conn:
        rows = conn.execute(sql, params).fetchall()
    return {"items": [dict(row) for row in rows], "count": len(rows)}


@app.get("/api/stats")
def stats():
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        blocked = conn.execute("SELECT COUNT(*) FROM events WHERE action='BLOCK'").fetchone()[0]
        allowed = conn.execute("SELECT COUNT(*) FROM events WHERE action='ALLOW'").fetchone()[0]
        bytes_total = conn.execute("SELECT COALESCE(SUM(bytes), 0) FROM events").fetchone()[0]
        unique_sources = conn.execute("SELECT COUNT(DISTINCT src_ip) FROM events").fetchone()[0]
        protocol_rows = conn.execute("SELECT protocol, COUNT(*) AS n FROM events GROUP BY protocol").fetchall()
        action_rows = conn.execute("SELECT action, COUNT(*) AS n FROM events GROUP BY action").fetchall()
        recent_rows = conn.execute("""
            SELECT substr(timestamp, 1, 16) AS bucket, COUNT(*) AS n
            FROM events GROUP BY bucket ORDER BY bucket DESC LIMIT 12
        """).fetchall()
    return {
        "total_events": total,
        "blocked": blocked,
        "allowed": allowed,
        "bytes_total": bytes_total,
        "unique_sources": unique_sources,
        "block_rate": round((blocked / total) * 100, 1) if total else 0,
        "protocols": {r["protocol"]: r["n"] for r in protocol_rows},
        "actions": {r["action"]: r["n"] for r in action_rows},
        "timeline": [{"time": r["bucket"], "count": r["n"]} for r in reversed(recent_rows)],
    }


@app.get("/api/alerts")
def list_alerts(limit: int = Query(default=100, ge=1, le=300)):
    make_alerts()
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    return {"items": [dict(row) for row in rows], "count": len(rows)}


@app.post("/api/events", status_code=201)
def add_event(event: EventIn):
    timestamp = event.timestamp or datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=422, detail="timestamp must be an ISO-8601 datetime")
    data = event.model_dump()
    data["timestamp"] = timestamp
    with get_db() as conn:
        cur = conn.execute("""
            INSERT INTO events(timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                                action, bytes, interface, note)
            VALUES (:timestamp, :src_ip, :dst_ip, :src_port, :dst_port, :protocol,
                    :action, :bytes, :interface, :note)
        """, data)
        event_id = cur.lastrowid
        conn.commit()
    make_alerts()
    return {"id": event_id, "message": "Event recorded", "event": data}


@app.get("/api/export.csv")
def export_csv():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM events ORDER BY timestamp DESC").fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
                     "protocol", "action", "bytes", "interface", "note"])
    for row in rows:
        writer.writerow([row[k] for k in row.keys()])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="firewall-events.csv"'}
    )


@app.post("/api/demo/reset")
def reset_demo():
    """Restore the built-in sample dataset. Intended only for this local demo."""
    with get_db() as conn:
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM alerts")
        seed_sample_data(conn)
    make_alerts()
    return {"message": "Sample dataset restored"}
