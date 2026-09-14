"""Typed access layer over the SQLite database."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from sentinelswitch.app.db import connect, dumps, loads, reset_schema, tx
from sentinelswitch.simulator.twin import SwitchTwin
from simulator.canonical import Environment


class Store:
    def __init__(self, env: Environment, db_path: Path):
        self.env = env
        self.db_path = db_path
        self.conn: sqlite3.Connection = connect(db_path)

    # ---- generic ------------------------------------------------------------------------------
    def reset(self) -> None:
        reset_schema(self.conn)

    def kv_get(self, key: str, default: Any = None) -> Any:
        row = self.conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        return loads(row["value"]) if row else default

    def kv_set(self, key: str, value: Any) -> None:
        with tx(self.conn) as c:
            c.execute("INSERT OR REPLACE INTO kv(key, value) VALUES (?, ?)", (key, dumps(value)))

    def _docs(self, table: str, where: str = "", params: tuple = (), order: str = "") -> list[dict[str, Any]]:
        sql = f"SELECT doc FROM {table}"
        if where:
            sql += " WHERE " + where
        if order:
            sql += " ORDER BY " + order
        return [loads(r["doc"]) for r in self.conn.execute(sql, params).fetchall()]

    def _doc(self, table: str, key_col: str, key: str) -> dict[str, Any] | None:
        row = self.conn.execute(f"SELECT doc FROM {table} WHERE {key_col}=?", (key,)).fetchone()
        return loads(row["doc"]) if row else None

    # ---- twin -----------------------------------------------------------------------------------
    def load_twin(self) -> SwitchTwin:
        data = self.kv_get("twin")
        if data is None:
            raise RuntimeError("database is not seeded; run `sentinelswitch seed`")
        return SwitchTwin.from_dict(self.env, data)

    def save_twin(self, twin: SwitchTwin) -> None:
        self.kv_set("twin", twin.to_dict())

    def load_baseline_twin(self) -> SwitchTwin:
        data = self.kv_get("twin_baseline")
        return SwitchTwin.from_dict(self.env, data)

    # ---- inserts --------------------------------------------------------------------------------
    def put_device(self, d: dict[str, Any]) -> None:
        with tx(self.conn) as c:
            if d.get("known", True):
                c.execute(
                    "INSERT OR REPLACE INTO devices(hostname, mac, ip, vlan, interface, role, doc) VALUES (?,?,?,?,?,?,?)",
                    (d["hostname"], d["mac"], d.get("ip"), d.get("vlan"), d.get("interface"), d.get("role"), dumps(d)),
                )
            else:
                c.execute(
                    "INSERT OR REPLACE INTO unknown_devices(mac, interface, doc) VALUES (?,?,?)",
                    (d["mac"], d.get("interface"), dumps(d)),
                )

    def put_user(self, u: dict[str, Any]) -> None:
        with tx(self.conn) as c:
            c.execute(
                "INSERT OR REPLACE INTO users(username, department, doc) VALUES (?,?,?)",
                (u["username"], u["department"], dumps(u)),
            )

    def put_alert(self, a: dict[str, Any]) -> None:
        with tx(self.conn) as c:
            c.execute(
                "INSERT OR REPLACE INTO alerts(id, ts, source, severity, status, incident_id, detection_id, device, doc) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    a["id"],
                    a["ts"],
                    a["source"],
                    a["severity"],
                    a["status"],
                    a.get("incident_id"),
                    a.get("detection_id"),
                    a.get("device"),
                    dumps(a),
                ),
            )

    def put_detection(self, d: dict[str, Any]) -> None:
        with tx(self.conn) as c:
            c.execute(
                "INSERT OR REPLACE INTO detections(id, ts, rule, severity, confidence, disposition, incident_id, doc) VALUES (?,?,?,?,?,?,?,?)",
                (
                    d["id"],
                    d["ts"],
                    d["rule"],
                    d["severity"],
                    d["confidence"],
                    d.get("disposition"),
                    d.get("incident_id"),
                    dumps(d),
                ),
            )

    def put_incident(self, i: dict[str, Any]) -> None:
        with tx(self.conn) as c:
            c.execute(
                "INSERT OR REPLACE INTO incidents(id, opened_at, severity, status, doc) VALUES (?,?,?,?,?)",
                (i["id"], i["opened_at"], i["severity"], i["status"], dumps(i)),
            )

    def put_review(self, r: dict[str, Any]) -> None:
        with tx(self.conn) as c:
            c.execute(
                "INSERT OR REPLACE INTO reviews(detection_id, opened_at, status, doc) VALUES (?,?,?,?)",
                (r["detection_id"], r["opened_at"], r["status"], dumps(r)),
            )

    def put_timeline(self, owner_id: str, timeline: list[dict[str, Any]]) -> None:
        with tx(self.conn) as c:
            c.execute("INSERT OR REPLACE INTO timelines(owner_id, doc) VALUES (?,?)", (owner_id, dumps(timeline)))

    def put_action(self, a: dict[str, Any]) -> None:
        with tx(self.conn) as c:
            c.execute(
                "INSERT OR REPLACE INTO containment_actions(workflow_id, incident_id, ts, status, doc) VALUES (?,?,?,?,?)",
                (
                    a["workflow_id"],
                    a.get("incident_id"),
                    a.get("applied_at") or a.get("requested_at"),
                    a["status"],
                    dumps(a),
                ),
            )

    def put_auth_event(self, e: dict[str, Any]) -> None:
        with tx(self.conn) as c:
            c.execute(
                "INSERT OR REPLACE INTO auth_events(event_id, ts, username, result, method, interface, doc) VALUES (?,?,?,?,?,?,?)",
                (
                    e["event_id"],
                    e["timestamp"],
                    e.get("username"),
                    e["result"],
                    e.get("method"),
                    e.get("nas_port_id"),
                    dumps(e),
                ),
            )

    def put_bucket(self, b: dict[str, Any]) -> None:
        with tx(self.conn) as c:
            c.execute("INSERT OR REPLACE INTO traffic_buckets(ts, doc) VALUES (?,?)", (b["ts"], dumps(b)))

    def put_validation(self, r: dict[str, Any]) -> None:
        with tx(self.conn) as c:
            c.execute(
                "INSERT OR REPLACE INTO validation_results(scenario_id, doc) VALUES (?,?)", (r["scenario_id"], dumps(r))
            )

    def put_scenario(self, s: dict[str, Any]) -> None:
        with tx(self.conn) as c:
            c.execute("INSERT OR REPLACE INTO scenarios(id, doc) VALUES (?,?)", (s["id"], dumps(s)))

    def bulk(self, fn, rows: list[dict[str, Any]]) -> None:
        for r in rows:
            fn(r)

    # ---- queries --------------------------------------------------------------------------------
    def devices(self) -> list[dict[str, Any]]:
        return self._docs("devices", order="vlan, interface")

    def unknown_devices(self) -> list[dict[str, Any]]:
        return self._docs("unknown_devices")

    def device(self, hostname: str) -> dict[str, Any] | None:
        return self._doc("devices", "hostname", hostname)

    def users(self) -> list[dict[str, Any]]:
        return self._docs("users", order="username")

    def alerts(
        self, *, severity: str | None = None, source: str | None = None, status: str | None = None, limit: int = 500
    ) -> list[dict[str, Any]]:
        clauses, params = [], []
        if severity:
            clauses.append("severity=?")
            params.append(severity)
        if source:
            clauses.append("source=?")
            params.append(source)
        if status:
            clauses.append("status=?")
            params.append(status)
        rows = self._docs("alerts", " AND ".join(clauses), tuple(params), order="ts DESC")
        return rows[:limit]

    def alert(self, alert_id: str) -> dict[str, Any] | None:
        return self._doc("alerts", "id", alert_id)

    def detections(self) -> list[dict[str, Any]]:
        return self._docs("detections", order="ts DESC")

    def detection(self, det_id: str) -> dict[str, Any] | None:
        return self._doc("detections", "id", det_id)

    def incidents(self) -> list[dict[str, Any]]:
        return self._docs("incidents", order="opened_at DESC")

    def incident(self, incident_id: str) -> dict[str, Any] | None:
        return self._doc("incidents", "id", incident_id)

    def reviews(self) -> list[dict[str, Any]]:
        return self._docs("reviews", order="opened_at DESC")

    def timeline(self, owner_id: str) -> list[dict[str, Any]]:
        row = self.conn.execute("SELECT doc FROM timelines WHERE owner_id=?", (owner_id,)).fetchone()
        return loads(row["doc"]) if row else []

    def actions(self) -> list[dict[str, Any]]:
        return self._docs("containment_actions", order="ts DESC")

    def action(self, workflow_id: str) -> dict[str, Any] | None:
        return self._doc("containment_actions", "workflow_id", workflow_id)

    def actions_for_incident(self, incident_id: str) -> list[dict[str, Any]]:
        return self._docs("containment_actions", "incident_id=?", (incident_id,), order="ts")

    def auth_events(self, limit: int = 1000) -> list[dict[str, Any]]:
        return self._docs("auth_events", order="ts DESC")[:limit]

    def buckets(self) -> list[dict[str, Any]]:
        return self._docs("traffic_buckets", order="ts")

    def validation(self) -> list[dict[str, Any]]:
        return self._docs("validation_results")

    def scenarios(self) -> list[dict[str, Any]]:
        return self._docs("scenarios")

    def counts(self) -> dict[str, int]:
        out = {}
        for t in ("devices", "alerts", "detections", "incidents", "reviews", "containment_actions", "auth_events"):
            out[t] = self.conn.execute(f"SELECT COUNT(*) AS n FROM {t}").fetchone()["n"]
        return out
