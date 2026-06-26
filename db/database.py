#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SQLite history database for LLDP/CDP capture records.
WAL mode for safe concurrent access from capture threads.
"""

import sqlite3
import csv
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from pathlib import Path
import os

logger = logging.getLogger(__name__)


def _get_default_db_path() -> str:
    """Get the default database path in user data directory."""
    from utils.platform_utils import get_user_data_dir
    return os.path.join(get_user_data_dir(), "lldp_history.db")


class LLDPHistoryDatabase:
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = _get_default_db_path()
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS captures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    protocol TEXT,
                    device_name TEXT,
                    chassis_id TEXT,
                    port_id TEXT,
                    port_description TEXT,
                    mac_address TEXT,
                    ip_address TEXT,
                    system_description TEXT,
                    device_model TEXT,
                    serial_number TEXT,
                    software_version TEXT,
                    port_vlan INTEGER,
                    link_speed TEXT,
                    duplex_mode TEXT,
                    port_role TEXT,
                    device_type TEXT,
                    confidence INTEGER,
                    raw_packet TEXT
                )
            """)
            # Add columns if upgrading from old schema
            self._migrate(conn)

    def _migrate(self, conn):
        """Add columns added after the initial schema."""
        existing = {r[1] for r in conn.execute("PRAGMA table_info(captures)").fetchall()}
        for col, ddl in (
            ("port_description", "TEXT"),
            ("raw_packet", "TEXT"),
        ):
            if col not in existing:
                conn.execute(f"ALTER TABLE captures ADD COLUMN {col} {ddl}")

    def save_capture(self, *, protocol: str = "", device_name: str = "",
                     chassis_id: str = "", port_id: str = "",
                     port_description: str = "",
                     mac_address: str = "", ip_address: str = "",
                     system_description: str = "", device_model: str = "",
                     serial_number: str = "", software_version: str = "",
                     port_vlan: Optional[int] = None,
                     link_speed: str = "", duplex_mode: str = "",
                     port_role: Optional[str] = None,
                     device_type: Optional[str] = None,
                     confidence: Optional[int] = None,
                     raw_packet: str = "") -> int:
        with self._connect() as conn:
            cur = conn.execute("""
                INSERT INTO captures (
                    protocol, device_name, chassis_id, port_id, port_description,
                    mac_address, ip_address, system_description, device_model,
                    serial_number, software_version, port_vlan, link_speed,
                    duplex_mode, port_role, device_type, confidence, raw_packet
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                protocol, device_name, chassis_id, port_id, port_description,
                mac_address, ip_address, system_description, device_model,
                serial_number, software_version, port_vlan, link_speed,
                duplex_mode, port_role, device_type, confidence, raw_packet,
            ))
            return cur.lastrowid

    def query_devices(self, *, limit: int = 500,
                      start_time: Optional[datetime] = None,
                      end_time: Optional[datetime] = None,
                      device_name: Optional[str] = None,
                      port_role: Optional[str] = None) -> List[Dict[str, Any]]:
        clauses = []
        params: list = []
        if start_time:
            clauses.append("timestamp >= ?")
            # Use space separator to match SQLite's default timestamp format
            params.append(start_time.strftime("%Y-%m-%d %H:%M:%S"))
        if end_time:
            clauses.append("timestamp <= ?")
            params.append(end_time.strftime("%Y-%m-%d %H:%M:%S"))
        if device_name:
            clauses.append("device_name LIKE ?")
            params.append(f"%{device_name}%")
        if port_role:
            clauses.append("port_role = ?")
            params.append(port_role)
        where = " AND ".join(clauses) if clauses else "1=1"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM captures WHERE {where} ORDER BY timestamp DESC LIMIT ?",
                params,
            ).fetchall()
            return [dict(r) for r in rows]

    def get_statistics(self, days: int = 30) -> Dict[str, Any]:
        with self._connect() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM captures WHERE timestamp >= datetime('now', '-{} days')".format(days)
            ).fetchone()[0]
            
            unique = conn.execute(
                "SELECT COUNT(DISTINCT device_name) FROM captures WHERE timestamp >= datetime('now', '-{} days') AND device_name IS NOT NULL AND device_name != ''".format(days)
            ).fetchone()[0]
            
            model_rows = conn.execute(
                "SELECT device_model, COUNT(*) as cnt FROM captures "
                "WHERE timestamp >= datetime('now', '-{} days') GROUP BY device_model ORDER BY cnt DESC LIMIT 10".format(days)
            ).fetchall()
            
            role_rows = conn.execute(
                "SELECT port_role, COUNT(*) as cnt FROM captures "
                "WHERE timestamp >= datetime('now', '-{} days') AND port_role IS NOT NULL AND port_role != '' GROUP BY port_role ORDER BY cnt DESC LIMIT 10".format(days)
            ).fetchall()
            
            models = [{"device_model": r[0] or "Unknown", "count": r[1]} for r in model_rows]
            roles = [{"port_role": r[0] or "Unknown", "count": r[1]} for r in role_rows]
            
            return {
                "total_captures": total,
                "unique_devices": unique,
                "period_days": days,
                "device_models": models,
                "port_roles": roles,
            }

    def export_csv(self, path: str, **query_kwargs) -> int:
        rows = self.query_devices(limit=100000, **query_kwargs)
        if not rows:
            return 0
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        return len(rows)
