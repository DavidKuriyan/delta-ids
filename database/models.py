from __future__ import annotations

import datetime
import os
import pathlib

from sqlalchemy import Boolean, Column, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    first_seen = Column(Integer, nullable=False, default=lambda: int(datetime.datetime.now(datetime.timezone.utc).timestamp()))
    last_seen = Column(Integer, nullable=False, default=lambda: int(datetime.datetime.now(datetime.timezone.utc).timestamp()))
    occurrence_count = Column(Integer, nullable=False, default=1)
    suppressed_count = Column(Integer, nullable=False, default=0)
    severity = Column(String(20), nullable=False, default="MEDIUM")
    confidence = Column(Integer, nullable=False, default=0)
    risk = Column(Integer, nullable=False, default=0)
    detection_type = Column(String(40), nullable=False, default="signature")
    sid = Column(Integer, nullable=False, default=0)
    revision = Column(Integer, nullable=False, default=0)
    source_ip = Column(String(50))
    source_port = Column(Integer)
    destination_ip = Column(String(50))
    destination_port = Column(Integer)
    protocol = Column(String(20))
    service = Column(String(80))
    flow_id = Column(Integer, nullable=False, default=0)
    traffic_id = Column(Integer, nullable=False, default=0)
    message = Column(Text)
    evidence = Column(Text)
    explanation = Column(Text)
    fingerprint = Column(String(255), unique=True)


class Flow(Base):
    __tablename__ = "flows"

    id = Column(Integer, primary_key=True, autoincrement=True)
    start_time = Column(Integer)
    last_seen = Column(Integer)
    service = Column(String(80))
    protocol = Column(String(20))
    packets = Column(Integer, default=0)
    bytes = Column(Integer, default=0)


class DetectionEvent(Base):
    __tablename__ = "detection_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Integer)
    flow_id = Column(Integer, default=0)
    sid = Column(Integer, default=0)
    event_type = Column(String(40))
    explanation = Column(Text)
    evidence = Column(Text)


class Rule(Base):
    __tablename__ = "rules"

    sid = Column(Integer, primary_key=True)
    revision = Column(Integer, primary_key=True)
    message = Column(Text)
    enabled = Column(Boolean, default=True)
    source_file = Column(Text)
    gid = Column(Integer, nullable=False, default=1)
    priority = Column(Integer, nullable=False, default=3)
    protocol = Column(String(20))
    category = Column(String(100))
    rule_text = Column(Text)
    rule_json = Column(Text)
    updated_at = Column(Integer)


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"

    incident_id = Column(Integer, primary_key=True)
    alert_id = Column(Integer, primary_key=True)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    first_seen = Column(Integer, nullable=False, default=0)
    last_seen = Column(Integer, nullable=False, default=0)
    status = Column(String(20), nullable=False, default="OPEN")
    severity = Column(String(20), nullable=False, default="MEDIUM")
    confidence = Column(Integer, nullable=False, default=0)
    risk = Column(Integer, nullable=False, default=0)
    category = Column(String(100), nullable=False, default="signature")
    event_count = Column(Integer, nullable=False, default=0)
    explanation = Column(Text)


class Statistic(Base):
    __tablename__ = "statistics"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Integer)
    name = Column(String(100))
    value = Column(Integer)
    text_value = Column(Text)


class TrafficLog(Base):
    """Compatibility model for the Python capture path's packet stream."""

    __tablename__ = "traffic_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Integer)
    src_ip = Column(String(50))
    dst_ip = Column(String(50))
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String(20))
    length = Column(Integer)
    payload_summary = Column(Text)
    details = Column(Text)


_MIGRATIONS = (
    # (table, column, ALTER definition) applied to databases created before the column existed.
    ("alerts", "traffic_id", "INTEGER NOT NULL DEFAULT 0"),
    ("traffic_logs", "details", "TEXT"),
    ("rules", "gid", "INTEGER NOT NULL DEFAULT 1"),
    ("rules", "priority", "INTEGER NOT NULL DEFAULT 3"),
    ("rules", "protocol", "VARCHAR(20)"),
    ("rules", "category", "VARCHAR(100)"),
    ("rules", "rule_text", "TEXT"),
    ("rules", "rule_json", "TEXT"),
    ("rules", "updated_at", "INTEGER"),
    ("statistics", "text_value", "TEXT"),
)


def _clean_ipv6_records(engine) -> None:
    """Purge legacy IPv6 entries so they never leak into the IPv4-only NIDS pipeline."""
    from sqlalchemy import text

    with engine.connect() as connection:
        try:
            connection.execute(text("DELETE FROM traffic_logs WHERE src_ip LIKE '%:%' OR dst_ip LIKE '%:%'"))
            connection.execute(text("DELETE FROM alerts WHERE source_ip LIKE '%:%' OR destination_ip LIKE '%:%' OR protocol = 'ICMPv6' OR protocol = 'IPV6'"))
            connection.commit()
        except Exception:
            pass


def _migrate_existing_tables(engine) -> None:
    """Add columns introduced after the first release without touching existing data."""
    from sqlalchemy import text

    with engine.connect() as connection:
        for table, column, definition in _MIGRATIONS:
            rows = connection.execute(text(f"PRAGMA table_info({table})")).fetchall()
            if rows and all(row[1] != column for row in rows):
                connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {definition}"))
                connection.commit()
    _clean_ipv6_records(engine)


def init_db(db_path="nids.db"):
    """Create/open the schema shared with the C++ REST API."""
    database = pathlib.Path(db_path).expanduser().resolve()
    parent = database.parent
    parent.mkdir(parents=True, exist_ok=True)
    if database.exists() and not os.access(database, os.W_OK):
        raise PermissionError(f"database is not writable: {database}; repair ownership or permissions")
    if not os.access(parent, os.W_OK):
        raise PermissionError(f"database directory is not writable: {parent}; repair ownership or permissions")
    engine = create_engine(f"sqlite:///{database}", future=True, pool_pre_ping=True)
    Base.metadata.create_all(engine)
    _migrate_existing_tables(engine)
    session = sessionmaker(bind=engine, future=True)()
    return session
