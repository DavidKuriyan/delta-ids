from __future__ import annotations

import datetime
import hashlib
import json
import logging
import threading
import time
from collections import deque
from typing import Optional

from database.models import Alert, Incident, IncidentAlert, Rule, Statistic, TrafficLog, init_db
from sqlalchemy import or_
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger("delta-ids")


def now_epoch() -> int:
    return int(time.time())


def format_human_alert(timestamp: int, alert: dict, severity: str) -> str:
    instant = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).astimezone()
    stamp = instant.strftime('%m/%d-%H:%M:%S') + f'.{instant.microsecond:06d}'
    gid = int(alert.get('gid', 1) or 1)
    sid = alert.get('sid', 0)
    rev = int(alert.get('revision', 1) or 1)
    protocol = str(alert.get('protocol') or 'IP').upper()
    source = str(alert.get('src_ip') or '-')
    destination = str(alert.get('dst_ip') or '-')
    if protocol not in {'ICMP', 'ICMPV6', 'IP'} and alert.get('src_port'):
        source += f":{alert['src_port']}"
    if protocol not in {'ICMP', 'ICMPV6', 'IP'} and alert.get('dst_port'):
        destination += f":{alert['dst_port']}"
    priority = int(alert.get('priority') or 3)
    return (f'{stamp}  [*] [{gid}:{sid}:{rev}] {alert.get("message", "Detection event")} [*]\\n'
            f'[Priority: {priority}] {{{protocol}}} {source} -> {destination}')


class AlertManager:
    def __init__(self, db_path: str | None = None, terminal: bool = True, persist: bool = False):
        self.session = init_db(db_path) if db_path and persist else None
        self.terminal = terminal
        self.persist = persist
        self.session_start = datetime.datetime.now(datetime.timezone.utc)
        self._live_traffic = deque(maxlen=500)
        self._live_alerts = deque(maxlen=1000)
        self._alert_counter = 0
        self._lock = threading.RLock()
        if self.session:
            self._persist_statistic("capture_sessions_started", 1)

    def persist_rules(self, rules, source_file: str) -> None:
        if not self.session:
            return
        with self._lock:
            try:
                for rule in rules:
                    self.session.merge(Rule(sid=int(rule.get('sid', 0)), revision=int(rule.get('rev', rule.get('revision', 1)) or 1), message=rule.get('message', ''), enabled=True, source_file=source_file, gid=int(rule.get('gid', 1) or 1), priority=int(rule.get('priority', 3) or 3), protocol=str(rule.get('protocol', ''))))
                self.session.commit()
            except SQLAlchemyError as error:
                self.session.rollback()
                logger.error("failed to persist rules: %s", error)

    def log_traffic(self, packet) -> Optional[int]:
        timestamp = now_epoch()
        event = {"timestamp": timestamp, "src_ip": packet.get("src_ip"), "dst_ip": packet.get("dst_ip"), "src_port": packet.get("src_port"), "dst_port": packet.get("dst_port"), "protocol": packet.get("protocol"), "length": packet.get("length", 0)}
        self._live_traffic.appendleft(event)
        if not self.session:
            return None
        with self._lock:
            try:
                row = TrafficLog(**event, payload_summary="", details=json.dumps(packet.get("details")) if packet.get("details") else None)
                self.session.add(row)
                self.session.commit()
                return int(row.id)
            except SQLAlchemyError as error:
                self.session.rollback()
                logger.error("failed to persist traffic: %s", error)
                return None

    def log_alert(self, alert):
        timestamp = now_epoch()
        with self._lock:
            self._alert_counter += 1
            event = {"id": self._alert_counter, "timestamp": timestamp, **alert}
            self._live_alerts.appendleft(event)
        severity = str(alert.get("severity", "Low")).upper()
        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            severity = "LOW"
        if self.terminal:
            print(format_human_alert(timestamp, alert, severity), flush=True)
        if not self.session:
            return
        with self._lock:
            try:
                source = alert.get("src_ip") or ""
                destination = alert.get("dst_ip") or ""
                sid = alert.get("sid") or 0
                fingerprint = hashlib.sha256(f"{source}|{destination}|{sid}|{alert.get('message', '')}".encode()).hexdigest()
                values = {"first_seen": timestamp, "last_seen": timestamp, "occurrence_count": 1, "suppressed_count": 0, "severity": severity, "confidence": int(alert.get("confidence", 0) or 0), "risk": int(alert.get("risk", 0) or 0), "detection_type": "behavioral" if alert.get("is_ml_anomaly") else "signature", "sid": sid, "revision": int(alert.get("revision", 1) or 1), "source_ip": source, "source_port": alert.get("src_port"), "destination_ip": destination, "destination_port": alert.get("dst_port"), "protocol": alert.get("protocol") or "", "service": alert.get("service") or "", "flow_id": int(alert.get("flow_id", 0) or 0), "traffic_id": int(alert.get("traffic_id", 0) or 0), "message": alert.get("message") or "", "evidence": alert.get("evidence") or "", "explanation": alert.get("explanation") or "", "fingerprint": fingerprint}
                statement = sqlite_insert(Alert).values(**values).on_conflict_do_update(index_elements=[Alert.__table__.c.fingerprint], set_={"last_seen": values["last_seen"], "occurrence_count": Alert.__table__.c.occurrence_count + 1, "traffic_id": values["traffic_id"]})
                self.session.execute(statement)
                self.session.commit()
                persisted = self.session.query(Alert).filter_by(fingerprint=fingerprint).one_or_none()
                if persisted is not None:
                    values["id"] = int(persisted.id)
                self._persist_incident(values)
            except SQLAlchemyError as error:
                self.session.rollback()
                logger.error("failed to persist alert: %s", error)

    def _persist_incident(self, values: dict) -> None:
        with self._lock:
            try:
                # Correlate only with an open incident that has an actual
                # source/destination/protocol/category relationship. The old
                # implementation grouped every open signature alert together.
                window = 30
                candidates = (self.session.query(Incident)
                              .filter(Incident.status == 'OPEN',
                                      Incident.category == ('behavioral' if values.get('detection_type') == 'behavioral' else 'signature'),
                                      Incident.last_seen >= values['first_seen'] - window)
                              .order_by(Incident.last_seen.desc()).all())
                incident = None
                for candidate in candidates:
                    linked_ids = [row.alert_id for row in self.session.query(IncidentAlert).filter_by(incident_id=candidate.id).all()]
                    linked = self.session.query(Alert).filter(Alert.id.in_(linked_ids)).all() if linked_ids else []
                    if any(alert.source_ip == values['source_ip'] and
                           alert.destination_ip == values['destination_ip'] and
                           alert.protocol == values['protocol'] for alert in linked):
                        incident = candidate
                        break
                if incident is None:
                    incident = Incident(first_seen=values['first_seen'], last_seen=values['last_seen'], status='OPEN', severity=values['severity'], confidence=values['confidence'], risk=values['risk'], category='behavioral' if values.get('detection_type') == 'behavioral' else 'signature', event_count=1, explanation=values['message'])
                    self.session.add(incident)
                    self.session.flush()
                else:
                    incident.last_seen = max(incident.last_seen or 0, values['last_seen'])
                    incident.event_count = (incident.event_count or 0) + 1
                    incident.confidence = max(incident.confidence or 0, values['confidence'])
                    incident.risk = max(incident.risk or 0, values['risk'])
                alert_id = int(values.get('id', 0) or 0)
                if alert_id:
                    self.session.merge(IncidentAlert(incident_id=incident.id, alert_id=alert_id))
                self.session.commit()
            except SQLAlchemyError as error:
                self.session.rollback()
                logger.error("failed to persist incident: %s", error)

    def persist_runtime_status(self, status: str, interface: str | None = None, packets_captured: int = 0, packets_processed: int = 0, last_packet_time: float | None = None, error: str | None = None) -> None:
        if not self.session:
            return
        payload = json.dumps({"status": status, "interface": interface, "packets_captured": packets_captured, "packets_processed": packets_processed, "last_packet_time": last_packet_time, "error": error})
        with self._lock:
            try:
                self.session.query(Statistic).filter(Statistic.name == "capture_runtime").delete(synchronize_session=False)
                self.session.add(Statistic(timestamp=now_epoch(), name="capture_runtime", value=0, text_value=payload))
                self.session.commit()
            except SQLAlchemyError as error:
                self.session.rollback()
                logger.error("failed to persist capture runtime status: %s", error)

    def _persist_statistic(self, name: str, value: int) -> None:
        if not self.session:
            return
        with self._lock:
            try:
                self.session.add(Statistic(timestamp=now_epoch(), name=name, value=value))
                self.session.commit()
            except SQLAlchemyError as error:
                self.session.rollback()
                logger.error("failed to persist statistic: %s", error)

    def get_recent_traffic(self, limit=100):
        return list(self._live_traffic)[:limit]

    def get_recent_alerts(self, limit=500):
        return list(self._live_alerts)[:limit]

    def clear_runtime_state(self) -> None:
        """Clear in-memory event views without affecting capture or rules."""
        with self._lock:
            self._live_traffic.clear()
            self._live_alerts.clear()

    def get_alert_counts(self):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "total": 0}
        for alert in self._live_alerts:
            severity = str(alert.get("severity", "LOW")).upper()
            counts[severity] = counts.get(severity, 0) + 1
            counts["total"] += 1
        return counts

    def reset_session_data(self) -> None:
        """Remove current-session evidence while preserving configured rules."""
        if not self.session:
            self.clear_runtime_state()
            return
        with self._lock:
            try:
                for model in (IncidentAlert, Incident, Alert, TrafficLog, Statistic):
                    self.session.query(model).delete(synchronize_session=False)
                self.session.commit()
                self.clear_runtime_state()
            except SQLAlchemyError as error:
                self.session.rollback()
                logger.error("failed to reset session data: %s", error)
                raise

    def close(self) -> None:
        if self.session:
            bind = self.session.get_bind()
            self.session.close()
            if bind:
                bind.dispose()


