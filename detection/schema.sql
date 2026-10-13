-- Local normalized replay evidence. Author: Jason Stys. No raw SQL comes from inputs.
-- Tables: run (provenance), event (normalized JSON), alert (investigation candidates).
-- Variables: parameterized inserts are owned by store.py; indexes support detector/time searches.
PRAGMA foreign_keys = ON;
CREATE TABLE run (id INTEGER PRIMARY KEY CHECK (id = 1), report_json TEXT NOT NULL) STRICT;
CREATE TABLE event (
    id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, product TEXT NOT NULL,
    service TEXT NOT NULL, normalized_json TEXT NOT NULL
) STRICT;
CREATE TABLE alert (
    detector TEXT NOT NULL, event_id TEXT NOT NULL REFERENCES event(id),
    timestamp TEXT NOT NULL, evidence_json TEXT NOT NULL,
    span_seconds REAL NOT NULL CHECK (span_seconds >= 0),
    PRIMARY KEY (detector, event_id)
) STRICT;
CREATE INDEX alert_by_time ON alert(timestamp, detector);
CREATE INDEX event_by_source_time ON event(product, service, timestamp);
