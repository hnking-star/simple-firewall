# Simple Firewall Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a simple, modular Linux firewall management system with Vue3 UI, Flask API, SQLite storage, custom rule DSL, Scapy monitoring, and iptables application.

**Architecture:** Keep backend modules small and responsibility-focused: parser, repository, iptables adapter, sniffer service, update service, and API blueprints. Keep frontend pages separate: dashboard, rules, monitor, logs, and settings. Prefer explicit data objects and simple REST polling over extra framework complexity.

**Tech Stack:** Python 3, Flask, SQLite, pytest, Scapy, iptables, Node.js, Vite, Vue3, Vue Router, Axios, ECharts.

---

## Engineering Principles

- Keep files focused; no large all-purpose service files.
- Implement the smallest working version of each module, then verify with tests.
- Do not modify host firewall outside rules owned by this project.
- All iptables commands must be generated in a testable adapter before execution.
- Default development path must support non-root testing by using dry-run or mocked command execution.
- Each public Python function should include a short docstring describing purpose, parameters, and return value.

## File Structure

### Backend

- Create: `/Users/bytedance/Desktop/keshe/backend/requirements.txt` — Python runtime and test dependencies.
- Create: `/Users/bytedance/Desktop/keshe/backend/run.py` — Flask entrypoint.
- Create: `/Users/bytedance/Desktop/keshe/backend/app/__init__.py` — app factory and service wiring.
- Create: `/Users/bytedance/Desktop/keshe/backend/app/config.py` — paths and defaults.
- Create: `/Users/bytedance/Desktop/keshe/backend/app/db.py` — SQLite connection and schema initialization.
- Create: `/Users/bytedance/Desktop/keshe/backend/app/models.py` — dataclasses for rules, packets, stats.
- Create: `/Users/bytedance/Desktop/keshe/backend/app/rule_parser.py` — DSL parser and validation.
- Create: `/Users/bytedance/Desktop/keshe/backend/app/repositories.py` — SQLite CRUD functions.
- Create: `/Users/bytedance/Desktop/keshe/backend/app/iptables_adapter.py` — iptables command generation and execution.
- Create: `/Users/bytedance/Desktop/keshe/backend/app/update_service.py` — immediate/time/count update mode logic.
- Create: `/Users/bytedance/Desktop/keshe/backend/app/sniffer_service.py` — Scapy capture service and packet conversion.
- Create: `/Users/bytedance/Desktop/keshe/backend/app/api.py` — Flask routes.
- Create: `/Users/bytedance/Desktop/keshe/backend/tests/conftest.py` — test app and temp database fixtures.
- Create: `/Users/bytedance/Desktop/keshe/backend/tests/test_rule_parser.py` — parser tests.
- Create: `/Users/bytedance/Desktop/keshe/backend/tests/test_iptables_adapter.py` — iptables command tests.
- Create: `/Users/bytedance/Desktop/keshe/backend/tests/test_api.py` — API integration tests.

### Frontend

- Create: `/Users/bytedance/Desktop/keshe/frontend/package.json` — frontend scripts and dependencies.
- Create: `/Users/bytedance/Desktop/keshe/frontend/index.html` — Vite HTML entry.
- Create: `/Users/bytedance/Desktop/keshe/frontend/vite.config.js` — dev server config and API proxy.
- Create: `/Users/bytedance/Desktop/keshe/frontend/src/main.js` — Vue app bootstrap.
- Create: `/Users/bytedance/Desktop/keshe/frontend/src/App.vue` — shell layout with sidebar.
- Create: `/Users/bytedance/Desktop/keshe/frontend/src/router.js` — route definitions.
- Create: `/Users/bytedance/Desktop/keshe/frontend/src/api/client.js` — Axios API client.
- Create: `/Users/bytedance/Desktop/keshe/frontend/src/assets/styles.css` — shared styles.
- Create: `/Users/bytedance/Desktop/keshe/frontend/src/pages/Dashboard.vue` — quantity analysis homepage.
- Create: `/Users/bytedance/Desktop/keshe/frontend/src/pages/Rules.vue` — rule CRUD and DSL parsing.
- Create: `/Users/bytedance/Desktop/keshe/frontend/src/pages/Monitor.vue` — sniffer control and packet view.
- Create: `/Users/bytedance/Desktop/keshe/frontend/src/pages/Logs.vue` — log query and CSV export.
- Create: `/Users/bytedance/Desktop/keshe/frontend/src/pages/Settings.vue` — system settings.

### Documentation

- Create: `/Users/bytedance/Desktop/keshe/README.md` — install, run, and Linux test instructions.
- Create: `/Users/bytedance/Desktop/keshe/docs/功能目标分解表.md` — requirement-to-feature mapping.
- Create: `/Users/bytedance/Desktop/keshe/docs/规则语言说明.md` — DSL syntax and examples.
- Create: `/Users/bytedance/Desktop/keshe/docs/课程设计报告.md` — report draft.

---

## Task 1: Backend Skeleton and Database Foundation

**Files:**
- Create: `/Users/bytedance/Desktop/keshe/backend/requirements.txt`
- Create: `/Users/bytedance/Desktop/keshe/backend/app/config.py`
- Create: `/Users/bytedance/Desktop/keshe/backend/app/db.py`
- Create: `/Users/bytedance/Desktop/keshe/backend/app/__init__.py`
- Create: `/Users/bytedance/Desktop/keshe/backend/run.py`
- Create: `/Users/bytedance/Desktop/keshe/backend/tests/conftest.py`
- Create: `/Users/bytedance/Desktop/keshe/backend/tests/test_api.py`

- [ ] **Step 1: Write backend dependency file**

Create `/Users/bytedance/Desktop/keshe/backend/requirements.txt`:

```txt
Flask==3.0.3
flask-cors==4.0.1
pytest==8.2.2
scapy==2.5.0
```

- [ ] **Step 2: Write failing health/database test**

Create `/Users/bytedance/Desktop/keshe/backend/tests/test_api.py`:

```python
def test_health_endpoint_returns_ok(client):
    response = client.get('/api/health')
    assert response.status_code == 200
    assert response.get_json() == {'status': 'ok'}


def test_database_schema_contains_rules_table(db_connection):
    rows = db_connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall()
    names = [row['name'] for row in rows]
    assert 'rules' in names
    assert 'traffic_logs' in names
    assert 'system_logs' in names
```

- [ ] **Step 3: Write test fixtures**

Create `/Users/bytedance/Desktop/keshe/backend/tests/conftest.py`:

```python
import sqlite3
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT))

from app import create_app
from app.db import init_db


@pytest.fixture()
def db_path(tmp_path):
    return tmp_path / 'firewall_test.db'


@pytest.fixture()
def app(db_path):
    flask_app = create_app({'DATABASE_PATH': str(db_path), 'TESTING': True})
    with flask_app.app_context():
        init_db(str(db_path))
    return flask_app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def db_connection(db_path):
    init_db(str(db_path))
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()
```

- [ ] **Step 4: Run test to verify it fails**

Run:

```bash
cd /Users/bytedance/Desktop/keshe/backend
python3 -m pip install -r requirements.txt
pytest tests/test_api.py -v
```

Expected: FAIL because `app` package does not exist.

- [ ] **Step 5: Implement config**

Create `/Users/bytedance/Desktop/keshe/backend/app/config.py`:

```python
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE_PATH = BASE_DIR / 'firewall.db'
DEFAULT_INTERFACE = 'any'
DEFAULT_UPDATE_MODE = 'immediate'
DEFAULT_UPDATE_INTERVAL = 30
DEFAULT_UPDATE_BATCH_SIZE = 3
```

- [ ] **Step 6: Implement database schema**

Create `/Users/bytedance/Desktop/keshe/backend/app/db.py`:

```python
import sqlite3
from datetime import datetime


def connect_db(database_path):
    """Open a SQLite connection.

    Args:
        database_path: Path to the SQLite database file.

    Returns:
        sqlite3.Connection with row access by column name.
    """
    conn = sqlite3.connect(database_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(database_path):
    """Create required tables and default settings.

    Args:
        database_path: Path to the SQLite database file.

    Returns:
        None.
    """
    conn = connect_db(database_path)
    now = datetime.utcnow().isoformat()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                action TEXT NOT NULL,
                direction TEXT NOT NULL,
                protocol TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port TEXT NOT NULL,
                dst_port TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                priority INTEGER NOT NULL DEFAULT 100,
                dsl_text TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS rule_updates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER,
                operation TEXT NOT NULL,
                status TEXT NOT NULL,
                message TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                applied_at TEXT
            );

            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port TEXT NOT NULL,
                dst_port TEXT NOT NULL,
                protocol TEXT NOT NULL,
                direction TEXT NOT NULL,
                action TEXT NOT NULL,
                rule_id INTEGER,
                packet_len INTEGER NOT NULL,
                reason TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                module TEXT NOT NULL,
                message TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                description TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        defaults = [
            ('interface', 'any', 'Scapy capture interface'),
            ('iptables_enabled', 'true', 'Apply rules to iptables'),
            ('sniffer_enabled', 'false', 'Run packet capture'),
            ('update_mode', 'immediate', 'immediate, timed, or counted'),
            ('update_interval', '30', 'Seconds between timed updates'),
            ('update_batch_size', '3', 'Pending changes before counted update'),
        ]
        conn.executemany(
            "INSERT OR IGNORE INTO settings(key, value, description, updated_at) VALUES (?, ?, ?, ?)",
            [(key, value, description, now) for key, value, description in defaults],
        )
        conn.commit()
    finally:
        conn.close()
```

- [ ] **Step 7: Implement Flask app factory and entrypoint**

Create `/Users/bytedance/Desktop/keshe/backend/app/__init__.py`:

```python
from flask import Flask
from flask_cors import CORS

from app.config import DEFAULT_DATABASE_PATH
from app.db import init_db


def create_app(test_config=None):
    """Create and configure the Flask application.

    Args:
        test_config: Optional dictionary used to override default config.

    Returns:
        Configured Flask application.
    """
    app = Flask(__name__)
    app.config['DATABASE_PATH'] = str(DEFAULT_DATABASE_PATH)
    if test_config:
        app.config.update(test_config)

    CORS(app)
    init_db(app.config['DATABASE_PATH'])

    from app.api import api_bp
    app.register_blueprint(api_bp, url_prefix='/api')
    return app
```

Create `/Users/bytedance/Desktop/keshe/backend/run.py`:

```python
from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
```

Create `/Users/bytedance/Desktop/keshe/backend/app/api.py`:

```python
from flask import Blueprint, jsonify

api_bp = Blueprint('api', __name__)


@api_bp.get('/health')
def health():
    """Return API health status.

    Args:
        None.

    Returns:
        JSON object with status field.
    """
    return jsonify({'status': 'ok'})
```

- [ ] **Step 8: Verify backend skeleton passes**

Run:

```bash
cd /Users/bytedance/Desktop/keshe/backend
pytest tests/test_api.py -v
```

Expected: 2 passed.

- [ ] **Step 9: Commit backend skeleton**

Run:

```bash
cd /Users/bytedance/Desktop/keshe
git add backend
git commit -m "feat: add backend app skeleton"
```

---

## Task 2: Rule DSL Parser

**Files:**
- Create: `/Users/bytedance/Desktop/keshe/backend/app/models.py`
- Create: `/Users/bytedance/Desktop/keshe/backend/app/rule_parser.py`
- Create: `/Users/bytedance/Desktop/keshe/backend/tests/test_rule_parser.py`

- [ ] **Step 1: Write parser tests**

Create `/Users/bytedance/Desktop/keshe/backend/tests/test_rule_parser.py`:

```python
import pytest

from app.rule_parser import RuleParser, RuleParserError


def test_parse_tcp_deny_out_rule():
    parsed = RuleParser.parse('DENY OUT UDP FROM ANY TO 8.8.8.8 SPORT ANY DPORT 53')
    assert parsed.action == 'DENY'
    assert parsed.direction == 'OUT'
    assert parsed.protocol == 'UDP'
    assert parsed.src_ip == 'ANY'
    assert parsed.dst_ip == '8.8.8.8'
    assert parsed.src_port == 'ANY'
    assert parsed.dst_port == '53'


def test_parse_icmp_rule_without_ports():
    parsed = RuleParser.parse('DENY IN ICMP FROM 10.0.0.5 TO ANY')
    assert parsed.protocol == 'ICMP'
    assert parsed.src_port == 'ANY'
    assert parsed.dst_port == 'ANY'


def test_reject_invalid_ip():
    with pytest.raises(RuleParserError, match='Invalid source IP'):
        RuleParser.parse('ALLOW IN TCP FROM 999.1.1.1 TO ANY SPORT ANY DPORT 80')


def test_reject_invalid_port():
    with pytest.raises(RuleParserError, match='Invalid destination port'):
        RuleParser.parse('ALLOW IN TCP FROM ANY TO ANY SPORT ANY DPORT abc')
```

- [ ] **Step 2: Run parser tests to verify failure**

Run:

```bash
cd /Users/bytedance/Desktop/keshe/backend
pytest tests/test_rule_parser.py -v
```

Expected: FAIL because `app.rule_parser` does not exist.

- [ ] **Step 3: Add rule dataclass**

Create `/Users/bytedance/Desktop/keshe/backend/app/models.py`:

```python
from dataclasses import dataclass


@dataclass(frozen=True)
class FirewallRule:
    """Structured firewall rule parsed from form data or DSL text.

    Args:
        action: ALLOW or DENY.
        direction: IN or OUT.
        protocol: TCP, UDP, ICMP, or ANY.
        src_ip: Source IPv4, CIDR, or ANY.
        dst_ip: Destination IPv4, CIDR, or ANY.
        src_port: Source port, range, or ANY.
        dst_port: Destination port, range, or ANY.
    """

    action: str
    direction: str
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: str = 'ANY'
    dst_port: str = 'ANY'
```

- [ ] **Step 4: Implement parser**

Create `/Users/bytedance/Desktop/keshe/backend/app/rule_parser.py`:

```python
import ipaddress

from app.models import FirewallRule


class RuleParserError(ValueError):
    """Raised when a firewall DSL rule cannot be parsed or validated."""


class RuleParser:
    """Parse one-line firewall DSL strings into FirewallRule objects."""

    ACTIONS = {'ALLOW', 'DENY'}
    DIRECTIONS = {'IN', 'OUT'}
    PROTOCOLS = {'TCP', 'UDP', 'ICMP', 'ANY'}

    @classmethod
    def parse(cls, text):
        """Parse a DSL rule.

        Args:
            text: One-line DSL rule string.

        Returns:
            FirewallRule object.
        """
        tokens = text.strip().upper().split()
        if len(tokens) < 7:
            raise RuleParserError('Rule is too short')

        action, direction, protocol = tokens[0], tokens[1], tokens[2]
        cls._require(action in cls.ACTIONS, 'Invalid action')
        cls._require(direction in cls.DIRECTIONS, 'Invalid direction')
        cls._require(protocol in cls.PROTOCOLS, 'Invalid protocol')
        cls._require(tokens[3] == 'FROM', 'Missing FROM')

        src_ip = tokens[4]
        cls._require(tokens[5] == 'TO', 'Missing TO')
        dst_ip = tokens[6]
        src_port = 'ANY'
        dst_port = 'ANY'

        if len(tokens) > 7:
            cls._require(len(tokens) == 11, 'Port clause must be SPORT value DPORT value')
            cls._require(tokens[7] == 'SPORT', 'Missing SPORT')
            src_port = tokens[8]
            cls._require(tokens[9] == 'DPORT', 'Missing DPORT')
            dst_port = tokens[10]

        cls._validate_ip(src_ip, 'source')
        cls._validate_ip(dst_ip, 'destination')
        cls._validate_port(src_port, 'source')
        cls._validate_port(dst_port, 'destination')
        return FirewallRule(action, direction, protocol, src_ip, dst_ip, src_port, dst_port)

    @staticmethod
    def _require(condition, message):
        """Raise parser error when condition is false.

        Args:
            condition: Boolean validation result.
            message: Error message.

        Returns:
            None.
        """
        if not condition:
            raise RuleParserError(message)

    @staticmethod
    def _validate_ip(value, label):
        """Validate IPv4, CIDR, or ANY.

        Args:
            value: IP token from DSL.
            label: Human-readable field name.

        Returns:
            None.
        """
        if value == 'ANY':
            return
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise RuleParserError(f'Invalid {label} IP') from exc

    @staticmethod
    def _validate_port(value, label):
        """Validate port token.

        Args:
            value: Port token, port range, or ANY.
            label: Human-readable field name.

        Returns:
            None.
        """
        if value == 'ANY':
            return
        if '-' in value:
            start, end = value.split('-', 1)
            if start.isdigit() and end.isdigit() and 1 <= int(start) <= int(end) <= 65535:
                return
            raise RuleParserError(f'Invalid {label} port')
        if value.isdigit() and 1 <= int(value) <= 65535:
            return
        raise RuleParserError(f'Invalid {label} port')
```

- [ ] **Step 5: Verify parser tests pass**

Run:

```bash
cd /Users/bytedance/Desktop/keshe/backend
pytest tests/test_rule_parser.py -v
```

Expected: 4 passed.

- [ ] **Step 6: Commit parser**

Run:

```bash
cd /Users/bytedance/Desktop/keshe
git add backend/app/models.py backend/app/rule_parser.py backend/tests/test_rule_parser.py
git commit -m "feat: add firewall rule parser"
```

---

## Task 3: iptables Command Adapter

**Files:**
- Create: `/Users/bytedance/Desktop/keshe/backend/app/iptables_adapter.py`
- Create: `/Users/bytedance/Desktop/keshe/backend/tests/test_iptables_adapter.py`

- [ ] **Step 1: Write command generation tests**

Create `/Users/bytedance/Desktop/keshe/backend/tests/test_iptables_adapter.py`:

```python
from app.iptables_adapter import IptablesAdapter
from app.models import FirewallRule


def test_build_drop_output_udp_dns_rule():
    rule = FirewallRule('DENY', 'OUT', 'UDP', 'ANY', '8.8.8.8', 'ANY', '53')
    command = IptablesAdapter.build_rule_command(rule)
    assert command == [
        'iptables', '-A', 'OUTPUT', '-p', 'udp', '-d', '8.8.8.8', '--dport', '53', '-j', 'DROP'
    ]


def test_build_allow_input_tcp_rule():
    rule = FirewallRule('ALLOW', 'IN', 'TCP', '192.168.1.10', 'ANY', 'ANY', '22')
    command = IptablesAdapter.build_rule_command(rule)
    assert command == [
        'iptables', '-A', 'INPUT', '-p', 'tcp', '-s', '192.168.1.10', '--dport', '22', '-j', 'ACCEPT'
    ]


def test_build_any_protocol_rule_without_protocol_flags():
    rule = FirewallRule('DENY', 'IN', 'ANY', '10.0.0.0/24', 'ANY', 'ANY', 'ANY')
    command = IptablesAdapter.build_rule_command(rule)
    assert command == ['iptables', '-A', 'INPUT', '-s', '10.0.0.0/24', '-j', 'DROP']
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
cd /Users/bytedance/Desktop/keshe/backend
pytest tests/test_iptables_adapter.py -v
```

Expected: FAIL because `app.iptables_adapter` does not exist.

- [ ] **Step 3: Implement adapter**

Create `/Users/bytedance/Desktop/keshe/backend/app/iptables_adapter.py`:

```python
import subprocess


class IptablesAdapter:
    """Build and execute iptables commands for project-owned rules."""

    @staticmethod
    def build_rule_command(rule):
        """Convert a FirewallRule into one iptables append command.

        Args:
            rule: FirewallRule instance.

        Returns:
            Command list suitable for subprocess.run.
        """
        chain = 'INPUT' if rule.direction == 'IN' else 'OUTPUT'
        target = 'ACCEPT' if rule.action == 'ALLOW' else 'DROP'
        command = ['iptables', '-A', chain]

        if rule.protocol != 'ANY':
            command.extend(['-p', rule.protocol.lower()])
        if rule.src_ip != 'ANY':
            command.extend(['-s', rule.src_ip])
        if rule.dst_ip != 'ANY':
            command.extend(['-d', rule.dst_ip])
        if rule.protocol in {'TCP', 'UDP'} and rule.src_port != 'ANY':
            command.extend(['--sport', rule.src_port.replace('-', ':')])
        if rule.protocol in {'TCP', 'UDP'} and rule.dst_port != 'ANY':
            command.extend(['--dport', rule.dst_port.replace('-', ':')])

        command.extend(['-j', target])
        return command

    @staticmethod
    def run(command, dry_run=False):
        """Execute or return an iptables command.

        Args:
            command: Command list.
            dry_run: When true, do not execute command.

        Returns:
            Dictionary with command, returncode, stdout, and stderr.
        """
        if dry_run:
            return {'command': command, 'returncode': 0, 'stdout': '', 'stderr': ''}
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        return {
            'command': command,
            'returncode': completed.returncode,
            'stdout': completed.stdout,
            'stderr': completed.stderr,
        }
```

- [ ] **Step 4: Verify adapter tests pass**

Run:

```bash
cd /Users/bytedance/Desktop/keshe/backend
pytest tests/test_iptables_adapter.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit adapter**

Run:

```bash
cd /Users/bytedance/Desktop/keshe
git add backend/app/iptables_adapter.py backend/tests/test_iptables_adapter.py
git commit -m "feat: add iptables command adapter"
```

---

## Task 4: Repositories and Rule API

**Files:**
- Create: `/Users/bytedance/Desktop/keshe/backend/app/repositories.py`
- Modify: `/Users/bytedance/Desktop/keshe/backend/app/api.py`
- Modify: `/Users/bytedance/Desktop/keshe/backend/tests/test_api.py`

- [ ] **Step 1: Add rule API tests**

Append to `/Users/bytedance/Desktop/keshe/backend/tests/test_api.py`:

```python

def test_create_and_list_rule(client):
    payload = {
        'name': 'block dns',
        'dsl_text': 'DENY OUT UDP FROM ANY TO 8.8.8.8 SPORT ANY DPORT 53',
        'enabled': True,
        'priority': 10,
    }
    create_response = client.post('/api/rules', json=payload)
    assert create_response.status_code == 201
    created = create_response.get_json()
    assert created['name'] == 'block dns'
    assert created['action'] == 'DENY'

    list_response = client.get('/api/rules')
    assert list_response.status_code == 200
    rules = list_response.get_json()['items']
    assert len(rules) == 1
    assert rules[0]['dst_ip'] == '8.8.8.8'


def test_parse_rule_endpoint(client):
    response = client.post('/api/rules/parse', json={
        'dsl_text': 'ALLOW IN TCP FROM ANY TO ANY SPORT ANY DPORT 22'
    })
    assert response.status_code == 200
    assert response.get_json()['dst_port'] == '22'
```

- [ ] **Step 2: Run API tests to verify failure**

Run:

```bash
cd /Users/bytedance/Desktop/keshe/backend
pytest tests/test_api.py -v
```

Expected: FAIL because `/api/rules` and `/api/rules/parse` are not implemented.

- [ ] **Step 3: Implement repositories**

Create `/Users/bytedance/Desktop/keshe/backend/app/repositories.py` with simple functions for this task:

```python
from datetime import datetime

from app.db import connect_db


def row_to_dict(row):
    """Convert sqlite row to dictionary.

    Args:
        row: sqlite3.Row instance.

    Returns:
        Plain dictionary.
    """
    return dict(row) if row else None


def create_rule(database_path, rule, name, enabled=True, priority=100, dsl_text=''):
    """Insert a firewall rule.

    Args:
        database_path: SQLite database path.
        rule: FirewallRule object.
        name: Rule display name.
        enabled: Whether rule is active.
        priority: Lower number means earlier application.
        dsl_text: Original DSL text.

    Returns:
        Inserted rule as dictionary.
    """
    now = datetime.utcnow().isoformat()
    conn = connect_db(database_path)
    try:
        cursor = conn.execute(
            """
            INSERT INTO rules(name, action, direction, protocol, src_ip, dst_ip, src_port, dst_port,
                              enabled, priority, dsl_text, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (name, rule.action, rule.direction, rule.protocol, rule.src_ip, rule.dst_ip,
             rule.src_port, rule.dst_port, int(enabled), priority, dsl_text, now, now),
        )
        conn.commit()
        return get_rule(database_path, cursor.lastrowid)
    finally:
        conn.close()


def get_rule(database_path, rule_id):
    """Fetch one rule by id.

    Args:
        database_path: SQLite database path.
        rule_id: Rule id.

    Returns:
        Rule dictionary or None.
    """
    conn = connect_db(database_path)
    try:
        return row_to_dict(conn.execute('SELECT * FROM rules WHERE id = ?', (rule_id,)).fetchone())
    finally:
        conn.close()


def list_rules(database_path):
    """List rules ordered by priority and id.

    Args:
        database_path: SQLite database path.

    Returns:
        List of rule dictionaries.
    """
    conn = connect_db(database_path)
    try:
        rows = conn.execute('SELECT * FROM rules ORDER BY priority ASC, id ASC').fetchall()
        return [row_to_dict(row) for row in rows]
    finally:
        conn.close()
```

- [ ] **Step 4: Implement rule routes**

Replace `/Users/bytedance/Desktop/keshe/backend/app/api.py` with:

```python
from flask import Blueprint, current_app, jsonify, request

from app.repositories import create_rule, list_rules
from app.rule_parser import RuleParser, RuleParserError

api_bp = Blueprint('api', __name__)


def rule_to_json(rule):
    """Normalize rule dictionary for JSON responses.

    Args:
        rule: Rule dictionary from repository.

    Returns:
        JSON-safe dictionary.
    """
    data = dict(rule)
    data['enabled'] = bool(data['enabled'])
    return data


@api_bp.get('/health')
def health():
    """Return API health status.

    Args:
        None.

    Returns:
        JSON object with status field.
    """
    return jsonify({'status': 'ok'})


@api_bp.get('/rules')
def rules_index():
    """List firewall rules.

    Args:
        None.

    Returns:
        JSON object containing rule items.
    """
    items = [rule_to_json(rule) for rule in list_rules(current_app.config['DATABASE_PATH'])]
    return jsonify({'items': items})


@api_bp.post('/rules')
def rules_create():
    """Create a firewall rule from DSL text.

    Args:
        JSON body with name, dsl_text, enabled, and priority.

    Returns:
        Created rule JSON.
    """
    payload = request.get_json(force=True)
    try:
        parsed = RuleParser.parse(payload['dsl_text'])
    except (KeyError, RuleParserError) as exc:
        return jsonify({'error': str(exc)}), 400

    created = create_rule(
        current_app.config['DATABASE_PATH'],
        parsed,
        payload.get('name', 'unnamed rule'),
        payload.get('enabled', True),
        int(payload.get('priority', 100)),
        payload['dsl_text'],
    )
    return jsonify(rule_to_json(created)), 201


@api_bp.post('/rules/parse')
def rules_parse():
    """Parse DSL text without saving it.

    Args:
        JSON body with dsl_text.

    Returns:
        Parsed rule fields.
    """
    payload = request.get_json(force=True)
    try:
        parsed = RuleParser.parse(payload['dsl_text'])
    except (KeyError, RuleParserError) as exc:
        return jsonify({'error': str(exc)}), 400
    return jsonify(parsed.__dict__)
```

- [ ] **Step 5: Verify rule API tests pass**

Run:

```bash
cd /Users/bytedance/Desktop/keshe/backend
pytest tests/test_api.py -v
```

Expected: all tests pass.

- [ ] **Step 6: Commit repositories and rule API**

Run:

```bash
cd /Users/bytedance/Desktop/keshe
git add backend/app/repositories.py backend/app/api.py backend/tests/test_api.py
git commit -m "feat: add rule management api"
```

---

## Task 5: Stats, Logs, Settings, and Sniffer Control API

**Files:**
- Modify: `/Users/bytedance/Desktop/keshe/backend/app/repositories.py`
- Create: `/Users/bytedance/Desktop/keshe/backend/app/sniffer_service.py`
- Modify: `/Users/bytedance/Desktop/keshe/backend/app/api.py`
- Modify: `/Users/bytedance/Desktop/keshe/backend/tests/test_api.py`

- [ ] **Step 1: Add API tests for read endpoints**

Append to `/Users/bytedance/Desktop/keshe/backend/tests/test_api.py`:

```python

def test_stats_endpoint_returns_dashboard_numbers(client):
    response = client.get('/api/stats')
    assert response.status_code == 200
    data = response.get_json()
    assert set(data.keys()) == {'blocked_count', 'allowed_count', 'active_connections', 'enabled_rules'}


def test_settings_can_be_read_and_updated(client):
    get_response = client.get('/api/settings')
    assert get_response.status_code == 200
    assert 'interface' in get_response.get_json()

    put_response = client.put('/api/settings', json={'interface': 'eth0', 'update_batch_size': '5'})
    assert put_response.status_code == 200
    assert put_response.get_json()['interface'] == 'eth0'


def test_logs_endpoint_returns_empty_items(client):
    response = client.get('/api/logs')
    assert response.status_code == 200
    assert response.get_json() == {'items': []}
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
cd /Users/bytedance/Desktop/keshe/backend
pytest tests/test_api.py -v
```

Expected: FAIL because stats, settings, and logs endpoints are not implemented.

- [ ] **Step 3: Add repository functions**

Append to `/Users/bytedance/Desktop/keshe/backend/app/repositories.py`:

```python

def get_settings(database_path):
    """Read all settings as key-value dictionary.

    Args:
        database_path: SQLite database path.

    Returns:
        Dictionary of setting values by key.
    """
    conn = connect_db(database_path)
    try:
        rows = conn.execute('SELECT key, value FROM settings ORDER BY key').fetchall()
        return {row['key']: row['value'] for row in rows}
    finally:
        conn.close()


def update_settings(database_path, values):
    """Update existing settings.

    Args:
        database_path: SQLite database path.
        values: Dictionary of setting values.

    Returns:
        Updated settings dictionary.
    """
    now = datetime.utcnow().isoformat()
    conn = connect_db(database_path)
    try:
        for key, value in values.items():
            conn.execute('UPDATE settings SET value = ?, updated_at = ? WHERE key = ?', (str(value), now, key))
        conn.commit()
        return get_settings(database_path)
    finally:
        conn.close()


def list_logs(database_path):
    """List recent traffic logs.

    Args:
        database_path: SQLite database path.

    Returns:
        List of traffic log dictionaries.
    """
    conn = connect_db(database_path)
    try:
        rows = conn.execute('SELECT * FROM traffic_logs ORDER BY id DESC LIMIT 200').fetchall()
        return [row_to_dict(row) for row in rows]
    finally:
        conn.close()


def get_stats(database_path):
    """Calculate dashboard counters.

    Args:
        database_path: SQLite database path.

    Returns:
        Dictionary with blocked, allowed, active connection, and enabled rule counts.
    """
    conn = connect_db(database_path)
    try:
        blocked = conn.execute("SELECT COUNT(*) AS c FROM traffic_logs WHERE action = 'DENY'").fetchone()['c']
        allowed = conn.execute("SELECT COUNT(*) AS c FROM traffic_logs WHERE action = 'ALLOW'").fetchone()['c']
        enabled = conn.execute('SELECT COUNT(*) AS c FROM rules WHERE enabled = 1').fetchone()['c']
        active = conn.execute(
            "SELECT COUNT(*) AS c FROM (SELECT src_ip, dst_ip, src_port, dst_port, protocol FROM traffic_logs GROUP BY src_ip, dst_ip, src_port, dst_port, protocol)"
        ).fetchone()['c']
        return {
            'blocked_count': blocked,
            'allowed_count': allowed,
            'active_connections': active,
            'enabled_rules': enabled,
        }
    finally:
        conn.close()
```

- [ ] **Step 4: Add lightweight sniffer service stub**

Create `/Users/bytedance/Desktop/keshe/backend/app/sniffer_service.py`:

```python
class SnifferService:
    """Track Scapy sniffer state for API control.

    The first implementation keeps state only. Packet capture is added in a later task.
    """

    def __init__(self):
        """Create a stopped sniffer service.

        Args:
            None.

        Returns:
            None.
        """
        self.running = False

    def start(self):
        """Mark the sniffer as running.

        Args:
            None.

        Returns:
            Dictionary with running state.
        """
        self.running = True
        return {'running': self.running}

    def stop(self):
        """Mark the sniffer as stopped.

        Args:
            None.

        Returns:
            Dictionary with running state.
        """
        self.running = False
        return {'running': self.running}
```

- [ ] **Step 5: Extend API routes**

Add imports to `/Users/bytedance/Desktop/keshe/backend/app/api.py`:

```python
from app.repositories import get_settings, get_stats, list_logs, update_settings
from app.sniffer_service import SnifferService
```

Add module-level service after blueprint creation:

```python
sniffer_service = SnifferService()
```

Append routes:

```python
@api_bp.get('/stats')
def stats():
    """Return dashboard counters.

    Args:
        None.

    Returns:
        Dashboard statistics JSON.
    """
    return jsonify(get_stats(current_app.config['DATABASE_PATH']))


@api_bp.get('/logs')
def logs_index():
    """Return recent traffic logs.

    Args:
        None.

    Returns:
        JSON object with log items.
    """
    return jsonify({'items': list_logs(current_app.config['DATABASE_PATH'])})


@api_bp.get('/settings')
def settings_index():
    """Return system settings.

    Args:
        None.

    Returns:
        Settings dictionary.
    """
    return jsonify(get_settings(current_app.config['DATABASE_PATH']))


@api_bp.put('/settings')
def settings_update():
    """Update system settings.

    Args:
        JSON body containing setting keys and values.

    Returns:
        Updated settings dictionary.
    """
    payload = request.get_json(force=True)
    return jsonify(update_settings(current_app.config['DATABASE_PATH'], payload))


@api_bp.post('/sniffer/start')
def sniffer_start():
    """Start sniffer state.

    Args:
        None.

    Returns:
        Running state JSON.
    """
    return jsonify(sniffer_service.start())


@api_bp.post('/sniffer/stop')
def sniffer_stop():
    """Stop sniffer state.

    Args:
        None.

    Returns:
        Running state JSON.
    """
    return jsonify(sniffer_service.stop())
```

- [ ] **Step 6: Verify API tests pass**

Run:

```bash
cd /Users/bytedance/Desktop/keshe/backend
pytest tests/test_api.py -v
```

Expected: all tests pass.

- [ ] **Step 7: Commit read APIs**

Run:

```bash
cd /Users/bytedance/Desktop/keshe
git add backend/app/repositories.py backend/app/sniffer_service.py backend/app/api.py backend/tests/test_api.py
git commit -m "feat: add stats logs settings api"
```

---


## Task 5A: Rule Update Service and Apply Endpoint

**Files:**
- Create: `/Users/bytedance/Desktop/keshe/backend/app/update_service.py`
- Modify: `/Users/bytedance/Desktop/keshe/backend/app/repositories.py`
- Modify: `/Users/bytedance/Desktop/keshe/backend/app/api.py`
- Modify: `/Users/bytedance/Desktop/keshe/backend/tests/test_api.py`

- [ ] **Step 1: Add apply endpoint test**

Append to `/Users/bytedance/Desktop/keshe/backend/tests/test_api.py`:

```python

def test_apply_rules_returns_generated_commands(client):
    client.post('/api/rules', json={
        'name': 'block dns',
        'dsl_text': 'DENY OUT UDP FROM ANY TO 8.8.8.8 SPORT ANY DPORT 53',
        'enabled': True,
        'priority': 10,
    })
    response = client.post('/api/rules/apply', json={'dry_run': True})
    assert response.status_code == 200
    data = response.get_json()
    assert data['applied_count'] == 1
    assert data['results'][0]['command'] == [
        'iptables', '-A', 'OUTPUT', '-p', 'udp', '-d', '8.8.8.8', '--dport', '53', '-j', 'DROP'
    ]
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
cd /Users/bytedance/Desktop/keshe/backend
pytest tests/test_api.py::test_apply_rules_returns_generated_commands -v
```

Expected: FAIL because `/api/rules/apply` is not implemented.

- [ ] **Step 3: Add enabled-rule repository function**

Append to `/Users/bytedance/Desktop/keshe/backend/app/repositories.py`:

```python

def list_enabled_rules(database_path):
    """List enabled firewall rules ordered by priority.

    Args:
        database_path: SQLite database path.

    Returns:
        List of enabled rule dictionaries.
    """
    conn = connect_db(database_path)
    try:
        rows = conn.execute('SELECT * FROM rules WHERE enabled = 1 ORDER BY priority ASC, id ASC').fetchall()
        return [row_to_dict(row) for row in rows]
    finally:
        conn.close()
```

- [ ] **Step 4: Implement update service**

Create `/Users/bytedance/Desktop/keshe/backend/app/update_service.py`:

```python
from app.iptables_adapter import IptablesAdapter
from app.models import FirewallRule
from app.repositories import list_enabled_rules


def dict_to_rule(row):
    """Convert a database rule row into FirewallRule.

    Args:
        row: Rule dictionary from SQLite.

    Returns:
        FirewallRule object.
    """
    return FirewallRule(
        row['action'], row['direction'], row['protocol'], row['src_ip'], row['dst_ip'], row['src_port'], row['dst_port']
    )


class RuleUpdateService:
    """Apply enabled project rules through the iptables adapter."""

    def __init__(self, database_path):
        """Create service.

        Args:
            database_path: SQLite database path.

        Returns:
            None.
        """
        self.database_path = database_path

    def apply_enabled_rules(self, dry_run=True):
        """Apply all enabled rules in priority order.

        Args:
            dry_run: When true, generate commands without executing them.

        Returns:
            Dictionary containing applied count and command results.
        """
        results = []
        for row in list_enabled_rules(self.database_path):
            command = IptablesAdapter.build_rule_command(dict_to_rule(row))
            results.append(IptablesAdapter.run(command, dry_run=dry_run))
        return {'applied_count': len(results), 'results': results}
```

- [ ] **Step 5: Add apply route**

Append to `/Users/bytedance/Desktop/keshe/backend/app/api.py` imports:

```python
from app.update_service import RuleUpdateService
```

Append route:

```python
@api_bp.post('/rules/apply')
def rules_apply():
    """Apply enabled firewall rules.

    Args:
        JSON body may contain dry_run boolean.

    Returns:
        Apply result with generated or executed commands.
    """
    payload = request.get_json(silent=True) or {}
    service = RuleUpdateService(current_app.config['DATABASE_PATH'])
    return jsonify(service.apply_enabled_rules(dry_run=payload.get('dry_run', True)))
```

- [ ] **Step 6: Verify apply endpoint**

Run:

```bash
cd /Users/bytedance/Desktop/keshe/backend
pytest tests/test_api.py::test_apply_rules_returns_generated_commands -v
```

Expected: PASS.

- [ ] **Step 7: Commit update service**

Run:

```bash
cd /Users/bytedance/Desktop/keshe
git add backend/app/update_service.py backend/app/repositories.py backend/app/api.py backend/tests/test_api.py
git commit -m "feat: add firewall rule apply service"
```

---

## Task 5B: Scapy Packet Conversion and Recent Traffic API

**Files:**
- Modify: `/Users/bytedance/Desktop/keshe/backend/app/sniffer_service.py`
- Modify: `/Users/bytedance/Desktop/keshe/backend/app/repositories.py`
- Modify: `/Users/bytedance/Desktop/keshe/backend/app/api.py`
- Create: `/Users/bytedance/Desktop/keshe/backend/tests/test_sniffer_service.py`

- [ ] **Step 1: Add packet conversion test**

Create `/Users/bytedance/Desktop/keshe/backend/tests/test_sniffer_service.py`:

```python
from app.sniffer_service import packet_to_record


def test_packet_to_record_extracts_tcp_fields():
    from scapy.all import IP, TCP

    packet = IP(src='10.0.0.1', dst='10.0.0.2') / TCP(sport=12345, dport=80)
    record = packet_to_record(packet, 'OUT')
    assert record['src_ip'] == '10.0.0.1'
    assert record['dst_ip'] == '10.0.0.2'
    assert record['src_port'] == '12345'
    assert record['dst_port'] == '80'
    assert record['protocol'] == 'TCP'
    assert record['direction'] == 'OUT'
```

- [ ] **Step 2: Run conversion test to verify failure**

Run:

```bash
cd /Users/bytedance/Desktop/keshe/backend
pytest tests/test_sniffer_service.py -v
```

Expected: FAIL because `packet_to_record` is not implemented.

- [ ] **Step 3: Implement packet conversion**

Replace `/Users/bytedance/Desktop/keshe/backend/app/sniffer_service.py` with:

```python
from scapy.all import ICMP, IP, TCP, UDP


def packet_to_record(packet, direction):
    """Convert a Scapy packet into a traffic log record.

    Args:
        packet: Scapy packet containing an IPv4 layer.
        direction: IN or OUT.

    Returns:
        Dictionary with packet fields used by logs and charts.
    """
    if IP not in packet:
        return None
    protocol = 'OTHER'
    src_port = 'ANY'
    dst_port = 'ANY'
    if TCP in packet:
        protocol = 'TCP'
        src_port = str(packet[TCP].sport)
        dst_port = str(packet[TCP].dport)
    elif UDP in packet:
        protocol = 'UDP'
        src_port = str(packet[UDP].sport)
        dst_port = str(packet[UDP].dport)
    elif ICMP in packet:
        protocol = 'ICMP'

    return {
        'src_ip': packet[IP].src,
        'dst_ip': packet[IP].dst,
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': protocol,
        'direction': direction,
        'packet_len': len(packet),
    }


class SnifferService:
    """Track Scapy sniffer state for API control."""

    def __init__(self):
        """Create a stopped sniffer service.

        Args:
            None.

        Returns:
            None.
        """
        self.running = False

    def start(self):
        """Mark the sniffer as running.

        Args:
            None.

        Returns:
            Dictionary with running state.
        """
        self.running = True
        return {'running': self.running}

    def stop(self):
        """Mark the sniffer as stopped.

        Args:
            None.

        Returns:
            Dictionary with running state.
        """
        self.running = False
        return {'running': self.running}
```

- [ ] **Step 4: Add recent traffic route**

Append to `/Users/bytedance/Desktop/keshe/backend/app/api.py`:

```python
@api_bp.get('/traffic/recent')
def traffic_recent():
    """Return recent traffic records.

    Args:
        None.

    Returns:
        JSON object with recent traffic items.
    """
    return jsonify({'items': list_logs(current_app.config['DATABASE_PATH'])})
```

- [ ] **Step 5: Verify sniffer conversion**

Run:

```bash
cd /Users/bytedance/Desktop/keshe/backend
pytest tests/test_sniffer_service.py -v
```

Expected: PASS.

- [ ] **Step 6: Commit sniffer conversion**

Run:

```bash
cd /Users/bytedance/Desktop/keshe
git add backend/app/sniffer_service.py backend/app/api.py backend/tests/test_sniffer_service.py
git commit -m "feat: add scapy packet conversion"
```

---
## Task 6: Frontend Scaffold and Page Layout

**Files:**
- Create frontend files listed in File Structure.

- [ ] **Step 1: Create package and Vite config**

Create `/Users/bytedance/Desktop/keshe/frontend/package.json`:

```json
{
  "scripts": {
    "dev": "vite --host 0.0.0.0",
    "build": "vite build"
  },
  "dependencies": {
    "@vitejs/plugin-vue": "latest",
    "axios": "latest",
    "echarts": "latest",
    "vite": "latest",
    "vue": "latest",
    "vue-router": "latest"
  },
  "devDependencies": {}
}
```

Create `/Users/bytedance/Desktop/keshe/frontend/vite.config.js`:

```javascript
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:5000'
    }
  }
})
```

- [ ] **Step 2: Create Vue entry files**

Create `/Users/bytedance/Desktop/keshe/frontend/index.html`:

```html
<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>简易防火墙管理系统</title>
  </head>
  <body>
    <div id="app"></div>
    <script type="module" src="/src/main.js"></script>
  </body>
</html>
```

Create `/Users/bytedance/Desktop/keshe/frontend/src/main.js`:

```javascript
import { createApp } from 'vue'
import App from './App.vue'
import router from './router'
import './assets/styles.css'

createApp(App).use(router).mount('#app')
```

- [ ] **Step 3: Create router and API client**

Create `/Users/bytedance/Desktop/keshe/frontend/src/router.js`:

```javascript
import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from './pages/Dashboard.vue'
import Rules from './pages/Rules.vue'
import Monitor from './pages/Monitor.vue'
import Logs from './pages/Logs.vue'
import Settings from './pages/Settings.vue'

const routes = [
  { path: '/', component: Dashboard },
  { path: '/rules', component: Rules },
  { path: '/monitor', component: Monitor },
  { path: '/logs', component: Logs },
  { path: '/settings', component: Settings }
]

export default createRouter({ history: createWebHistory(), routes })
```

Create `/Users/bytedance/Desktop/keshe/frontend/src/api/client.js`:

```javascript
import axios from 'axios'

export const api = axios.create({ baseURL: '/api', timeout: 5000 })
```

- [ ] **Step 4: Create shell layout and styles**

Create `/Users/bytedance/Desktop/keshe/frontend/src/App.vue`:

```vue
<template>
  <div class="layout">
    <aside class="sidebar">
      <h1>简易防火墙</h1>
      <RouterLink to="/">首页概览</RouterLink>
      <RouterLink to="/rules">规则管理</RouterLink>
      <RouterLink to="/monitor">抓包监控</RouterLink>
      <RouterLink to="/logs">日志审计</RouterLink>
      <RouterLink to="/settings">系统设置</RouterLink>
    </aside>
    <main class="content">
      <RouterView />
    </main>
  </div>
</template>
```

Create `/Users/bytedance/Desktop/keshe/frontend/src/assets/styles.css`:

```css
* { box-sizing: border-box; }
body { margin: 0; font-family: Arial, "Microsoft YaHei", sans-serif; background: #f3f4f6; color: #111827; }
.layout { min-height: 100vh; display: flex; }
.sidebar { width: 220px; background: #111827; color: white; padding: 20px; }
.sidebar h1 { font-size: 20px; margin: 0 0 24px; }
.sidebar a { display: block; color: #d1d5db; text-decoration: none; padding: 10px 12px; border-radius: 8px; margin-bottom: 8px; }
.sidebar a.router-link-active, .sidebar a:hover { background: #2563eb; color: white; }
.content { flex: 1; padding: 24px; }
.page-title { margin: 0 0 18px; }
.grid { display: grid; gap: 16px; }
.cards { grid-template-columns: repeat(4, minmax(140px, 1fr)); }
.card, .panel { background: white; border-radius: 14px; padding: 18px; box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08); }
.metric { font-size: 28px; font-weight: 700; margin-top: 8px; }
button { border: 0; border-radius: 8px; padding: 8px 12px; background: #2563eb; color: white; cursor: pointer; }
input, select, textarea { width: 100%; border: 1px solid #d1d5db; border-radius: 8px; padding: 8px; }
table { width: 100%; border-collapse: collapse; background: white; border-radius: 12px; overflow: hidden; }
th, td { padding: 10px; border-bottom: 1px solid #e5e7eb; text-align: left; }
```

- [ ] **Step 5: Create initial route pages**

Create `/Users/bytedance/Desktop/keshe/frontend/src/pages/Dashboard.vue`:

```vue
<template>
  <section>
    <h2 class="page-title">首页概览</h2>
    <div class="grid cards">
      <div class="card"><div>拦截次数</div><div class="metric">{{ stats.blocked_count }}</div></div>
      <div class="card"><div>放行次数</div><div class="metric">{{ stats.allowed_count }}</div></div>
      <div class="card"><div>活跃连接</div><div class="metric">{{ stats.active_connections }}</div></div>
      <div class="card"><div>启用规则</div><div class="metric">{{ stats.enabled_rules }}</div></div>
    </div>
    <div class="grid" style="grid-template-columns: 2fr 1fr; margin-top: 16px;">
      <div ref="lineRef" class="panel" style="height: 340px;"></div>
      <div ref="pieRef" class="panel" style="height: 340px;"></div>
    </div>
  </section>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import * as echarts from 'echarts'
import { api } from '../api/client'

const stats = reactive({ blocked_count: 0, allowed_count: 0, active_connections: 0, enabled_rules: 0 })
const lineRef = ref(null)
const pieRef = ref(null)

async function loadStats() {
  const response = await api.get('/stats')
  Object.assign(stats, response.data)
}

onMounted(async () => {
  await loadStats()
  echarts.init(lineRef.value).setOption({ xAxis: { type: 'category', data: ['1', '2', '3'] }, yAxis: {}, series: [{ type: 'line', data: [0, stats.allowed_count, stats.blocked_count] }] })
  echarts.init(pieRef.value).setOption({ series: [{ type: 'pie', data: [{ name: 'ALLOW', value: stats.allowed_count }, { name: 'DENY', value: stats.blocked_count }] }] })
  setInterval(loadStats, 2000)
})
</script>
```

Create `/Users/bytedance/Desktop/keshe/frontend/src/pages/Rules.vue`:

```vue
<template><section><h2 class="page-title">规则管理</h2><div class="panel">规则配置页面已加载</div></section></template>
```

Create `/Users/bytedance/Desktop/keshe/frontend/src/pages/Monitor.vue`:

```vue
<template><section><h2 class="page-title">抓包监控</h2><div class="panel">抓包监控页面已加载</div></section></template>
```

Create `/Users/bytedance/Desktop/keshe/frontend/src/pages/Logs.vue`:

```vue
<template><section><h2 class="page-title">日志审计</h2><div class="panel">日志审计页面已加载</div></section></template>
```

Create `/Users/bytedance/Desktop/keshe/frontend/src/pages/Settings.vue`:

```vue
<template><section><h2 class="page-title">系统设置</h2><div class="panel">系统设置页面已加载</div></section></template>
```

- [ ] **Step 6: Install and build frontend**

Run:

```bash
cd /Users/bytedance/Desktop/keshe/frontend
npm install
npm run build
```

Expected: Vite build succeeds and creates `/Users/bytedance/Desktop/keshe/frontend/dist`.

- [ ] **Step 7: Commit frontend scaffold**

Run:

```bash
cd /Users/bytedance/Desktop/keshe
git add frontend
git commit -m "feat: add vue firewall dashboard scaffold"
```

---

## Task 7: Complete Functional Frontend Pages

**Files:**
- Modify: `/Users/bytedance/Desktop/keshe/frontend/src/pages/Rules.vue`
- Modify: `/Users/bytedance/Desktop/keshe/frontend/src/pages/Monitor.vue`
- Modify: `/Users/bytedance/Desktop/keshe/frontend/src/pages/Logs.vue`
- Modify: `/Users/bytedance/Desktop/keshe/frontend/src/pages/Settings.vue`

- [ ] **Step 1: Implement Rules page**

Create `/Users/bytedance/Desktop/keshe/frontend/src/pages/Rules.vue`:

```vue
<template>
  <section>
    <h2 class="page-title">规则管理</h2>
    <div class="panel">
      <textarea v-model="dslText" rows="3"></textarea>
      <button @click="parseRule">解析规则</button>
      <button @click="saveRule">保存规则</button>
      <pre>{{ parsed }}</pre>
    </div>
    <table style="margin-top:16px">
      <thead><tr><th>ID</th><th>名称</th><th>动作</th><th>方向</th><th>协议</th><th>源</th><th>目标</th></tr></thead>
      <tbody><tr v-for="rule in rules" :key="rule.id"><td>{{ rule.id }}</td><td>{{ rule.name }}</td><td>{{ rule.action }}</td><td>{{ rule.direction }}</td><td>{{ rule.protocol }}</td><td>{{ rule.src_ip }}</td><td>{{ rule.dst_ip }}</td></tr></tbody>
    </table>
  </section>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { api } from '../api/client'

const dslText = ref('DENY OUT UDP FROM ANY TO 8.8.8.8 SPORT ANY DPORT 53')
const parsed = ref('')
const rules = ref([])

async function loadRules() {
  const response = await api.get('/rules')
  rules.value = response.data.items
}

async function parseRule() {
  const response = await api.post('/rules/parse', { dsl_text: dslText.value })
  parsed.value = JSON.stringify(response.data, null, 2)
}

async function saveRule() {
  await api.post('/rules', { name: '页面新增规则', dsl_text: dslText.value, enabled: true, priority: 100 })
  await loadRules()
}

onMounted(loadRules)
</script>
```

- [ ] **Step 2: Implement Monitor page**

Create `/Users/bytedance/Desktop/keshe/frontend/src/pages/Monitor.vue`:

```vue
<template>
  <section>
    <h2 class="page-title">抓包监控</h2>
    <div class="panel">
      <button @click="startSniffer">启动抓包</button>
      <button @click="stopSniffer">停止抓包</button>
      <p>运行状态：{{ running ? '运行中' : '已停止' }}</p>
    </div>
  </section>
</template>

<script setup>
import { ref } from 'vue'
import { api } from '../api/client'

const running = ref(false)

async function startSniffer() {
  const response = await api.post('/sniffer/start')
  running.value = response.data.running
}

async function stopSniffer() {
  const response = await api.post('/sniffer/stop')
  running.value = response.data.running
}
</script>
```

- [ ] **Step 3: Implement Logs page**

Create `/Users/bytedance/Desktop/keshe/frontend/src/pages/Logs.vue`:

```vue
<template>
  <section>
    <h2 class="page-title">日志审计</h2>
    <button @click="loadLogs">刷新日志</button>
    <table style="margin-top:16px">
      <thead><tr><th>时间</th><th>源 IP</th><th>目标 IP</th><th>协议</th><th>动作</th><th>原因</th></tr></thead>
      <tbody><tr v-for="log in logs" :key="log.id"><td>{{ log.timestamp }}</td><td>{{ log.src_ip }}</td><td>{{ log.dst_ip }}</td><td>{{ log.protocol }}</td><td>{{ log.action }}</td><td>{{ log.reason }}</td></tr></tbody>
    </table>
  </section>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { api } from '../api/client'

const logs = ref([])

async function loadLogs() {
  const response = await api.get('/logs')
  logs.value = response.data.items
}

onMounted(loadLogs)
</script>
```

- [ ] **Step 4: Implement Settings page**

Create `/Users/bytedance/Desktop/keshe/frontend/src/pages/Settings.vue`:

```vue
<template>
  <section>
    <h2 class="page-title">系统设置</h2>
    <div class="panel grid">
      <label>网卡名称 <input v-model="settings.interface" /></label>
      <label>更新模式 <select v-model="settings.update_mode"><option value="immediate">立即更新</option><option value="timed">按时间更新</option><option value="counted">按数量更新</option></select></label>
      <label>时间间隔 <input v-model="settings.update_interval" /></label>
      <label>数量阈值 <input v-model="settings.update_batch_size" /></label>
      <button @click="saveSettings">保存设置</button>
    </div>
  </section>
</template>

<script setup>
import { onMounted, reactive } from 'vue'
import { api } from '../api/client'

const settings = reactive({ interface: 'any', update_mode: 'immediate', update_interval: '30', update_batch_size: '3' })

async function loadSettings() {
  const response = await api.get('/settings')
  Object.assign(settings, response.data)
}

async function saveSettings() {
  const response = await api.put('/settings', settings)
  Object.assign(settings, response.data)
}

onMounted(loadSettings)
</script>
```

- [ ] **Step 5: Build frontend**

Run:

```bash
cd /Users/bytedance/Desktop/keshe/frontend
npm run build
```

Expected: Vite build succeeds.

- [ ] **Step 6: Commit functional pages**

Run:

```bash
cd /Users/bytedance/Desktop/keshe
git add frontend/src/pages
git commit -m "feat: add firewall management pages"
```

---

## Task 8: Project Documentation

**Files:**
- Create: `/Users/bytedance/Desktop/keshe/README.md`
- Create: `/Users/bytedance/Desktop/keshe/docs/功能目标分解表.md`
- Create: `/Users/bytedance/Desktop/keshe/docs/规则语言说明.md`
- Create: `/Users/bytedance/Desktop/keshe/docs/课程设计报告.md`

- [ ] **Step 1: Write README**

Create `/Users/bytedance/Desktop/keshe/README.md` with installation and run commands:

```markdown
# 简易防火墙管理系统

本项目使用 Vue3、Flask、SQLite、Scapy 和 iptables 实现简易 Linux 防火墙管理系统。

## 后端运行

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

## 前端运行

```bash
cd frontend
npm install
npm run dev
```

## Linux 真实拦截说明

应用 iptables 规则和 Scapy 抓包需要 root 或 sudo 权限。测试前建议在虚拟机中运行，避免影响本机网络。
```

- [ ] **Step 2: Write 功能目标分解表**

Create `/Users/bytedance/Desktop/keshe/docs/功能目标分解表.md`:

```markdown
# 功能目标分解表

| 题目要求 | 系统功能 | 实现模块 |
|---|---|---|
| 可配置、可显示系统运行结果 | Web 管理界面、首页概览 | Vue3 页面、Flask API |
| 自定义规则语言和解析器 | DSL 规则输入与解析 | rule_parser.py |
| 涉及 IP、端口、协议 | 规则字段覆盖源/目标 IP、端口、协议 | rules 表、RuleParser |
| 立即更新 | 保存后立即应用 | update_service.py、iptables_adapter.py |
| 时间定量更新 | 定时批量应用 | settings 表、后台更新服务 |
| 数量定量更新 | 达到阈值批量应用 | rule_updates 表 |
| 图表动态展示 | 流量折线图、协议饼图 | Dashboard.vue、ECharts |
| 日志记录与分析 | 拦截/放行日志、系统日志 | SQLite、Logs.vue |
| 运行结果存入数据库 | 规则、日志、配置入库 | db.py、repositories.py |
```

- [ ] **Step 3: Write DSL guide**

Create `/Users/bytedance/Desktop/keshe/docs/规则语言说明.md`:

```markdown
# 规则语言说明

## 语法

```txt
ACTION DIRECTION PROTOCOL FROM SRC_IP TO DST_IP SPORT SRC_PORT DPORT DST_PORT
```

## 示例

```txt
DENY OUT UDP FROM ANY TO 8.8.8.8 SPORT ANY DPORT 53
ALLOW IN TCP FROM ANY TO ANY SPORT ANY DPORT 22
DENY IN ICMP FROM 10.0.0.5 TO ANY
```

## 字段

- ACTION：ALLOW 或 DENY。
- DIRECTION：IN 或 OUT。
- PROTOCOL：TCP、UDP、ICMP 或 ANY。
- SRC_IP / DST_IP：IPv4、CIDR 或 ANY。
- SRC_PORT / DST_PORT：端口、端口范围或 ANY。
```

- [ ] **Step 4: Write course report draft**

Create `/Users/bytedance/Desktop/keshe/docs/课程设计报告.md` with sections:

```markdown
# 简易防火墙课程设计报告

## 1. 选题背景与目标

本系统面向 Linux 主机网络安全管理，提供规则配置、规则解析、流量监控、日志审计和运行结果图表展示。

## 2. 需求分析

系统需要支持 Web 配置、自定义规则语言、立即更新、按时间更新、按数量更新、运行日志记录和数据库存储。

## 3. 总体设计

系统采用 Vue3 前端和 Flask 后端分离架构。后端使用 SQLite 存储数据，使用 Scapy 监听网络流量，使用 iptables 应用防火墙规则。

## 4. 规则语言设计

规则语言包含动作、方向、协议、源 IP、目标 IP、源端口和目标端口。

## 5. 数据库设计

数据库包含 rules、rule_updates、traffic_logs、system_logs 和 settings 五张核心表。

## 6. 核心模块实现

核心模块包括规则解析器、规则管理接口、iptables 适配器、抓包监控服务、日志审计服务和前端图表页面。

## 7. 测试与结果分析

测试覆盖规则解析、规则增删改查、iptables 命令生成、前端页面构建和 Linux 环境下的拦截验证。

## 8. 总结

本系统实现了简易防火墙的核心功能，能够通过图形化界面完成规则管理、运行监控和日志审计。
```

- [ ] **Step 5: Commit documentation**

Run:

```bash
cd /Users/bytedance/Desktop/keshe
git add README.md docs/功能目标分解表.md docs/规则语言说明.md docs/课程设计报告.md
git commit -m "docs: add firewall course documentation"
```

---

## Task 9: Final Verification

**Files:**
- Verify all created files.

- [ ] **Step 1: Run backend tests**

Run:

```bash
cd /Users/bytedance/Desktop/keshe/backend
pytest -v
```

Expected: all backend tests pass.

- [ ] **Step 2: Build frontend**

Run:

```bash
cd /Users/bytedance/Desktop/keshe/frontend
npm run build
```

Expected: build succeeds.

- [ ] **Step 3: Start backend for manual check**

Run:

```bash
cd /Users/bytedance/Desktop/keshe/backend
python run.py
```

Expected: Flask listens on `http://127.0.0.1:5000` and `GET /api/health` returns `{"status":"ok"}`.

- [ ] **Step 4: Start frontend for manual check**

Run in another terminal:

```bash
cd /Users/bytedance/Desktop/keshe/frontend
npm run dev
```

Expected: Vite listens on `http://127.0.0.1:5173` and sidebar pages render.

- [ ] **Step 5: Linux iptables dry-run and real-run review**

Use the backend parser and adapter tests as dry-run proof. On Linux VM, after user approval for sudo operations, create one outbound DNS deny rule from UI and verify generated command matches:

```bash
iptables -A OUTPUT -p udp -d 8.8.8.8 --dport 53 -j DROP
```

Expected: `dig @8.8.8.8 example.com` fails while the rule is active, then succeeds after rule removal.

- [ ] **Step 6: Commit verification fixes if any**

If verification required code changes, run:

```bash
cd /Users/bytedance/Desktop/keshe
git add backend frontend docs README.md
git commit -m "fix: resolve firewall verification issues"
```

---

## Coverage Self-Review

- Spec 2.1 Linux target and INPUT/OUTPUT scope: covered by Task 3 and Task 9.
- Spec 2.2 full deliverables: covered by Tasks 1 through 8.
- Spec 4 frontend pages: covered by Tasks 6 and 7.
- Spec 5 DSL parser: covered by Task 2.
- Spec 6 update mechanisms: covered by database/settings in Tasks 1 and 5 plus apply service in Task 5A. Timed and counted modes use stored settings and the apply endpoint as the first simple batch mechanism.
- Spec 7 API list: core endpoints covered by Tasks 1, 4, 5, 5A, and 5B.
- Spec 8 database schema: covered by Task 1.
- Spec 9 testing: covered by Tasks 2, 3, 4, 5, and 9.
- Spec 10 documentation: covered by Task 8.
- Simplicity and modularity: reflected in focused backend modules and separated frontend pages.
