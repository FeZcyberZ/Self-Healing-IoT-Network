import os
import sys
import time
import json
import hashlib
import getpass
import socket
import argparse
import threading

from dataclasses import dataclass, field
from collections import deque
from typing import Optional, Dict, Tuple, Any, Deque, List

import paho.mqtt.client as mqtt


# Config
MQTT_HOST = os.getenv("MQTT_HOST", "10.42.0.1")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
BROKER_USER = os.getenv("MQTT_USER", "")
BROKER_PASS = os.getenv("MQTT_PASS", "")

# MQTT topic patterns for subscribing to all nodes
STATUS_SUB = os.getenv("STATUS_SUB", "mesh/+/status")
TELEMETRY_SUB = os.getenv("TELEMETRY_SUB", "mesh/+/telemetry")

# Topic formats for publishing commands to individual nodes
CMD_TOPIC_FMT = os.getenv("CMD_TOPIC_FMT", "mesh/{node}/cmd/state")
ROUTE_CMD_TOPIC = os.getenv("ROUTE_CMD_TOPIC", "mesh/route/cmd")
ROUTE_NODE_CMD_FMT = os.getenv("ROUTE_NODE_CMD_FMT", "mesh/{node}/cmd/route")

# Detection and timing parameters
ROLLING_WINDOW_S = int(os.getenv("ROLLING_WINDOW", "10"))
ENGINE_TICK_S = float(os.getenv("ENGINE_TICK", "1.0"))
HEARTBEAT_INTERVAL_S = int(os.getenv("HEARTBEAT_INTERVAL", "5"))

# Quarantine timing parameters
QUARANTINE_TIME_S = int(os.getenv("QUARANTINE_TIME", "30"))
RECOVERY_TIME_S = int(os.getenv("RECOVERY_TIME", "10"))
QUARANTINE_VALIDATE_S = int(os.getenv("QUARANTINE_VALIDATE", str(ROLLING_WINDOW_S)))

# Risk score thresholds for state transitions
THRESH_SUSPECT = int(os.getenv("THRESH_SUSPECT", "5"))
THRESH_QUARANTINE = int(os.getenv("THRESH_QUARANTINE", "8"))

# Weights for each behavioural risk indicator
W_HEARTBEAT_LOSS = int(os.getenv("W_HEARTBEAT_LOSS", "3"))
W_MISSING_TELEMETRY = int(os.getenv("W_MISSING_TELEMETRY", "2"))
W_RATE = int(os.getenv("W_RATE", "8"))
W_RECONNECT = int(os.getenv("W_RECONNECT", "2"))
W_PACKET_ERROR = int(os.getenv("W_PACKET_ERROR", "1"))
W_MALFORMED = int(os.getenv("W_MALFORMED", "3"))

# Thresholds that trigger each risk indicator
EXPECTED_TELEMETRY_PER_WINDOW = int(os.getenv("EXPECTED_TELEMETRY_PER_WINDOW", "3"))
RATE_MULTIPLIER = int(os.getenv("RATE_MULTIPLIER", "2"))
RECONNECT_FLOOD_COUNT = int(os.getenv("RECONNECT_FLOOD_COUNT", "5"))
PACKET_ERROR_THRESHOLD = float(os.getenv("PACKET_ERROR_THRESHOLD", "0.15"))

# Ping validation parameters used during recovery
PING_TIMEOUT_S = int(os.getenv("PING_TIMEOUT", "5"))
PING_REQUIRED_OK = int(os.getenv("PING_REQUIRED_OK", "1"))

# How long before a silent node is marked offline
OFFLINE_AFTER_S = int(os.getenv("OFFLINE_AFTER_S", str(HEARTBEAT_INTERVAL_S * 3)))
OFFLINE_ACTION = os.getenv("OFFLINE_ACTION", "reroute").strip().lower()

# MQTT connection settings
MQTT_KEEPALIVE = int(os.getenv("MQTT_KEEPALIVE", "30"))
QOS_STATUS_SUB = int(os.getenv("QOS_STATUS_SUB", "1"))
QOS_TELEM_SUB = int(os.getenv("QOS_TELEM_SUB", "0"))
QOS_CMD_PUB = int(os.getenv("QOS_CMD_PUB", "1"))
QOS_ROUTE_PUB = int(os.getenv("QOS_ROUTE_PUB", "1"))

# Print node state every tick when enabled
PRINT_EVERY_TICK = os.getenv("PRINT_EVERY_TICK", "0") == "1"

# Log file paths
LOG_FILE = os.getenv("LOG_FILE", "behaviour_engine_log.jsonl")
CHAIN_LOG_FILE = os.getenv("CHAIN_LOG_FILE", "behaviour_engine_chain.jsonl")
CHAIN_STATE_FILE = os.getenv("CHAIN_STATE_FILE", "behaviour_engine_chain.state")

# Pre-register known nodes so they appear before any traffic arrives
EXPECTED_NODES = [x.strip() for x in os.getenv("EXPECTED_NODES", "").split(",") if x.strip()]

# Mosquitto dynamic security plugin settings for broker-level quarantine
DYNSEC_ENABLED = os.getenv("DYNSEC_ENABLED", "0") == "1"
DYNSEC_CTRL_TOPIC = os.getenv("DYNSEC_CTRL_TOPIC", "$CONTROL/dynamic-security/v1")
DYNSEC_RESP_TOPIC = os.getenv("DYNSEC_RESP_TOPIC", "$CONTROL/dynamic-security/v1/response")
DYNSEC_QUAR_ROLE = os.getenv("DYNSEC_QUAR_ROLE", "quarantined")


# Return current time as a float timestamp
def now_s() -> float:
    return time.time()


# Serialise a dict to compact JSON with sorted keys
def jdump(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


# Return SHA-256 hex digest of a bytes object
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# Remove timestamps from a deque that fall outside the rolling window
def prune_times(q: Deque[float], now: float, window_s: int):
    cutoff = now - window_s
    while q and q[0] < cutoff:
        q.popleft()


# Extract the node ID from a mesh topic string
def parse_node_from_topic(topic: str) -> Optional[str]:
    parts = topic.split("/")
    return parts[1] if len(parts) >= 3 and parts[0] == "mesh" else None


# Safely decode and parse a JSON payload, returning the object and any error
def safe_json_loads(payload: bytes) -> Tuple[Optional[Any], Optional[str]]:
    try:
        return json.loads(payload.decode("utf-8", errors="replace")), None
    except Exception as e:
        return None, str(e)


# Append-only hash-chained log for tamper-evident event recording
class HashChain:
    def __init__(self, chain_log: str, chain_state: str):
        self.chain_log = chain_log
        self.chain_state = chain_state
        self.prev = "0" * 64
        self.seq = 0
        self._load_state()

    # Load previous hash and sequence number from the state file
    def _load_state(self):
        try:
            with open(self.chain_state, "r", encoding="utf-8") as f:
                state = json.load(f)
            self.prev = state.get("prev_hash", self.prev)
            self.seq = int(state.get("seq", self.seq))
        except FileNotFoundError:
            pass
        except Exception:
            self.prev = "0" * 64
            self.seq = 0

    # Persist current hash and sequence number to the state file
    def _save_state(self):
        with open(self.chain_state, "w", encoding="utf-8") as f:
            json.dump({"prev_hash": self.prev, "seq": self.seq}, f)

    # Append a new record to the chain log and update the state
    def append(self, record: dict):
        self.seq += 1
        entry = {"seq": self.seq, "ts": now_s(), "prev_hash": self.prev, "record": record}
        raw = jdump(entry).encode("utf-8")
        entry["hash"] = sha256_hex(self.prev.encode("utf-8") + raw)

        with open(self.chain_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")

        self.prev = entry["hash"]
        self._save_state()


# Verify the integrity of the hash chain log file
def verify_chain(chain_log: str) -> Tuple[bool, str]:
    if not os.path.exists(chain_log):
        return False, f"Missing chain log: {chain_log}"

    prev = "0" * 64
    expected_seq = 1

    with open(chain_log, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
            except Exception:
                return False, f"Invalid JSON at line {line_no}"

            if entry.get("seq") != expected_seq:
                return False, f"Sequence break at line {line_no}"
            if entry.get("prev_hash") != prev:
                return False, f"Prev-hash mismatch at line {line_no}"

            h = entry.get("hash")
            if not isinstance(h, str) or len(h) != 64:
                return False, f"Bad hash at line {line_no}"

            entry_no_hash = {k: v for k, v in entry.items() if k != "hash"}
            raw = jdump(entry_no_hash).encode("utf-8")
            want = sha256_hex(prev.encode("utf-8") + raw)

            if want != h:
                return False, f"Hash mismatch at line {line_no}"

            prev = h
            expected_seq += 1

    return True, f"OK ({expected_seq - 1} entries verified)"


# Dataclass holding all state for a single monitored node
@dataclass
class Node:
    id: str
    state: str = "NORMAL"

    created_ts: float = field(default_factory=now_s)
    last_seen: float = 0.0
    last_heartbeat: float = 0.0
    seen_heartbeat: bool = False

    # Sliding window deques for rate-based indicators
    telemetry_ts: Deque[float] = field(default_factory=deque)
    status_ts: Deque[float] = field(default_factory=deque)
    connect_ts: Deque[float] = field(default_factory=deque)
    malformed_ts: Deque[float] = field(default_factory=deque)

    packet_error: Optional[float] = None
    last_telemetry: Dict[str, Any] = field(default_factory=dict)

    # Quarantine and recovery timing
    quarantine_until: float = 0.0
    quarantine_start: Optional[float] = None
    recovery_start: Optional[float] = None
    ping_outstanding: bool = False
    ping_sent_ts: float = 0.0
    ping_ok_count: int = 0

    # Offline tracking
    offline: bool = False
    offline_since: Optional[float] = None

    # Timestamps for first transition into each elevated state
    suspect_first_ts: Optional[float] = None
    quarantine_first_ts: Optional[float] = None
    quarantine_cmd_ts: Optional[float] = None
    restore_cmd_ts: Optional[float] = None


# Central behaviour engine — subscribes to MQTT, scores nodes and manages quarantine
class BehaviourEngine:
    def __init__(self, username: str, password: str, paho_log: bool):
        self.nodes: Dict[str, Node] = {}
        self.chain = HashChain(CHAIN_LOG_FILE, CHAIN_STATE_FILE)

        self.client_id = f"behaviour-engine-{socket.gethostname()}-{os.getpid()}"
        self.client = self._make_client(self.client_id)

        if username or password:
            self.client.username_pw_set(username, password)

        if paho_log:
            self.client.on_log = self.on_log

        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.on_disconnect = self.on_disconnect
        self.client.reconnect_delay_set(min_delay=1, max_delay=10)

        self._dynsec_lock = threading.Lock()
        self._dynsec_pending: Dict[str, dict] = {}

        self._events_lock = threading.Lock()
        self._events: Deque[dict] = deque(maxlen=3000)

        self._log_lock = threading.Lock()
        self._nodes_lock = threading.Lock()

        # Set log file permissions to owner-read-write only
        for p in (LOG_FILE, CHAIN_LOG_FILE, CHAIN_STATE_FILE):
            try:
                if not os.path.exists(p):
                    open(p, "a").close()
                os.chmod(p, 0o600)
            except OSError:
                pass

        # Pre-register any nodes listed in EXPECTED_NODES
        for nid in EXPECTED_NODES:
            self.get_node(nid, discovered_by="EXPECTED_LIST")

    # Create a PubSubClient compatible with both old and new paho APIs
    def _make_client(self, client_id: str):
        try:
            return mqtt.Client(
                client_id=client_id,
                protocol=mqtt.MQTTv311,
                callback_api_version=mqtt.CallbackAPIVersion.VERSION1
            )
        except Exception:
            return mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv311)

    # Write an event to the plain log, the hash chain and the in-memory event buffer
    def log(self, event: dict):
        event = dict(event)
        event.setdefault("ts", now_s())

        with self._log_lock:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, separators=(",", ":")) + "\n")
            self.chain.append(event)

        with self._events_lock:
            self._events.append(event)

    # Return the most recent n events from the in-memory buffer
    def tail_events(self, n: int = 200) -> List[dict]:
        with self._events_lock:
            return list(self._events)[-n:]

    # Send a dynamic security command to the broker
    def _dynsec_send(self, command: dict):
        if not DYNSEC_ENABLED:
            return

        with self._dynsec_lock:
            corr = f"{int(now_s() * 1000)}-{os.getpid()}-{len(self._dynsec_pending)}"
            msg = {**command, "correlationData": corr}
            self._dynsec_pending[corr] = {"sent": now_s(), "command": command}

        self.client.publish(DYNSEC_CTRL_TOPIC, json.dumps(msg), qos=1, retain=False)
        self.log({"event": "DYNSEC_CMD", "corr": corr, "cmd": command.get("command"), "payload": msg})

    # Restrict a quarantined node at the broker level via dynamic security
    def dynsec_quarantine(self, node_id: str):
        self._dynsec_send({"command": "addClientRole", "username": node_id, "rolename": DYNSEC_QUAR_ROLE})

    # Remove broker-level restrictions when a node is restored
    def dynsec_restore(self, node_id: str):
        self._dynsec_send({"command": "removeClientRole", "username": node_id, "rolename": DYNSEC_QUAR_ROLE})

    # Return an existing node or create a new one on first contact
    def get_node(self, node_id: str, discovered_by: str = "TRAFFIC") -> Node:
        with self._nodes_lock:
            node = self.nodes.get(node_id)
            if node is None:
                node = Node(node_id)
                self.nodes[node_id] = node
                new = True
            else:
                new = False
        if new:
            self.log({"event": "NODE_DISCOVERED", "node": node_id, "by": discovered_by})
            print(f"[ENGINE] DISCOVERED {node_id} by={discovered_by}", flush=True)
        return node

    # Publish a state command to a node's command topic
    def send_cmd(self, node_id: str, cmd: str):
        topic = CMD_TOPIC_FMT.format(node=node_id)
        info = self.client.publish(topic, cmd, qos=QOS_CMD_PUB, retain=False)
        self.log({"event": "CMD", "node": node_id, "cmd": cmd, "topic": topic, "mid": getattr(info, "mid", None)})
        print(f"[ENGINE] CMD {node_id} -> {cmd}", flush=True)

    # Publish a rerouting instruction to the route command topic and all peer nodes
    def send_route_cmd(self, kind: str, target_node: str):
        payload = {"type": kind, "node": target_node, "ts": now_s()}
        info = self.client.publish(ROUTE_CMD_TOPIC, json.dumps(payload), qos=QOS_ROUTE_PUB, retain=False)
        self.log({"event": "ROUTE_CMD", "kind": kind, "node": target_node, "topic": ROUTE_CMD_TOPIC, "mid": getattr(info, "mid", None)})

        with self._nodes_lock:
            node_ids = list(self.nodes.keys())

        for nid in node_ids:
            if nid == target_node:
                continue
            topic = ROUTE_NODE_CMD_FMT.format(node=nid)
            node_payload = {"type": kind, "avoid": target_node, "ts": now_s()}
            self.client.publish(topic, json.dumps(node_payload), qos=QOS_ROUTE_PUB, retain=False)
            self.log({"event": "ROUTE_NODE_HINT", "to": nid, "kind": kind, "avoid": target_node, "topic": topic})

        print(f"[ENGINE] ROUTE {kind} for {target_node}", flush=True)

    # Handle a status or heartbeat payload from a node
    def _handle_status_payload(self, node: Node, data: Any, now: float):
        node.last_heartbeat = now
        node.seen_heartbeat = True

        event = ""
        if isinstance(data, dict):
            if data.get("node") and data["node"] != node.id:
                return
            event = (data.get("event") or data.get("state") or "").upper()
        elif isinstance(data, str):
            event = data.strip().upper()

        if not event:
            return

        if event in {"ONLINE", "CONNECT", "CONNECTED", "BOOT"}:
            node.connect_ts.append(now)
            self.log({"event": "NODE_ONLINE", "node": node.id, "status": event})

        if event in {"PONG", "PING_OK", "ALIVE", "HB"} and node.ping_outstanding:
            node.ping_outstanding = False
            node.ping_ok_count += 1
            self.log({"event": "PING_OK", "node": node.id, "count": node.ping_ok_count, "kind": event})

    # Calculate the cumulative risk score and active indicators for a node
    def calculate_risk(self, node: Node, now: float) -> Tuple[int, dict]:
        for q in (node.telemetry_ts, node.status_ts, node.connect_ts, node.malformed_ts):
            prune_times(q, now, ROLLING_WINDOW_S)

        risk = 0
        ind: Dict[str, Any] = {}

        last_live = node.last_heartbeat if node.seen_heartbeat else node.last_seen
        hb_age = now - last_live if last_live > 0 else 0.0

        # Heartbeat loss indicator
        if last_live > 0 and hb_age >= HEARTBEAT_INTERVAL_S * 2:
            risk += W_HEARTBEAT_LOSS
            ind["heartbeat_loss"] = True
            ind["hb_age_s"] = round(hb_age, 1)

        # Missing telemetry indicator
        if node.last_seen > 0 and not node.telemetry_ts and hb_age >= HEARTBEAT_INTERVAL_S:
            risk += W_MISSING_TELEMETRY
            ind["missing_telemetry"] = True

        # Abnormal publish rate indicator
        if len(node.telemetry_ts) >= EXPECTED_TELEMETRY_PER_WINDOW * RATE_MULTIPLIER:
            risk += W_RATE
            ind["abnormal_rate"] = {"count": len(node.telemetry_ts)}

        # Reconnection flood indicator
        if len(node.connect_ts) >= RECONNECT_FLOOD_COUNT:
            risk += W_RECONNECT
            ind["reconnect_flood"] = {"count": len(node.connect_ts)}

        # Elevated packet error rate indicator
        if node.packet_error is not None and node.packet_error >= PACKET_ERROR_THRESHOLD:
            risk += W_PACKET_ERROR
            ind["packet_error"] = {"per": node.packet_error}

        # Malformed payload indicator
        if node.malformed_ts:
            risk += W_MALFORMED
            ind["malformed_payload"] = {"count": len(node.malformed_ts)}

        ind["offline"] = bool(last_live > 0 and hb_age >= OFFLINE_AFTER_S)
        ind["hb_age_s"] = round(hb_age, 1)
        return risk, ind

    # Update offline status and trigger rerouting when a node goes silent
    def update_offline(self, node: Node, ind: dict, now: float):
        offline = bool(ind.get("offline"))

        if offline and not node.offline:
            node.offline = True
            node.offline_since = now
            self.log({"event": "NODE_OFFLINE", "node": node.id, "since": now, "action": OFFLINE_ACTION})
            self.send_route_cmd("ROUTE_AVOID", node.id)

            if OFFLINE_ACTION == "quarantine":
                node.state = "QUARANTINED"
                node.quarantine_until = now + QUARANTINE_TIME_S
                node.quarantine_start = None
                self.send_cmd(node.id, "ISOLATE")
                node.quarantine_cmd_ts = now
                self.dynsec_quarantine(node.id)
                self.log({"event": "OFFLINE_QUARANTINE_ISSUED", "node": node.id})

        elif not offline and node.offline:
            was_since = node.offline_since
            node.offline = False
            node.offline_since = None
            self.log({"event": "NODE_ONLINE_AGAIN", "node": node.id, "offline_since": was_since})
            self.send_route_cmd("ROUTE_RESTORE", node.id)

    # Run the node state machine and issue quarantine or restore commands as needed
    def update_state(self, node: Node, risk: int, ind: dict, now: float):
        prev = node.state

        if risk >= THRESH_SUSPECT and node.suspect_first_ts is None:
            node.suspect_first_ts = now
            self.log({"event": "SUSPECT_FIRST", "node": node.id, "risk": risk, "indicators": ind})

        if node.state == "QUARANTINED":
            if now >= node.quarantine_until:
                node.state = "RECOVERING"
                node.recovery_start = now
                node.ping_outstanding = False
                node.ping_ok_count = 0
            else:
                return

        if node.state == "RECOVERING":
            if risk >= THRESH_QUARANTINE:
                node.state = "QUARANTINED"
                node.quarantine_until = now + QUARANTINE_TIME_S
                node.recovery_start = None
                node.ping_outstanding = False
                node.ping_ok_count = 0
                self.log({"event": "RECOVERY_FAILED_RISK", "node": node.id, "risk": risk, "indicators": ind})
                return

            if node.ping_ok_count < PING_REQUIRED_OK and not node.ping_outstanding:
                self.send_cmd(node.id, "PING")
                node.ping_outstanding = True
                node.ping_sent_ts = now
                self.log({"event": "PING_SENT", "node": node.id})

            if node.ping_outstanding and (now - node.ping_sent_ts) > PING_TIMEOUT_S:
                self.log({"event": "PING_TIMEOUT", "node": node.id})
                node.state = "QUARANTINED"
                node.quarantine_until = now + QUARANTINE_TIME_S
                node.recovery_start = None
                node.ping_outstanding = False
                node.ping_ok_count = 0
                return

            if node.ping_ok_count >= PING_REQUIRED_OK and node.recovery_start is not None:
                if risk < THRESH_SUSPECT and (now - node.recovery_start) >= RECOVERY_TIME_S:
                    node.state = "NORMAL"

        if node.state in {"NORMAL", "SUSPECT", "RECOVERING"}:
            if risk >= THRESH_QUARANTINE:
                if node.quarantine_start is None:
                    node.quarantine_start = now
                if now - node.quarantine_start >= QUARANTINE_VALIDATE_S:
                    node.state = "QUARANTINED"
                    node.quarantine_until = now + QUARANTINE_TIME_S
                    node.quarantine_start = None
                    if node.quarantine_first_ts is None:
                        node.quarantine_first_ts = now
            else:
                node.quarantine_start = None
                node.state = "SUSPECT" if risk >= THRESH_SUSPECT else "NORMAL"

        if node.state == prev:
            return

        self.log({"event": "STATE_CHANGE", "node": node.id, "from": prev, "to": node.state, "risk": risk, "indicators": ind})
        print(f"[ENGINE] STATE {node.id}: {prev} -> {node.state} risk={risk} {list(ind.keys())}", flush=True)

        if node.state == "QUARANTINED":
            self.send_cmd(node.id, "ISOLATE")
            node.quarantine_cmd_ts = now
            self.send_route_cmd("ROUTE_AVOID", node.id)
            self.dynsec_quarantine(node.id)
            self.log({"event": "QUARANTINE_ISSUED", "node": node.id})

        elif node.state == "NORMAL" and prev != "NORMAL":
            self.send_cmd(node.id, "RESTORE")
            node.restore_cmd_ts = now
            self.send_route_cmd("ROUTE_RESTORE", node.id)
            self.dynsec_restore(node.id)
            self.log({"event": "RESTORE_ISSUED", "node": node.id})

    # Score all nodes and update their states on each engine tick
    def tick(self):
        now = now_s()
        with self._nodes_lock:
            nodes = list(self.nodes.values())

        for node in nodes:
            risk, ind = self.calculate_risk(node, now)
            self.update_offline(node, ind, now)
            self.update_state(node, risk, ind, now)
            if PRINT_EVERY_TICK:
                print(f"[TICK] {node.id} state={node.state} risk={risk} ind={list(ind.keys())}", flush=True)

    # Connect to the broker and run the tick loop
    def run(self):
        self.client.connect(MQTT_HOST, MQTT_PORT, keepalive=MQTT_KEEPALIVE)
        self.client.loop_start()
        try:
            while True:
                try:
                    self.tick()
                except Exception as e:
                    self.log({"event": "TICK_ERROR", "error": repr(e)})
                    print(f"[ENGINE] tick error: {e!r}", flush=True)
                time.sleep(ENGINE_TICK_S)
        except KeyboardInterrupt:
            print("[ENGINE] shutting down", flush=True)
        finally:
            self.client.loop_stop()
            try:
                self.client.disconnect()
            except Exception:
                pass

    # Build the metrics dict used by the dashboard API
    def compute_metrics(self) -> dict:
        now = now_s()
        with self._nodes_lock:
            nodes = list(self.nodes.values())

        out: Dict[str, Any] = {}
        for node in nodes:
            risk, ind = self.calculate_risk(node, now)
            last_seen_age = (now - node.last_seen) if node.last_seen > 0 else None
            last_hb_age = (now - node.last_heartbeat) if node.last_heartbeat > 0 else None
            out[node.id] = {
                "state": node.state,
                "offline": node.offline,
                "risk": risk,
                "indicators": ind,
                "last_seen_age_s": last_seen_age,
                "last_heartbeat_age_s": last_hb_age,
                "telemetry_in_window": len(node.telemetry_ts),
                "status_in_window": len(node.status_ts),
                "connect_in_window": len(node.connect_ts),
                "malformed_in_window": len(node.malformed_ts),
                "packet_error": node.packet_error,
                "last_telemetry": node.last_telemetry,
                "quarantine_until": node.quarantine_until,
            }
        return {"ts": now, "nodes": out}

    # Log paho debug messages when enabled
    def on_log(self, client, userdata, level, buf):
        print(f"[PAHO] {buf}", flush=True)

    # Log broker disconnection events
    def on_disconnect(self, client, userdata, rc):
        self.log({"event": "MQTT_DISCONNECT", "rc": rc})
        print(f"[ENGINE] DISCONNECT rc={rc}", flush=True)

    # Subscribe to telemetry and status topics on successful connection
    def on_connect(self, client, userdata, flags, rc, properties=None):
        print(f"[ENGINE] CONNECT rc={rc}", flush=True)
        self.log({
            "event": "MQTT_CONNECTED",
            "rc": rc,
            "client_id": self.client_id,
            "host": MQTT_HOST,
            "port": MQTT_PORT
        })

        if rc != 0:
            print("[ENGINE] Bad rc; will retry.", flush=True)
            return

        client.subscribe(TELEMETRY_SUB, qos=QOS_TELEM_SUB)
        client.subscribe(STATUS_SUB, qos=QOS_STATUS_SUB)
        self.log({"event": "SUBSCRIBED", "telemetry": TELEMETRY_SUB, "status": STATUS_SUB})

        if DYNSEC_ENABLED:
            client.subscribe(DYNSEC_RESP_TOPIC, qos=1)
            self.log({"event": "SUBSCRIBED_DYNSEC", "topic": DYNSEC_RESP_TOPIC})

    # Route incoming messages to the appropriate handler
    def on_message(self, client, userdata, msg):
        now = now_s()

        if DYNSEC_ENABLED and msg.topic == DYNSEC_RESP_TOPIC:
            data, err = safe_json_loads(msg.payload)
            if err:
                self.log({"event": "DYNSEC_BAD_RESPONSE", "error": err})
                return
            if isinstance(data, dict) and "correlationData" in data:
                corr = data["correlationData"]
                with self._dynsec_lock:
                    self._dynsec_pending[corr] = {"response": data, "ts": now}
                self.log({"event": "DYNSEC_RESPONSE", "corr": corr, "response": data})
            return

        node_id = parse_node_from_topic(msg.topic)
        if not node_id:
            return

        node = self.get_node(node_id)
        node.last_seen = now

        if msg.topic.endswith("/status"):
            node.status_ts.append(now)
            data, err = safe_json_loads(msg.payload)
            payload_for_handler = data if not err else msg.payload.decode("utf-8", errors="replace")
            self._handle_status_payload(node, payload_for_handler, now)
            return

        if msg.topic.endswith("/telemetry"):
            node.telemetry_ts.append(now)
            data, err = safe_json_loads(msg.payload)

            if err or not isinstance(data, dict):
                print(f"[DEBUG] Bad telemetry from {node_id}: {msg.payload!r}", flush=True)
                node.malformed_ts.append(now)
                return

            print(f"[DEBUG] Telemetry from {node_id}: {data}", flush=True)

            if "node" in data and data.get("node") != node_id:
                node.malformed_ts.append(now)
                return

            node.last_telemetry = data

            # Extract packet error rate from whichever field name the node uses
            per = data.get("packet_error_rate")
            if per is None:
                per = data.get("per")
            if per is None:
                per = data.get("packet_error")
            if per is None:
                per = data.get("packet_loss")

            if per is not None:
                try:
                    node.packet_error = float(per)
                    print(f"[DEBUG] packet_error set for {node_id}: {node.packet_error}", flush=True)
                except Exception:
                    print(f"[DEBUG] packet_error invalid for {node_id}: {per!r}", flush=True)
                    node.malformed_ts.append(now)


# Flask dashboard served on a background thread
def run_dashboard(engine: "BehaviourEngine", host: str, port: int):
    from flask import Flask, Response, jsonify

    app = Flask(__name__)

    # Serve the main dashboard HTML page
    @app.get("/")
    def index():
        html = f"""
<!doctype html><html><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Behaviour Engine</title>
<style>
body{{font-family:system-ui,Segoe UI,Roboto,Arial;margin:16px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:10px}}
.card{{border:1px solid #3333;border-radius:12px;padding:12px}}
.bad{{color:#b00;font-weight:700}}
.warn{{color:#b70;font-weight:700}}
.ok{{color:#070;font-weight:700}}
small{{color:#666}}
pre{{white-space:pre-wrap;word-break:break-word;background:#00000008;padding:10px;border-radius:10px}}
</style></head><body>
<h1>Behaviour Engine</h1>
<small>
Broker {MQTT_HOST}:{MQTT_PORT} | window={ROLLING_WINDOW_S}s | suspect≥{THRESH_SUSPECT} | quarantine≥{THRESH_QUARANTINE} for {QUARANTINE_VALIDATE_S}s |
offline_after={OFFLINE_AFTER_S}s action={OFFLINE_ACTION}
</small>
<div class="grid" id="nodes"></div>
<h2>Live events</h2>
<pre id="events"></pre>
<script>
function cls(state, offline) {{
  if (offline) return "warn";
  if (state==="QUARANTINED") return "bad";
  if (state==="SUSPECT"||state==="RECOVERING") return "warn";
  return "ok";
}}
async function refresh(){{
  const r = await fetch('/api/nodes');
  const data = await r.json();
  const el = document.getElementById('nodes');
  el.innerHTML = '';
  for (const [id,n] of Object.entries(data.nodes)) {{
    const age = n.last_seen_age_s===null ? 'n/a' : (n.last_seen_age_s.toFixed(1) + 's');
    const hb = n.last_heartbeat_age_s===null ? 'n/a' : (n.last_heartbeat_age_s.toFixed(1) + 's');
    const c = cls(n.state, n.offline);
    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = `<b>${{id}}</b> <span class="${{c}}">${{n.offline ? "OFFLINE" : n.state}}</span><br/>
    <small>last_seen=${{age}} last_hb=${{hb}} telem_win=${{n.telemetry_in_window}} status_win=${{n.status_in_window}} connect_win=${{n.connect_in_window}}</small><br/>
    <small>packet_error=${{n.packet_error===null ? 'n/a' : n.packet_error}}</small>`;
    el.appendChild(card);
  }}
}}
refresh();
setInterval(refresh, 1000);

const ev = document.getElementById('events');
const es = new EventSource('/stream');
es.onmessage = (e) => {{
  ev.textContent = e.data + "\\n" + ev.textContent;
}};
</script></body></html>
"""
        return Response(html, mimetype="text/html")

    # Return current node states and metrics as JSON
    @app.get("/api/nodes")
    def api_nodes():
        return jsonify(engine.compute_metrics())

    # Return the most recent events as JSON
    @app.get("/api/events")
    def api_events():
        return jsonify({"events": engine.tail_events(200)})

    # Return metrics for all nodes as JSON
    @app.get("/api/metrics")
    def api_metrics():
        return jsonify(engine.compute_metrics())

    # Stream live events to the dashboard using server-sent events
    @app.get("/stream")
    def stream():
        def gen():
            last_seq = 0
            while True:
                events = engine.tail_events(50)
                if events:
                    newest = events[-1]
                    seq = int(newest.get("ts", 0) * 1000)
                    if seq != last_seq:
                        yield f"data: {json.dumps(newest, separators=(',', ':'))}\n\n"
                        last_seq = seq
                time.sleep(0.5)

        return Response(gen(), mimetype="text/event-stream")

    app.run(host=host, port=port, debug=False, threaded=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true", help="Verify hash chain and exit")
    ap.add_argument("--no-prompt", action="store_true", help="Use MQTT_USER/MQTT_PASS env vars")
    ap.add_argument("--paho-log", action="store_true", help="Enable PAHO debug logs")
    ap.add_argument("--dashboard", action="store_true", help="Run built in dashboard")
    ap.add_argument("--dash-host", default="127.0.0.1", help="Dashboard bind host")
    ap.add_argument("--dash-port", type=int, default=8000, help="Dashboard bind port")
    args = ap.parse_args()

    # Verify the chain log and exit without starting the engine
    if args.verify:
        ok, msg = verify_chain(CHAIN_LOG_FILE)
        print(msg)
        sys.exit(0 if ok else 2)

    if args.no_prompt:
        user, pw = BROKER_USER, BROKER_PASS
        if not user or not pw:
            sys.exit("Set MQTT_USER and MQTT_PASS or run without --no-prompt.")
    else:
        user = BROKER_USER or input("MQTT username: ").strip()
        pw = BROKER_PASS or getpass.getpass("MQTT password: ").strip()
        if not user or not pw:
            sys.exit("Missing credentials")

    eng = BehaviourEngine(user, pw, paho_log=args.paho_log)

    # Start the dashboard on a daemon thread if requested
    if args.dashboard:
        t = threading.Thread(
            target=run_dashboard,
            args=(eng, args.dash_host, args.dash_port),
            daemon=True,
        )
        t.start()
        print(f"[ENGINE] dashboard on http://{args.dash_host}:{args.dash_port}", flush=True)

    eng.run()


if __name__ == "__main__":
    main()
