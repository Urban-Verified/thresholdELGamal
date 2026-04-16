#!/usr/bin/env python3
"""
Neutral Bulletin Board — append-only, publicly readable log.

Prevents equivocation: once a participant posts under (topic, sender_id),
that entry is immutable and visible identically to all readers.

During DKG, keypers post commitments here instead of relaying through the
backend, ensuring no party can show different commitments to different
recipients.

Current implementation: centralized Flask HTTP server (in-memory).
Future: swap for a blockchain-backed or replicated-state-machine backend.

Usage (standalone):
    python bulletin_board.py --port 5500

Programmatic:
    from bulletin_board import create_bb_app, InMemoryBulletinBoard, BBClient
    app = create_bb_app()
    client = BBClient("http://127.0.0.1:5500")
"""

import argparse
import hashlib
import json
import threading
from abc import ABC, abstractmethod

import requests as _requests
from flask import Flask, request, jsonify


# ======================================================================
#  Abstract interface
# ======================================================================

class AbstractBulletinBoard(ABC):
    """Minimal bulletin-board contract.

    Any concrete backend (HTTP server, blockchain, database) must implement
    these five methods.
    """

    @abstractmethod
    def post(self, topic: str, sender_id: str, data) -> bool:
        """Append *data* under *(topic, sender_id)*.

        Returns True on success.
        Returns False if the sender already posted to this topic or the
        topic is frozen.
        """

    @abstractmethod
    def read_topic(self, topic: str) -> dict:
        """Return ``{sender_id: data, ...}`` for every entry in *topic*."""

    @abstractmethod
    def read_entry(self, topic: str, sender_id: str):
        """Return the entry for *(topic, sender_id)*, or None."""

    @abstractmethod
    def freeze(self, topic: str) -> str:
        """Freeze *topic* (no further posts) and return its digest."""

    @abstractmethod
    def get_digest(self, topic: str) -> str:
        """SHA-256 digest of the current topic contents."""


# ======================================================================
#  Deterministic digest helper
# ======================================================================

def _compute_digest(entries: dict) -> str:
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


# ======================================================================
#  In-memory implementation (thread-safe)
# ======================================================================

class InMemoryBulletinBoard(AbstractBulletinBoard):
    """Thread-safe, in-process bulletin board."""

    def __init__(self):
        self._topics: dict[str, dict] = {}
        self._frozen: set[str] = set()
        self._lock = threading.Lock()

    # --- interface ---

    def post(self, topic, sender_id, data):
        sender_id = str(sender_id)
        with self._lock:
            if topic in self._frozen:
                return False
            bucket = self._topics.setdefault(topic, {})
            if sender_id in bucket:
                return False  # append-only: no overwrites
            bucket[sender_id] = data
            return True

    def read_topic(self, topic):
        with self._lock:
            return dict(self._topics.get(topic, {}))

    def read_entry(self, topic, sender_id):
        with self._lock:
            return self._topics.get(topic, {}).get(str(sender_id))

    def freeze(self, topic):
        with self._lock:
            self._frozen.add(topic)
            return _compute_digest(self._topics.get(topic, {}))

    def get_digest(self, topic):
        with self._lock:
            return _compute_digest(self._topics.get(topic, {}))

    def reset(self):
        with self._lock:
            self._topics.clear()
            self._frozen.clear()


# ======================================================================
#  Flask HTTP server wrapping InMemoryBulletinBoard
# ======================================================================

def create_bb_app(board=None):
    """Create a Flask app that exposes *board* over HTTP.

    Endpoints:
        POST /bb/post               Post an entry {topic, sender_id, data}
        GET  /bb/read/<topic>       Read all entries for a topic
        GET  /bb/entry/<topic>/<id> Read a single entry
        POST /bb/freeze             Freeze a topic {topic}
        GET  /bb/digest/<topic>     Current topic digest
        GET  /bb/status             Health check
    """
    app = Flask("bulletin_board")
    if board is None:
        board = InMemoryBulletinBoard()
    app._board = board

    @app.route("/bb/post", methods=["POST"])
    def bb_post():
        data = request.get_json()
        topic = data["topic"]
        sender_id = str(data["sender_id"])
        payload = data["data"]
        ok = board.post(topic, sender_id, payload)
        if not ok:
            return jsonify({"error": "Already posted or topic frozen", "ok": False}), 409
        return jsonify({"ok": True})

    @app.route("/bb/read/<path:topic>", methods=["GET"])
    def bb_read(topic):
        entries = board.read_topic(topic)
        return jsonify({"topic": topic, "entries": entries})

    @app.route("/bb/entry/<path:topic>/<sender_id>", methods=["GET"])
    def bb_read_entry(topic, sender_id):
        entry = board.read_entry(topic, sender_id)
        if entry is None:
            return jsonify({"error": "Not found"}), 404
        return jsonify({"topic": topic, "sender_id": sender_id, "data": entry})

    @app.route("/bb/freeze", methods=["POST"])
    def bb_freeze():
        data = request.get_json()
        topic = data["topic"]
        digest = board.freeze(topic)
        return jsonify({"topic": topic, "digest": digest, "frozen": True})

    @app.route("/bb/digest/<path:topic>", methods=["GET"])
    def bb_digest(topic):
        digest = board.get_digest(topic)
        return jsonify({"topic": topic, "digest": digest})

    @app.route("/bb/status", methods=["GET"])
    def bb_status():
        return jsonify({"status": "ok"})

    return app


# ======================================================================
#  HTTP client (talks to the Flask server above)
# ======================================================================

class BBClient(AbstractBulletinBoard):
    """HTTP client for a remote BulletinBoard server."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def post(self, topic, sender_id, data):
        resp = _requests.post(f"{self.base_url}/bb/post", json={
            "topic": topic,
            "sender_id": str(sender_id),
            "data": data,
        }, timeout=10)
        if resp.status_code == 409:
            return False
        resp.raise_for_status()
        return resp.json().get("ok", False)

    def read_topic(self, topic):
        resp = _requests.get(f"{self.base_url}/bb/read/{topic}", timeout=10)
        resp.raise_for_status()
        return resp.json().get("entries", {})

    def read_entry(self, topic, sender_id):
        resp = _requests.get(
            f"{self.base_url}/bb/entry/{topic}/{sender_id}", timeout=10,
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json().get("data")

    def freeze(self, topic):
        resp = _requests.post(
            f"{self.base_url}/bb/freeze", json={"topic": topic}, timeout=10,
        )
        resp.raise_for_status()
        return resp.json().get("digest", "")

    def get_digest(self, topic):
        resp = _requests.get(
            f"{self.base_url}/bb/digest/{topic}", timeout=10,
        )
        resp.raise_for_status()
        return resp.json().get("digest", "")


# ======================================================================
#  Standalone entry point
# ======================================================================

def main():
    parser = argparse.ArgumentParser(description="Neutral Bulletin Board server")
    parser.add_argument("--port", type=int, default=5500, help="Port to listen on")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    args = parser.parse_args()

    app = create_bb_app()
    print(f"[BulletinBoard] Listening on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
