"""Turns a raw log message into a stable "template" by masking variable
tokens — IPs, numbers, ports, timestamps — so that many different raw
lines collapse onto the same template ID.

This is what makes the autoencoder's input tractable: it learns the
normal *sequence of templates*, not raw text, which is what actually
generalizes to new IPs and timestamps it has never seen.

This is a lightweight, regex-based templater. It's intentionally simpler
than a full Drain3 tree — good enough for the log families this project
targets (sshd, sudo, nginx). If broader log coverage is ever needed,
swap this module for Drain3 behind the same `templatize()` interface.
"""
from __future__ import annotations

import hashlib
import re

_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_PORT_RE = re.compile(r"\bport \d+\b")
_NUM_RE = re.compile(r"\b\d+\b")
_QUOTED_RE = re.compile(r'"[^"]*"')


def templatize(message: str) -> str:
    """Return a masked template string for a raw log message."""
    t = message
    t = _IP_RE.sub("<IP>", t)
    t = _PORT_RE.sub("port <PORT>", t)
    t = _QUOTED_RE.sub('"<STR>"', t)
    t = _NUM_RE.sub("<NUM>", t)
    return t.strip()


def template_id(message: str) -> str:
    """A short, stable hash identifying the template this message belongs to."""
    template = templatize(message)
    return hashlib.sha1(template.encode("utf-8")).hexdigest()[:12]
