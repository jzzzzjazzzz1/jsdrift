"""Scope guard.

Every request JSDrift makes - including every redirect hop - goes through ``Scope.check``.
Out-of-scope rules always win over in-scope rules, and private/metadata addresses are
blocked so a hostile page cannot steer the tool into your internal network.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .util import norm_host

METADATA_IPS = {"169.254.169.254", "fd00:ec2::254", "100.100.100.200", "192.0.0.192"}


class ScopeConfigError(ValueError):
    pass


@dataclass
class Decision:
    allowed: bool
    reason: str

    def __bool__(self) -> bool:
        return self.allowed


def _split_port(pattern: str) -> tuple[str, int | None]:
    m = re.fullmatch(r"(.+):(\d{1,5})", pattern)
    return (m.group(1), int(m.group(2))) if m else (pattern, None)


def _compile(pattern: str) -> tuple[re.Pattern, int | None, str]:
    p = pattern.strip().lower()
    host, port = _split_port(p)
    if not host:
        raise ScopeConfigError("empty scope pattern")
    if "*" in host:
        fixed = [label for label in host.split(".") if "*" not in label]
        if len(fixed) < 2:
            raise ScopeConfigError(f"scope pattern '{pattern}' is too broad (needs >= 2 fixed labels)")
    rx = re.compile("^" + re.escape(host).replace(r"\*", r"[a-z0-9._-]*") + "$")
    return rx, port, p


@dataclass
class Scope:
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    allow_http: bool = False
    allow_private_ips: bool = False
    _in: list = field(default_factory=list, repr=False)
    _out: list = field(default_factory=list, repr=False)
    _dns: dict = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if not self.in_scope:
            raise ScopeConfigError("scope.in_scope must list at least one host pattern")
        self._in = [_compile(p) for p in self.in_scope]
        self._out = [_compile(p) for p in self.out_of_scope]

    @classmethod
    def from_dict(cls, d: dict) -> "Scope":
        return cls(
            in_scope=list(d.get("in_scope", [])),
            out_of_scope=list(d.get("out_of_scope", [])),
            allow_http=bool(d.get("allow_http", False)),
            allow_private_ips=bool(d.get("allow_private_ips", False)),
        )

    @staticmethod
    def _match(rules: list, host: str, port: int) -> str | None:
        for rx, rport, raw in rules:
            if rx.match(host) and (rport is None or rport == port):
                return raw
        return None

    def classify_host(self, host: str, port: int = 443) -> str:
        """'in_scope' | 'out_of_scope' (explicitly excluded) | 'third_party' (unlisted)."""
        host = norm_host(host)
        if self._match(self._out, host, port) or self._match(self._out, host, 80):
            return "out_of_scope"
        if self._match(self._in, host, port) or self._match(self._in, host, 80):
            return "in_scope"
        return "third_party"

    def _resolve(self, host: str) -> list[str]:
        if host in self._dns:
            return self._dns[host]
        try:
            ips = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
        except OSError:
            ips = []
        self._dns[host] = ips
        return ips

    def check(self, url: str, resolve: bool = True) -> Decision:
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            return Decision(False, "malformed URL")
        if parts.scheme not in ("http", "https"):
            return Decision(False, f"scheme '{parts.scheme}' not allowed")
        if parts.scheme == "http" and not self.allow_http:
            return Decision(False, "plain http blocked (set scope.allow_http to permit)")
        if parts.username or parts.password:
            return Decision(False, "credentials in URL")
        host = norm_host(parts.hostname)
        if not host:
            return Decision(False, "no host")
        port = port or (443 if parts.scheme == "https" else 80)

        hit = self._match(self._out, host, port)
        if hit:
            return Decision(False, f"explicitly out of scope ({hit})")
        hit = self._match(self._in, host, port)
        if not hit:
            return Decision(False, "host not in scope")

        try:
            ips = [str(ipaddress.ip_address(host))]
        except ValueError:
            ips = self._resolve(host) if resolve else []
        for ip in ips:
            addr = ipaddress.ip_address(ip)
            if ip in METADATA_IPS or addr.is_link_local:
                return Decision(False, f"{ip} is a link-local/metadata address (always blocked)")
            if not self.allow_private_ips and (
                addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast or addr.is_unspecified
            ):
                return Decision(False, f"resolves to non-public address {ip} (set scope.allow_private_ips to permit)")
        return Decision(True, f"in scope ({hit})")
