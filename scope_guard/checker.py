"""Core scope checking logic."""

import fnmatch
import ipaddress
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse


@dataclass
class CheckResult:
    target: str
    in_scope: bool
    matched_rule: Optional[str] = None
    reason: str = ""


@dataclass
class ScopeRule:
    type: str
    value: str
    is_exclusion: bool = False

    def matches(self, target: str) -> bool:
        if self.type == "domain":
            return self._match_domain(target)
        elif self.type == "ip_range":
            return self._match_ip(target)
        elif self.type == "url":
            return self._match_url(target)
        elif self.type == "regex":
            return bool(re.match(self.value, target))
        return False

    def _match_domain(self, target: str) -> bool:
        parsed = urlparse(target) if "://" in target else None
        domain = parsed.hostname if parsed else target.split("/")[0].split(":")[0]

        if not domain:
            return False

        if self.value.startswith("*."):
            suffix = self.value[2:]
            return domain == suffix or domain.endswith("." + suffix)
        return domain == self.value

    def _match_ip(self, target: str) -> bool:
        parsed = urlparse(target) if "://" in target else None
        host = parsed.hostname if parsed else target.split("/")[0].split(":")[0]

        try:
            ip = ipaddress.ip_address(host)
            network = ipaddress.ip_network(self.value, strict=False)
            return ip in network
        except ValueError:
            return False

    def _match_url(self, target: str) -> bool:
        return fnmatch.fnmatch(target, self.value)


class ScopeChecker:
    def __init__(self, in_scope: list, out_of_scope: list, program: str = ""):
        self.program = program
        self.in_scope = [ScopeRule(**r) for r in in_scope]
        self.out_of_scope = [ScopeRule(**r, is_exclusion=True) for r in out_of_scope]

    @classmethod
    def from_file(cls, path: str) -> "ScopeChecker":
        import yaml

        with open(path) as f:
            data = yaml.safe_load(f)

        return cls(
            in_scope=data.get("in_scope", []),
            out_of_scope=data.get("out_of_scope", []),
            program=data.get("program", ""),
        )

    @classmethod
    def from_dict(cls, data: dict) -> "ScopeChecker":
        return cls(
            in_scope=data.get("in_scope", []),
            out_of_scope=data.get("out_of_scope", []),
            program=data.get("program", ""),
        )

    def check(self, target: str) -> CheckResult:
        for rule in self.out_of_scope:
            if rule.matches(target):
                return CheckResult(
                    target=target,
                    in_scope=False,
                    matched_rule=rule.value,
                    reason="Matched out-of-scope rule",
                )

        for rule in self.in_scope:
            if rule.matches(target):
                return CheckResult(
                    target=target,
                    in_scope=True,
                    matched_rule=rule.value,
                    reason="Matched in-scope rule",
                )

        return CheckResult(
            target=target,
            in_scope=False,
            reason="No matching scope rule found",
        )

    def check_many(self, targets: list) -> list:
        return [self.check(t) for t in targets]

    def filter_in_scope(self, targets: list) -> list:
        return [t for t in targets if self.check(t).in_scope]
