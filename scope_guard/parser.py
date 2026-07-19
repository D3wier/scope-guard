"""Platform scope parsers (HackerOne, Bugcrowd)."""

import json
import urllib.request
from typing import Optional


def parse_h1_scope(handle: str) -> Optional[dict]:
    """Fetch and parse scope from HackerOne program."""
    url = f"https://hackerone.com/programs/{handle}/policy_scopes.json"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        resp = urllib.request.urlopen(req, timeout=15)
        data = json.loads(resp.read())
    except Exception:
        return None

    in_scope = []
    out_of_scope = []

    for item in data.get("data", []):
        attrs = item.get("attributes", {})
        asset_type = attrs.get("asset_type", "")
        identifier = attrs.get("asset_identifier", "")
        eligible = attrs.get("eligible_for_bounty", False)
        eligible_submission = attrs.get("eligible_for_submission", True)

        rule_type = "domain"
        if asset_type == "CIDR":
            rule_type = "ip_range"
        elif asset_type == "URL":
            rule_type = "url"

        rule = {"type": rule_type, "value": identifier}

        if eligible_submission and eligible:
            in_scope.append(rule)
        elif not eligible_submission:
            out_of_scope.append(rule)

    return {
        "program": handle,
        "platform": "hackerone",
        "in_scope": in_scope,
        "out_of_scope": out_of_scope,
    }


def parse_scope_file(path: str) -> dict:
    """Parse a JSON or YAML scope file."""
    with open(path) as f:
        content = f.read()

    if path.endswith(".json"):
        return json.loads(content)

    import yaml
    return yaml.safe_load(content)
