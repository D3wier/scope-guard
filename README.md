# scope-guard

CLI tool that parses bug bounty program policies and gives you real-time "in scope? yes/no" checks for any URL, domain, or IP. Prevents accidental out-of-scope testing.

## Features

- **Policy parser** — Reads scope definitions from HackerOne, Bugcrowd, or custom YAML/JSON formats
- **Real-time checks** — Pipe URLs and get instant scope verdicts
- **Wildcard support** — Handles `*.example.com`, CIDR ranges, and regex patterns
- **Exclusion rules** — Respects out-of-scope lists and program restrictions
- **Pipeline integration** — Filter recon output to in-scope targets only
- **Multiple programs** — Manage scope files for different programs
- **Visual feedback** — Color-coded terminal output

## Installation

```bash
pip install scope-guard
```

Or from source:

```bash
git clone https://github.com/D3wier/scope-guard.git
cd scope-guard
pip install -e .
```

## Quick Start

```bash
# Import scope from a HackerOne program
scope-guard import --h1 program-handle

# Or create a scope file manually
scope-guard init my-program

# Check a single URL
scope-guard check https://api.example.com/users

# Filter a list of URLs
cat urls.txt | scope-guard filter

# Interactive mode
scope-guard watch
```

## Scope File Format

```yaml
# ~/.scope-guard/my-program.yaml
program: my-program
platform: hackerone

in_scope:
  - type: domain
    value: "*.example.com"
  - type: domain
    value: "api.example.com"
  - type: ip_range
    value: "10.0.0.0/24"
  - type: url
    value: "https://app.example.com/*"

out_of_scope:
  - type: domain
    value: "blog.example.com"
  - type: domain
    value: "*.staging.example.com"
  - type: url
    value: "*/logout"

rules:
  no_automated_scanning: false
  rate_limit: "30/min"
  no_destructive: true
  testing_hours: "00:00-23:59 UTC"
```

## CLI Usage

```bash
# Initialize a new scope file
scope-guard init <program-name>

# Import from platform
scope-guard import --h1 <handle>      # HackerOne
scope-guard import --bc <handle>      # Bugcrowd
scope-guard import --file scope.json  # Custom JSON/YAML

# Check single target
scope-guard check <url|domain|ip>
scope-guard check https://api.target.com/v2/users
scope-guard check 10.0.0.50

# Filter stdin (only output in-scope)
subfinder -d example.com | scope-guard filter
cat all_urls.txt | scope-guard filter > inscope_urls.txt

# Filter with verdict labels
cat urls.txt | scope-guard filter --verbose
# ✓ https://api.example.com/users
# ✗ https://blog.example.com/post

# Set active program
scope-guard use my-program

# List configured programs
scope-guard list

# Show current scope summary
scope-guard show
```

## Pipeline Examples

```bash
# Recon pipeline — only scan in-scope subdomains
subfinder -d example.com -silent | scope-guard filter | httpx -silent

# Filter nuclei targets
cat live_hosts.txt | scope-guard filter | nuclei -t cves/

# Check before testing
if scope-guard check "$TARGET" --quiet; then
  echo "Target is in scope, proceeding..."
  nuclei -u "$TARGET"
fi
```

## Python API

```python
from scope_guard import ScopeChecker

checker = ScopeChecker.from_file("scope.yaml")

# Check targets
result = checker.check("https://api.example.com/users")
print(result.in_scope)    # True
print(result.matched_rule) # "*.example.com"

# Batch check
urls = ["https://api.example.com", "https://evil.com"]
results = checker.check_many(urls)
in_scope = [r.target for r in results if r.in_scope]
```

## License

MIT License — see [LICENSE](LICENSE)
