# 🛡️ NIGHTFALL Security Toolkit

> Defensive cybersecurity toolkit for security analysis, threat
> detection, file integrity monitoring, and security automation.

NIGHTFALL is a modular defensive security toolkit written in Python.

It is designed to analyze security logs, detect suspicious
authentication activity, generate security alerts and events, monitor
file integrity, and provide a command-line interface for defensive
security operations.

------------------------------------------------------------------------

## 🎯 Features

### Security Analysis

-   Authentication log analysis
-   Failed login detection
-   Source IP tracking
-   Brute-force detection
-   Configurable detection thresholds

### Threat Detection

-   Brute-force detection
-   Threat classification
-   Detection metadata
-   Source IP identification

### Security Events

-   Structured security events
-   Event severity
-   Event metadata
-   Security event pipeline

### Alerting

-   Security alert generation
-   Severity-based alert handling
-   Defensive response decisions

### File Integrity Monitoring

-   SHA-256 file hashing
-   Directory scanning
-   Integrity baselines
-   Baseline comparison
-   Modified file detection
-   New file detection
-   Deleted file detection

### CLI

NIGHTFALL provides: - `analyze` - `integrity` - `baseline` - `check`

### Testing & CI

-   Pytest test suite
-   GitHub Actions CI
-   Package installation validation
-   CLI validation
-   Python package build validation

------------------------------------------------------------------------

## 🚀 Installation

### Requirements

-   Python 3.10+
-   pip

Clone the repository:

``` bash
git clone https://github.com/nightfall-sec/nightfall-security.git
cd nightfall-security
```

Install NIGHTFALL:

``` bash
pip install .
```

Verify:

``` bash
nightfall --help
```

------------------------------------------------------------------------

## 🖥️ CLI Usage

### Analyze security logs

``` bash
nightfall analyze security.log
```

Custom brute-force threshold:

``` bash
nightfall analyze security.log --threshold 3
```

JSON output:

``` bash
nightfall analyze security.log --json
```

### File integrity scan

``` bash
nightfall integrity ./monitored
```

JSON output:

``` bash
nightfall integrity ./monitored --json
```

------------------------------------------------------------------------

## 🔐 Integrity Baseline

Create a baseline:

``` bash
nightfall baseline ./monitored --output baseline.json
```

The baseline stores SHA-256 hashes for files in the monitored directory.

------------------------------------------------------------------------

## 🔎 Integrity Check

Compare the current directory against the saved baseline:

``` bash
nightfall check ./monitored --baseline baseline.json
```

NIGHTFALL detects: - Unchanged files - Modified files - New files -
Deleted files

Exit codes:

``` text
0 = integrity is OK
1 = integrity violation or operational error
```

JSON output:

``` bash
nightfall check ./monitored --baseline baseline.json --json
```

------------------------------------------------------------------------

## 🧪 Testing

Run the complete test suite:

``` bash
python -m pytest -v
```

GitHub Actions validates: 1. Python environment 2. Package installation
3. CLI availability 4. Package building 5. Test suite

------------------------------------------------------------------------

## 📦 Building the Package

Install the build tool:

``` bash
python -m pip install build
```

Build:

``` bash
python -m build
```

This produces:

``` text
dist/
├── *.whl
└── *.tar.gz
```

------------------------------------------------------------------------

## 🏗️ Project Structure

``` text
nightfall-security/
├── .github/
│   └── workflows/
│       └── tests.yml
├── src/
│   └── nightfall/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── config.py
│       ├── event_pipeline.py
│       ├── file_integrity.py
│       ├── incident_response.py
│       ├── log_analyzer.py
│       ├── reporting.py
│       ├── security_event.py
│       ├── security_pipeline.py
│       ├── threat_detection.py
│       └── alert_engine.py
├── tests/
├── pyproject.toml
├── README.md
└── LICENSE
```

------------------------------------------------------------------------

## 🧠 Architecture

``` text
Security Logs
     │
     ▼
Log Analyzer
     │
     ▼
Threat Detection
     │
     ▼
Security Event
     │
     ▼
Alert Engine
     │
     ▼
Incident Response
```

File integrity:

``` text
Monitored Directory
        │
        ▼
   SHA-256 Scan
        │
        ▼
     Baseline
        │
        ▼
   Current Scan
        │
        ▼
Baseline Comparison
        ├── Unchanged
        ├── Modified
        ├── New
        └── Deleted
```

------------------------------------------------------------------------

## 🔒 Defensive Security Scope

NIGHTFALL is intended for:
- Authorized defensive security testing
- Security research
- Education
- Monitoring systems owned by the operator
- Systems for which explicit authorization has been granted
- Defensive automation
------------------------------------------------------------------------

## 🧭 Development Status

NIGHTFALL is under active development.

Current foundation includes: - Log analysis
- Threat detection
- Brute-force detection
- Security events
- Alerting
- Defensive response logic
- File integrity monitoring
- Integrity baselines
- CLI
- Automated testing
- Continuous integration
- Python package build validation

------------------------------------------------------------------------

## 🌑 NIGHTFALL

**Observe. Adapt. Defend.**
