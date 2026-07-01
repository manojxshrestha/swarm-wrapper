# Enterprise Deployment

Multi-user, multi-team deployment architecture for Swarm.

## Architecture

```mermaid
graph TB
    classDef operator fill:#cce5ff,stroke:#333,stroke-width:2px,color:#000
    classDef core fill:#d4edda,stroke:#333,stroke-width:2px,color:#000
    classDef storage fill:#fff3cd,stroke:#333,stroke-width:2px,color:#000
    classDef external fill:#f8d7da,stroke:#333,stroke-width:2px,color:#000
    classDef security fill:#e6ccff,stroke:#333,stroke-width:2px,color:#000

    subgraph OPERATORS ["Operators"]
        direction LR
        O1["Operator 1<br/>(Analyst)"]:::operator
        O2["Operator 2<br/>(Auditor)"]:::operator
        O3["Operator N<br/>(Admin)"]:::operator
    end

    subgraph SWARM ["Swarm Platform"]
        direction TB
        MCP["Swarm MCP Server<br/>88 tools · single instance"]:::core
        RBAC["RBAC Layer<br/>access_control.py"]:::security
        LOCK["Locking Layer<br/>state_manager.py"]:::security
        AUDIT["Audit Trail<br/>per-engagement event log"]:::security
        CRYPTO["Credential Encryption<br/>crypto_utils.py (Fernet)"]:::security
    end

    subgraph STORAGE ["Shared Storage ($RECON_BASE)"]
        direction TB
        S1["engagements/<br/>runtime data per engagement"]:::storage
        S2["findings.db<br/>SQLite findings database"]:::storage
        S3["evidence/<br/>PoC outputs · screenshots"]:::storage
        S4["configs/<br/>YAML engagement configs"]:::storage
        S5["checkpoints/<br/>state snapshots"]:::storage
    end

    subgraph INTEGRATIONS ["External Integrations"]
        direction LR
        BURP["Burp Suite MCP<br/>HTTP request execution"]:::external
        BROWSER["Browser Agent<br/>headed Chromium · Playwright"]:::external
        LLM["OpenCode / LLM<br/>agent host"]:::external
    end

    OPERATORS -->|"open via OpenCode"| LLM
    LLM <-->|"MCP protocol"| MCP
    MCP --> RBAC
    RBAC --> LOCK
    LOCK --> AUDIT
    MCP --> CRYPTO
    MCP <-->|"request execution"| BURP
    MCP <-->|"browser automation"| BROWSER
    MCP <--> STORAGE

    O1 -.->|"read-write"| STORAGE
    O3 -.->|"admin"| STORAGE
```

## RBAC Tiers

| Role | Permissions |
|------|-------------|
| `admin` | Full access: create engagements, manage users, delete data |
| `operator` | Create/edit engagements, run tests, log findings |
| `analyst` | View findings, generate reports, read-only access |
| `auditor` | Read-only: review findings, export evidence |
| `service_account` | Automated API access, specific engagement scope |

## Setup

### 1. Install

```bash
pip install -e server/
```

### 2. Configure data directory

```bash
export SWARM_DATA=/opt/swarm/data
```

### 3. Verify deployment

```bash
python scripts/verify-enterprise.py
```

## RBAC Quickstart

```python
# Grant operator access to an engagement
grant_access("eng-001", "alice", "operator", "editor")

# Grant auditor read-only access
grant_access("eng-001", "bob", "auditor", "guest")

# Check access before modifying
check_access("eng-001", "bob", required_level="editor")
# → {"granted": False, "reason": "Access level 'guest' insufficient"}
```

## Locking

Prevent concurrent destructive operations:

```python
acquire_lock("eng-001", "alice", reason="Running Phase 4 exploitation")
# ... exclusive access ...
release_lock("eng-001", "alice")
```

## State Recovery

```python
# Create checkpoint before risky operations
create_checkpoint("eng-001", "alice", "Before phase-4 recon")

# Rollback if something goes wrong
rollback_to_checkpoint("eng-001", "cp-1741718400-1")
```

## Audit Trail

All access events are logged per-engagement:

```bash
cat $SWARM_ROOT/engagements/eng-001/audit/eng-001_access.log
```

## Requirements

- Python 3.10+
- Shared filesystem (NFS, EFS, or similar) for multi-instance deployments
- `cryptography` package for credential encryption (optional)
