# Real IP Blocking — Production Enforcement Guide

## Current State

When an analyst clicks **BLOCK IP** in CyberSentinel, the platform currently:
1. Writes a `blocked:{ip}` key to Redis (24h TTL)
2. Inserts a row into the `firewall_rules` PostgreSQL table
3. Marks the incident as RESOLVED

**No live network traffic is dropped.** The block is a database record and audit log only. This is by design for a v1 platform — the detection, investigation, and decision pipeline is complete; the enforcement hook is the missing piece.

---

## Option A — Linux Host (iptables / nftables)

**Best for:** Self-hosted deployments on a Linux server or VM.

### How it works
Call `iptables` or `nft` from Python when the analyst approves a block.

```python
import subprocess

def enforce_block_linux(ip: str, duration_hours: int = 24):
    # Add DROP rule for inbound traffic from this IP
    subprocess.run(
        ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
        check=True
    )
    # Schedule automatic removal after duration
    subprocess.run(
        ["at", f"now + {duration_hours} hours"],
        input=f"iptables -D INPUT -s {ip} -j DROP\n".encode(),
        check=True
    )
```

**Where to add this:** In `src/api/gateway.py`, inside `execute_ip_block()`, call `enforce_block_linux(ip)` after writing to Redis.

**Unblock:**
```bash
iptables -D INPUT -s <IP> -j DROP
```

**Persistent across reboots:** Save with `iptables-save > /etc/iptables/rules.v4`.

**Requires:** The API container must run with `--cap-add NET_ADMIN` (already set on `dpi-sensor`; add to `api-gateway` in `docker-compose.yml`).

---

## Option B — Windows Firewall (netsh / PowerShell)

**Best for:** Running CyberSentinel natively on a Windows host.

```python
import subprocess

def enforce_block_windows(ip: str):
    rule_name = f"CyberSentinel-Block-{ip}"
    subprocess.run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in", "action=block",
        f"remoteip={ip}",
        "enable=yes"
    ], check=True)

def remove_block_windows(ip: str):
    rule_name = f"CyberSentinel-Block-{ip}"
    subprocess.run([
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}"
    ], check=True)
```

**Requires:** The process must run as Administrator. The `start_live_dpi.ps1` script already self-elevates — add a PowerShell call from the API or trigger via a local agent.

**Alternative (PowerShell):**
```powershell
New-NetFirewallRule -DisplayName "CyberSentinel-Block-$ip" -Direction Inbound -Action Block -RemoteAddress $ip
```

---

## Option C — pfSense / OPNsense (REST API)

**Best for:** Organizations with a dedicated firewall appliance.

pfSense exposes a REST API via the `pfsense-api` package. OPNsense has a native REST API.

```python
import httpx

async def enforce_block_pfsense(ip: str, pfsense_url: str, api_key: str):
    async with httpx.AsyncClient(verify=False) as client:
        await client.post(
            f"{pfsense_url}/api/v1/firewall/rule",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "type": "block",
                "interface": "wan",
                "src": ip,
                "dst": "any",
                "descr": f"CyberSentinel auto-block {ip}",
                "enabled": True,
            }
        )
```

**Environment variables to add to `.env`:**
```
PFSENSE_URL=https://192.168.1.1
PFSENSE_API_KEY=your_api_key_here
```

---

## Option D — Cloud Provider Security Groups

**Best for:** Cloud-hosted workloads (AWS EC2, Azure VM, GCP instance).

### AWS — Security Group (boto3)
```python
import boto3

def enforce_block_aws(ip: str, security_group_id: str):
    ec2 = boto3.client("ec2")
    ec2.revoke_security_group_ingress(
        GroupId=security_group_id,
        IpPermissions=[{
            "IpProtocol": "-1",  # all traffic
            "IpRanges": [{"CidrIp": f"{ip}/32", "Description": f"CyberSentinel block"}],
        }]
    )
    # To block: add an explicit DENY via a Network ACL (NACLs support DENY; SGs are allow-only)
    ec2.create_network_acl_entry(
        NetworkAclId="acl-xxxxxxxx",
        RuleNumber=1,
        Protocol="-1",
        RuleAction="deny",
        Egress=False,
        CidrBlock=f"{ip}/32",
    )
```

### Azure — NSG Rule
```python
from azure.mgmt.network import NetworkManagementClient

def enforce_block_azure(ip: str, nsg_name: str, rg: str):
    client = NetworkManagementClient(credential, subscription_id)
    client.security_rules.begin_create_or_update(
        rg, nsg_name, f"DenyIP-{ip.replace('.', '-')}",
        {
            "priority": 100,
            "protocol": "*",
            "source_address_prefix": ip,
            "destination_address_prefix": "*",
            "access": "Deny",
            "direction": "Inbound",
        }
    )
```

---

## Option E — Endpoint Agent (osquery / CrowdStrike / SentinelOne)

**Best for:** Blocking at the host level rather than the network perimeter — useful when the threat is lateral movement from an internal IP.

Most EDR platforms expose a REST API:
- **CrowdStrike RTR**: `POST /real-time-response/entities/command/v1` with `netsh` or `iptables` command
- **SentinelOne**: `POST /web/api/v2.1/threats/{id}/mitigate/network-quarantine`
- **Wazuh**: Active response module — send a command to the agent to run `iptables`

---

## How to Wire It Into CyberSentinel

All enforcement options plug into the same two places in the codebase:

### 1. `src/api/gateway.py` — `execute_ip_block()` (line ~560)
Called when an analyst clicks **BLOCK IP** in the dashboard.
```python
# After writing to Redis and firewall_rules table, add:
await loop.run_in_executor(None, enforce_block_linux, ip)
# or enforce_block_windows, enforce_block_pfsense, etc.
```

### 2. `src/api/gateway.py` — `unblock_ip()` (line ~610)
Called when an analyst clicks **UNBLOCK** in the Firewall Rules panel.
```python
# After deleting the Redis key, add:
await loop.run_in_executor(None, remove_block_linux, ip)
```

### 3. `src/agents/mcp_orchestrator.py` — `_block_ip()` (line ~210)
Called by the AI agent when it autonomously decides to block (future: auto-block mode).

---

## Environment Variables to Add

```dotenv
# Enforcement backend: linux | windows | pfsense | aws | azure | none (default)
BLOCK_ENFORCEMENT=none

# pfSense / OPNsense
PFSENSE_URL=https://192.168.1.1
PFSENSE_API_KEY=

# AWS
AWS_REGION=us-east-1
AWS_SECURITY_GROUP_ID=sg-xxxxxxxx
AWS_NETWORK_ACL_ID=acl-xxxxxxxx

# Azure
AZURE_SUBSCRIPTION_ID=
AZURE_RESOURCE_GROUP=
AZURE_NSG_NAME=
```

---

## Security Considerations

- **Analyst approval is mandatory** — never auto-block without human review for production.  
  Auto-block should only be enabled for confirmed IOC matches (e.g., known C2 IPs from threat intel feeds).
- **Always set an expiry** — permanent blocks accumulate and create management debt. Default 24h is good.
- **Log everything** — the `firewall_rules` table already provides an audit trail.
- **False-positive recovery** — the UNBLOCK button in the dashboard clears both Redis and sets the rule as expired. Make sure enforcement removal is also tested.
- **IPv6** — extend all enforcement calls to handle IPv6 addresses if your network uses dual-stack.
