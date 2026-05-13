# Wazuh Rules for FortiGate FortiOS 8.0.0 (JSON Logs)

A Wazuh detection ruleset for Fortinet FortiGate firewalls running FortiOS 8.0.0, consuming native JSON-format syslog output.

## Overview

FortiGate devices can emit logs in JSON format over syslog. Wazuh's built-in `json` decoder processes these logs and promotes all JSON keys to top-level decoded fields. This ruleset anchors on the `devid` field (which always begins with `FG` on FortiGate hardware and VMs) to fingerprint FortiGate events among all JSON sources, then builds a structured detection hierarchy from there.

**Rule ID range:** 118100 – 118299  
**Total rules:** 149  
**Target firmware:** FortiOS 8.0.0 (log format is broadly compatible with 6.4 and 7.x)

## Files

```
decoders/
  fortigate-json_decoders.xml   # Optional custom decoder (not required when using built-in JSON decoder)

rules/
  fortigate-json_rules.xml      # 149 detection rules

references/
  fortios_8_0_log_ids.csv       # FortiOS 8.0.0 log ID reference with pre-assigned Wazuh rule IDs
  fortiguard_web_filter_categories.csv  # FortiGuard URL category number-to-name mapping
```

## Decoder Notes

The rules rely on **Wazuh's built-in `json` decoder**, not the custom decoder in this repo. Wazuh automatically selects the built-in decoder when a log event is valid JSON. No custom decoder installation is required.

The included `fortigate-json_decoders.xml` is provided for environments that route FortiGate syslog through a specific program name (`devname`), but the rules do not depend on it.

## Rule Coverage

### Traffic (118101 – 118108)
| Rule | Description |
|------|-------------|
| 118101 | Traffic log parent (anchor) |
| 118102 | Traffic allowed (`action: accept/allow`) |
| 118103 | Traffic denied/dropped by policy |
| 118104 | Connection reset by client or server |
| 118105 | Failed connection attempts (`logid: 0000000011`) |
| 118106 | Forward traffic statistics (`logid: 0000000020`) |
| 118107 | Local traffic (management plane) |
| 118108 | ZTNA traffic (`logid: 0005000024`) |

### UTM — Antivirus (118110 – 118118)
Malware blocked/passed, FortiSandbox verdicts, Outbreak Prevention, EMS threat feed, Content Disarm & Reconstruction (CDR), 0-day malware stream, oversize file.

### UTM — IPS / Anomaly (118119 – 118128)
IPS attack signatures (alert/warning/notice), Botnet C&C blocked and detected, malicious URL, L2 protocol attacks, anomaly attack (alert/warning).

### UTM — Web Filter (118129 – 118144)
URL filter list blocked, FortiGuard category blocked (including targeted rules for Malicious Websites, Phishing, Hacking, Proxy Avoidance), FortiGuard risk-level blocked, antiphishing, domain fronting, command blocked, rating errors, quota expiry, video filter, FortiGuard unreachable.

### UTM — Application Control (118145 – 118150)
Application blocked, high/critical/elevated risk application, port enforcement violation, protocol enforcement violation.

### UTM — DLP (118151 – 118154)
Data loss blocked, data loss detected (monitor mode), fingerprint source error.

### UTM — WAF (118155 – 118159)
Request blocked (signature, custom signature, address list), WAF anomaly blocked.

### UTM — Email / Spam (118160)
Spam / MIME spam notification.

### UTM — CASB (118161)
SaaS application activity blocked.

### Event — Admin Authentication (118162 – 118170)
Login success, login failure, account locked, logout, session dropped, password expired, VDOM enter/leave, FortiToken push failed.

### Event — Configuration Changes (118171 – 118182)
CLI and GUI config changes, global setting changes, config backup, config restore, system start/shutdown/reboot/factory-reset, firmware upgrade, image load failure, invalid/tampered firmware, application crash.

### Event — VPN (118183 – 118185)
IPsec tunnel up, tunnel down, VPN statistics.

### Event — System Health (118186 – 118213)
Memory conserve mode, extreme low memory, IPS fail-open, interface link/admin changes, kernel errors, socket pool exhaustion, IP pool exhaustion, power supply failure/redundancy, thermal alerts, fan anomaly, disk unavailable, log disk failure, SSD spare blocks, disk log full/corrupted.

### Event — Routing (118214 – 118218)
BGP/OSPF neighbor state change, routing information changed, routing log critical.

### Event — SD-WAN (118219 – 118222)
Link quality change, quality degraded, fail detect, neighbor status.

### Event — Licensing (118223 – 118232)
AV/IPS/webfilter license expiring and expired, VM license expired, license status change, duplicate license, certificate expiring, CRL expired.

### Event — Security Fabric / CSF (118233 – 118236)
FortiAnalyzer connection up/down/failed, write permission violation, hard link violation, kernel/firmware load violation, executable hash missing/mismatch.

### Event — Miscellaneous (118237 – 118242)
DHCP pool full/high, Security Fabric loop, upstream SN changed, locally-generated traffic to IoC, FNBAM auth error, log upload error.

### Frequency / Correlation (118250 – 118257)
| Rule | Trigger | Threshold |
|------|---------|-----------|
| 118250 | Admin brute force | 5 failures / 60 s (same srcip) |
| 118251 | Admin brute force escalation | 10 failures / 120 s |
| 118252 | Firewall deny flood (port scan / attack) | 10 denies / 30 s (same srcip) |
| 118253 | IPS attack campaign | 5 IPS alerts / 60 s (same srcip) |
| 118254 | Malware spread from infected host | 3 detections / 120 s (same srcip) |
| 118255 | Connection flood / scan | 15 failed connections / 30 s (same srcip) |
| 118256 | Data exfiltration attempt | 5 DLP violations / 300 s (same srcip) |
| 118257 | Web attack campaign | 10 WAF blocks / 60 s (same srcip) |

## Severity Mapping

| FortiGate level | Wazuh level |
|----------------|-------------|
| emergency | 15 |
| alert | 14 |
| critical | 12 |
| error | 8 |
| warning | 6 |
| notice | 5 |
| information | 3 |
| debug | 2 |

## Compliance Tags

Rules are tagged for the following frameworks where applicable:

- **PCI DSS** (1.3.4, 5.1, 6.5, 6.6, 10.2.x, 10.5.5, 11.4)
- **GDPR** (IV 35.7.d)
- **HIPAA** (164.312.a, 164.312.b)
- **NIST 800-53** (AC, AU, CM, IA, SC, SI)
- **GPG13** (4.13)

## MITRE ATT&CK Coverage

Selected technique IDs mapped in rules:

`T1048` `T1059` `T1071` `T1078` `T1098` `T1102` `T1110.001` `T1133` `T1190` `T1204.002` `T1486` `T1499` `T1505` `T1531` `T1543` `T1562` `T1571`

## Installation

### 1. FortiGate syslog configuration

Configure FortiGate to send JSON-format syslog to Wazuh:

```
config log syslogd setting
    set status enable
    set server <WAZUH_MANAGER_IP>
    set port 514
    set format json
end
```

> **Note:** When using JSON format, the syslog header `program_name` field is set to the device name (`devname` value). Wazuh receives the raw JSON payload after the syslog prefix.

### 2. Deploy decoder (optional)

Only needed if your FortiGate syslog is tagged with `devname` as the program name and you want explicit decoder chaining:

```bash
cp decoders/fortigate-json_decoders.xml /var/ossec/etc/decoders/
```

### 3. Deploy rules

```bash
cp rules/fortigate-json_rules.xml /var/ossec/etc/rules/
```

### 4. Restart Wazuh manager

```bash
systemctl restart wazuh-manager
```

### 5. Verify with wazuh-logtest

```bash
/var/ossec/bin/wazuh-logtest
```

Paste a sample FortiGate JSON log line and confirm:
- **Phase 2** decoder: `name: 'json'`
- **Phase 3** rule: one of the 118xxx rules fires

## Requirements

- Wazuh Manager 4.3 or later
- FortiGate running FortiOS 6.4 / 7.x / 8.0
- Syslog format set to `json` on the FortiGate

## References

- [FortiOS 8.0.0 Log Message Reference](https://docs.fortinet.com/document/fortigate/8.0.0/fortios-log-message-reference)
- [Wazuh Ruleset Documentation](https://documentation.wazuh.com/current/user-manual/ruleset/index.html)
- [Wazuh Decoder Syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html)
