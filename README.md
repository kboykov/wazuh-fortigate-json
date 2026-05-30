# Wazuh Rules for FortiGate FortiOS 8.0.0 (JSON Logs)

A Wazuh detection ruleset for Fortinet FortiGate firewalls running FortiOS 8.0.0, consuming native JSON-format syslog output.

## Overview

FortiGate devices can emit logs in JSON format over syslog. Wazuh's built-in `json` decoder processes these logs and promotes all JSON keys to top-level decoded fields. This ruleset anchors on the presence of a numeric `logid`, then keeps detection rules flat and based solely on exact `logid` values.

**Rule ID range:** 118100 - 118299
**Total rules:** 173
**Target firmware:** FortiOS 8.0.0 (log format is broadly compatible with 6.4 and 7.x)

## Files

```
rules/
  fortigate-json_rules.xml      # 173 logid-based detection, suppression, and correlation rules

references/
  fortios_8_0_log_ids.csv       # FortiOS 8.0.0 log ID reference with pre-assigned Wazuh rule IDs
  fortiguard_web_filter_categories.csv  # FortiGuard URL category number-to-name mapping
  forti_master_reference.txt    # Pipe-delimited FortiOS 8.0.0 master log ID reference
  FortiOS_8.0.0_Log_Reference.md # Full FortiOS 8.0.0 log reference
```

## Decoder Notes

The rules rely on **Wazuh's built-in `json` decoder**. Wazuh automatically selects the built-in decoder when a log event is valid JSON. No custom decoder installation is required.

## Detection Model

Rule `118100` anchors decoded JSON logs that contain a numeric `logid`. Every detection rule below it uses `if_sid=118100` and matches exact `logid` values. Fields such as `devid`, `type`, `subtype`, `action`, `level`, `status`, `catdesc`, `apprisk`, `srcip`, `remip`, and `user` are used only in descriptions or as frequency correlation keys. The only field-based exceptions are level-0 noise suppressors for selected allowed infrastructure traffic under `118102`.

## Rule Coverage

### Traffic
Allowed, denied/invalid, failed connection, local traffic, forward statistics, and ZTNA traffic log IDs.

Allowed traffic rule `118102` has level-0 suppressors for noisy syslog, DNS, SNMP, and ICMP traffic by `service`, ICMP `proto=1`, and common source/destination ports `53`, `161`, `162`, and `514`.

### UTM and Security
Antivirus, FortiSandbox, Outbreak Prevention, EMS threat feed, CDR, IPS, anomaly/DoS, web filter, application control, DLP, WAF, email/spam, and CASB log IDs.

### Management Authentication
Admin login success/failure, login disabled, logout, disconnect, password expiry, VDOM access, FortiToken/MFA lifecycle and failure, FNBAM, SNMP auth query failure, unauthenticated CMDB requests, sensitive CMDB table requests, PPP auth, and admin GUI/log access actions.

### User Authentication
Firewall user auth success/failure, lockout, timeout, explicit proxy auth, NTLM auth, FortiGuard override auth, 802.1x auth, FSSO status, and auth backup/restore/server reachability events.

### VPN
IPsec tunnel up/down/statistics, IPsec negotiation and ESP errors, SSL VPN login/tunnel/session activity, SSL VPN session errors, VPN certificate and SSL setting changes, PPTP, L2TP, and FortiClient VPN endpoint connect/disconnect events.

### System and Infrastructure
Configuration changes, system lifecycle, resource exhaustion, IPS fail-open, interface changes, hardware health, routing, SD-WAN, licensing, FortiAnalyzer connectivity, integrity violations, DHCP, Security Fabric, IoC traffic, and log upload failures.

### Frequency / Correlation
| Rule | Trigger | Threshold |
|------|---------|-----------|
| 118250 | Admin brute force | 5 failures / 60 s (same srcip) |
| 118251 | Admin brute force escalation | 10 failures / 120 s (same srcip) |
| 118252 | Firewall deny flood (port scan / attack) | 15 denies / 60 s (same srcip) |
| 118253 | IPS attack campaign | 5 IPS alerts / 120 s (same srcip) |
| 118254 | Malware spread from infected host | 3 detections / 120 s (same srcip) |
| 118255 | Connection flood / scan | 20 failed connections / 60 s (same srcip) |
| 118256 | Data exfiltration attempt | 3 DLP violations / 300 s (same srcip) |
| 118257 | Web attack campaign | 5 WAF blocks / 60 s (same srcip) |
| 118283 | SSL VPN brute force | 5 failures / 300 s (same remip) |
| 118284 | SSL VPN brute force escalation | 10 failures / 600 s (same remip) |
| 118285 | User auth failure burst | 8 failures / 300 s (same srcip) |
| 118286 | User auth targeted failures | 5 failures / 300 s (same user) |
| 118287 | IPsec tunnel flapping | 3 disconnects / 600 s (same remip) |
| 118288 | SSL VPN tunnel flapping | 3 disconnects / 600 s (same user) |
| 118289 | IPsec negotiation error burst | 5 errors / 300 s (same remip) |
| 118290 | MFA/FortiToken failure burst | 3 failures / 300 s (same user) |
| 118291 | Unauthenticated management CMDB burst | 5 events / 300 s (same devid) |
| 118292 | FNBAM auth error burst | 5 events / 300 s (same devid) |
| 118293 | PPP auth failure burst | 5 failures / 300 s (same user) |
| 118294 | Auth lockout/timeout burst | 3 events / 300 s (same user) |

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

- **PCI DSS** (1.3.4, 5.1, 6.5, 6.6, 8.x, 10.2.x, 10.5.x, 10.6.x, 10.7, 11.4)
- **GDPR** (IV 30.1.g, IV 32.2, IV 35.7.d)
- **HIPAA** (164.312.b)
- **NIST 800-53** (AC, AU, CM, IA, SC, SI)
- **GPG13** (4.13, 7.1, 10.3)

## MITRE ATT&CK Coverage

Selected technique IDs mapped in rules:

`T1014` `T1046` `T1048` `T1059` `T1071` `T1078` `T1087` `T1090.004` `T1102` `T1110` `T1110.001` `T1133` `T1190` `T1204.002` `T1485` `T1498` `T1499` `T1529` `T1542` `T1542.001` `T1557` `T1562` `T1562.001` `T1566` `T1566.002` `T1571`

## Installation

### 1. FortiGate syslog configuration

Configure FortiGate to send JSON-format syslog to Wazuh:

```bash
config log syslogd setting
    set status enable
    set server <WAZUH_MANAGER_IP>
    set port 514
    set format json
end
```

> **Note:** When using JSON format, the syslog header `program_name` field is set to the device name (`devname` value). Wazuh receives the raw JSON payload after the syslog prefix.

### 2. Deploy rules

```bash
cp rules/fortigate-json_rules.xml /var/ossec/etc/rules/
```

### 3. Restart Wazuh manager

```bash
systemctl restart wazuh-manager
```

### 4. Verify with wazuh-logtest

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
