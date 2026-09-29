# Incident Report: slow password spraying and anonymous SMB enumeration

**Author:** Houssam Zouheir
**Environment:** Azure honeynet (2 Windows VMs, 1 Linux VM), Microsoft Sentinel

## Timeline (UTC)

| Date / time | Event |
|---|---|
| 27/09 06:27 | First anonymous SMB session (LogonType 3) from 186.67.38.171 |
| 28/09 00:56 | Anonymous sessions begin from 118.99.103.253 (206 events, about 1/second) |
| 28/09 13:39 | First 4625 failure from 218.147.202.136 in the filtered query (password spraying) |
| 28/09 18:50 – 19:40 | Spraying bursts from 186.10.4.106, 186.72.55.152 and 182.191.72.12 (5 – 10 accounts per 10 min) |
| 28/09 20:00 – 20:50 | 94.26.68.54 (5 accounts, about 30 attempts/10 min) and 218.147.202.136 (14 accounts, 1 attempt per account/10 min) |
| 29/09 13:33 | Last 4625 failure from 218.147.202.136 in the filtered query (168 attempts on 7 names) |

## Indicators of compromise

- **Spraying:** 218.147.202.136, 186.10.4.106, 186.72.55.152, 182.191.72.12, 94.26.68.54; accounts include `ADMIN1`–`ADMIN5`, `TESTUSER`, `AZUREADMIN`
- **Anonymous SMB enumeration:** 118.99.103.253, 14.172.156.19, 186.67.38.171, 81.10.4.117, 154.192.120.183
- **RDP brute-force:** 193.24.123.39 (AbuseIPDB: 200 reports / 46 sources)

## Impact

No real account was compromised. Five IPs established anonymous SMB sessions on `windows-vm`, revealing that port 445 was exposed before hardening (possible enumeration of shares and accounts).

## Detection

Sentinel Rules 1–5 (see `../queries/`). The 10-minute spraying hunting query (5+ distinct accounts) detected all five spraying IPs. Rule 4 adds a 24-hour lookback to also catch slower sprays.

## Remediation

- NSG restricted to allow-listed IPs (ports 445 and 3389 closed to the internet)
- Just-In-Time VM Access
- MFA on administrative access

## MITRE ATT&CK

| Technique | ID |
|---|---|
| Network service discovery / port scan | T1046 |
| Brute force: password guessing | T1110.001 |
| Brute force: password spraying | T1110.003 |
| Network share discovery | T1135 |
| Account discovery | T1087 |
| Valid accounts (attempted) | T1078 |
