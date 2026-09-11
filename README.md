# RDP Security Lab

A defensive Network Security and Windows hardening project for assessing Remote Desktop Protocol configuration against exposure, identity, session, telemetry and privilege controls.

The lab is intentionally **offline**. It consumes synthetic configuration metadata and performs no RDP connections, credential testing, scanning or exploitation.

## Why this project exists
RDP is often treated as a single service-port problem, but secure remote administration depends on several layers working together: network exposure, authentication, credential protection, encryption, session restrictions, logging and privileged-access governance. This repository models those layers as explainable controls with remediation and post-change validation criteria.

## Architecture

```text
Synthetic RDP host metadata
            |
            v
    fail-closed validation
            |
            v
       RDPHost model
            |
            v
    hardening assessment
            |
            v
 risk + ATT&CK classification
            |
            v
 remediation / revalidation report
```

## Control coverage
- direct internet exposure of RDP
- Network Level Authentication (NLA)
- MFA for remote administration
- Restricted Admin / protected-admin workflow
- RDP encryption level
- drive and clipboard redirection
- idle session timeout
- account lockout / authentication throttling
- centralized RDP and Windows logon telemetry
- standing privileged-group scope
- accountable service ownership

## Repository structure

```text
src/
  models.py
  assessor.py
  io.py
  reporting.py
  cli.py
data/
  synthetic_hosts.json
tests/
  test_assessor.py
docs/
  architecture-methodology.md
reports/
  example-assessment.md
.github/workflows/
  ci.yml
```

## Run locally
Python 3.12+; no third-party packages required.

```bash
python -m src.cli data/synthetic_hosts.json --output rdp-assessment.md
python -m unittest discover -s tests -v
```

## Risk model
The engine uses deterministic 0–100 prioritization scores. They are not CVSS values and do not prove exploitability. Direct internet exposure and missing MFA receive the strongest weighting, followed by missing NLA, weak cryptography, missing telemetry and broad privileged access.

## ATT&CK context
Mappings include **T1133 External Remote Services**, **T1021.001 Remote Desktop Protocol**, **T1190 Exploit Public-Facing Application**, **T1078 Valid Accounts**, **T1110 Brute Force**, **T1098 Account Manipulation**, **T1550 Use Alternate Authentication Material**, **T1041 Exfiltration Over C2 Channel**, and **T1562.001 Impair Defenses** where relevant. These are defensive context only, not claims of compromise.

## Remediation lifecycle
`assess -> validate business context -> prioritize -> change under control -> authorized functional/security retest -> capture evidence -> close or rework`

Every finding includes an explicit validation criterion. For example, removing internet exposure should be followed by confirming TCP/3389 is unreachable from unapproved external networks while approved administration remains functional.

## Skills demonstrated
Windows security, network hardening, identity security, privileged access governance, Python security automation, risk communication, ATT&CK mapping, remediation assurance, unit testing and CI/CD.

## CI
GitHub Actions runs Python compilation, ten unit tests and an offline CLI smoke test using read-only repository permissions.

## Limitations and safety
This repository does not brute force RDP, spray passwords, capture credentials, hijack sessions, deliver exploits, create persistence, scan networks or target production systems. All bundled systems are synthetic. Real assessments require explicit authorization, vendor-supported configuration review and carefully controlled retesting.

## Roadmap
- Add gateway and jump-host policy profiles.
- Add event-log validation scenarios for 4624/4625 and TerminalServices channels.
- Add just-in-time access metadata.
- Add certificate/TLS policy fields.
- Add remediation before/after comparison.
- Add JSON/CSV executive exports.
