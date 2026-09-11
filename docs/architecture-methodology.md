# RDP Security Assessment Methodology

## Purpose
This repository models a defensive RDP hardening review using supplied synthetic host configuration. It does not establish RDP sessions or attempt authentication.

## Architecture
`synthetic JSON -> fail-closed validation -> RDPHost model -> control assessment -> prioritized findings -> remediation and revalidation report`

## Control domains
The current control catalog covers direct internet exposure, Network Level Authentication, MFA, Restricted Admin mode, RDP encryption level, drive/clipboard redirection, idle timeout, account lockout protection, centralized logging, privileged-group scope and accountable ownership.

## Risk model
Scores are deterministic prioritization values, not CVSS scores. Direct internet exposure and absent MFA receive the highest weight. Findings remain independently actionable so a team can remediate identity, exposure, session, telemetry and privilege controls separately.

## ATT&CK context
Mappings include T1133, T1021.001, T1190, T1078, T1110, T1098, T1550, T1041 and T1562.001 where relevant. These are defensive classification references, not assertions of compromise.

## Validation approach
Every finding includes a post-change validation criterion. Closure should verify the intended control state and legitimate administrative functionality. Examples include confirming external TCP/3389 exposure is removed, MFA is enforced, RDP telemetry reaches monitoring, and privileged membership has been reduced to approved users.

## Safety
No brute-force logic, password spraying, credential capture, exploit delivery, session hijacking, persistence, scanning or production targeting is included.
