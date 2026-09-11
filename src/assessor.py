from collections import Counter
from .models import Finding, RDPHost


def assess(host: RDPHost) -> list[Finding]:
    out: list[Finding] = []
    def add(cid, title, severity, score, why, fix, check, attack=()):
        out.append(Finding(cid, title, severity, score, host.hostname, why, fix, check, tuple(attack)))

    if host.internet_exposed:
        add('RDP-001','RDP exposed to the internet','Critical',95,'Direct exposure of RDP materially increases attack surface for credential abuse and service exploitation.','Place RDP behind approved remote-access controls, restrict source networks and remove direct internet exposure.','Confirm TCP/3389 is unreachable from unapproved external networks while approved administration still works.',('T1133','T1021.001','T1190'))
    if not host.nla_enabled:
        add('RDP-002','Network Level Authentication disabled','High',82,'NLA reduces pre-authentication exposure and should normally be required for modern RDP deployments.','Enable NLA after compatibility validation.','Confirm clients must authenticate before full RDP session establishment.',('T1021.001',))
    if not host.mfa_enabled:
        add('RDP-003','MFA absent for remote administration','Critical',90,'Single-factor remote administration increases risk from stolen or reused credentials.','Enforce strong MFA through the approved remote-access and privileged-access path.','Verify normal and privileged RDP access cannot complete without the approved second factor.',('T1078','T1021.001'))
    if not host.restricted_admin:
        add('RDP-004','Restricted Admin mode not enforced','Medium',60,'Standard RDP credential handling can increase exposure of reusable credentials on remote hosts.','Evaluate Restricted Admin or equivalent protected-admin patterns for suitable privileged workflows.','Validate the approved administrative workflow and confirm credentials are not unnecessarily exposed to the remote host.',('T1550','T1021.001'))
    if host.encryption_level.lower() in {'low','client-compatible','weak'}:
        add('RDP-005','Weak RDP encryption configuration','High',78,'The declared RDP encryption level does not meet the intended hardened baseline.','Require organization-approved encryption and TLS policy for RDP.','Confirm clients negotiate only the approved protected configuration.',('T1021.001',))
    if host.allow_drive_redirection:
        add('RDP-006','Drive redirection enabled','Medium',52,'Drive redirection can create an unnecessary data transfer path in privileged sessions.','Disable drive redirection where not required, or scope it to approved use cases.','Confirm unapproved local drives are unavailable in the remote session.',('T1021.001','T1041'))
    if host.allow_clipboard_redirection:
        add('RDP-007','Clipboard redirection enabled','Low',35,'Clipboard sharing can increase accidental or unauthorized data transfer between trust zones.','Disable or constrain clipboard redirection for privileged/admin sessions where business need does not require it.','Confirm clipboard transfer is blocked or limited according to policy.',('T1021.001',))
    if host.idle_timeout_minutes == 0 or host.idle_timeout_minutes > 30:
        add('RDP-008','Idle session timeout is weak','Medium',50,'Long-lived unattended administrative sessions increase exposure and reduce session hygiene.','Apply an approved idle disconnect/logoff threshold appropriate to administrative use.','Confirm idle sessions are disconnected or logged off within policy.',('T1078',))
    if host.lockout_threshold == 0 or host.lockout_threshold > 10:
        add('RDP-009','Account lockout protection is weak','High',70,'A missing or very high threshold can weaken resistance to repeated authentication attempts.','Apply an identity lockout or smart-throttling policy aligned with the central authentication standard.','Confirm repeated failed logons trigger the expected protective control without causing unsafe denial-of-service conditions.',('T1110','T1021.001'))
    if not host.logging_enabled:
        add('RDP-010','RDP security logging disabled','High',74,'Missing logon and session telemetry weakens detection and incident reconstruction.','Enable and centrally retain relevant Windows logon, RDP session and policy-change telemetry.','Perform an authorized test session and confirm complete events arrive in monitoring.',('T1562.001','T1021.001'))
    if host.privileged_group_count > 5:
        add('RDP-011','Broad privileged access to RDP host','High',76,'Large privileged groups increase standing administrative exposure and complicate accountability.','Reduce standing privilege using role-based, time-bound or just-in-time access where available.','Re-query effective privileged membership and confirm only approved administrators remain.',('T1078','T1098'))
    if not host.owner.strip():
        add('GOV-001','RDP service owner missing','Medium',45,'Remediation and exceptions require accountable service ownership.','Assign a system/service owner and document responsibility for access and hardening.','Confirm ownership in the asset inventory and change process.')
    return sorted(out, key=lambda f: f.score, reverse=True)


def metrics(findings: list[Finding]) -> dict:
    c = Counter(f.severity for f in findings)
    return {'findings': len(findings), 'critical_high': c['Critical'] + c['High'], 'highest_score': max((f.score for f in findings), default=0), 'severity_counts': dict(c)}
