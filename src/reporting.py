from .assessor import metrics
from .models import Finding


def markdown_report(findings: list[Finding]) -> str:
    m = metrics(findings)
    lines = ['# RDP Security Assessment', '', '> Synthetic offline hardening assessment. No live RDP connections, authentication attempts, scanning or exploitation were performed.', '', '## Executive metrics', '', f"- Findings: **{m['findings']}**", f"- Critical/High: **{m['critical_high']}**", f"- Highest score: **{m['highest_score']}/100**", '', '## Prioritized findings', '']
    for f in findings:
        lines += [f'### {f.severity} — {f.control_id}: {f.title}', '', f'- Host: `{f.host}`', f'- Score: **{f.score}/100**', f"- ATT&CK context: {', '.join(f.attack) if f.attack else 'governance'}", '', f'**Rationale:** {f.rationale}', '', f'**Remediation:** {f.remediation}', '', f'**Validation:** {f.validation}', '']
    return '\n'.join(lines)
