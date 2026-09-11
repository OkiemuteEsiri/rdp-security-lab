import argparse
from pathlib import Path
from .assessor import assess
from .io import load_hosts
from .reporting import markdown_report


def main():
    p = argparse.ArgumentParser(description='Assess supplied RDP hardening metadata offline')
    p.add_argument('input')
    p.add_argument('--output', default='rdp-assessment.md')
    a = p.parse_args()
    findings = [f for host in load_hosts(a.input) for f in assess(host)]
    Path(a.output).write_text(markdown_report(findings), encoding='utf-8')
    print(f'Wrote {a.output} with {len(findings)} findings')


if __name__ == '__main__':
    main()
