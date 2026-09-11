import unittest
from src.assessor import assess, metrics
from src.models import RDPHost


def host(**kw):
    base = dict(host_id='H1', hostname='LAB', internet_exposed=False, nla_enabled=True, mfa_enabled=True, restricted_admin=True, encryption_level='high', allow_drive_redirection=False, allow_clipboard_redirection=False, idle_timeout_minutes=15, lockout_threshold=5, logging_enabled=True, privileged_group_count=2, owner='owner')
    base.update(kw)
    return RDPHost(**base)


class Tests(unittest.TestCase):
    def test_secure_baseline_clean(self): self.assertEqual(assess(host()), [])
    def test_internet_exposed(self): self.assertTrue(any(f.control_id == 'RDP-001' for f in assess(host(internet_exposed=True))))
    def test_nla(self): self.assertTrue(any(f.control_id == 'RDP-002' for f in assess(host(nla_enabled=False))))
    def test_mfa(self): self.assertTrue(any(f.control_id == 'RDP-003' for f in assess(host(mfa_enabled=False))))
    def test_drive_redirection(self): self.assertTrue(any(f.control_id == 'RDP-006' for f in assess(host(allow_drive_redirection=True))))
    def test_idle_timeout(self): self.assertTrue(any(f.control_id == 'RDP-008' for f in assess(host(idle_timeout_minutes=60))))
    def test_lockout(self): self.assertTrue(any(f.control_id == 'RDP-009' for f in assess(host(lockout_threshold=0))))
    def test_logging(self): self.assertTrue(any(f.control_id == 'RDP-010' for f in assess(host(logging_enabled=False))))
    def test_privilege_scope(self): self.assertTrue(any(f.control_id == 'RDP-011' for f in assess(host(privileged_group_count=8))))
    def test_metrics(self): self.assertEqual(metrics(assess(host(mfa_enabled=False)))['critical_high'], 1)


if __name__ == '__main__': unittest.main()
