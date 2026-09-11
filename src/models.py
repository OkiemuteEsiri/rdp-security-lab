from dataclasses import dataclass
from datetime import datetime


def utc(value: str) -> datetime:
    ts = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if ts.tzinfo is None:
        raise ValueError('timestamp must be timezone-aware')
    return ts


@dataclass(frozen=True)
class RDPHost:
    host_id: str
    hostname: str
    internet_exposed: bool
    nla_enabled: bool
    mfa_enabled: bool
    restricted_admin: bool
    encryption_level: str
    allow_drive_redirection: bool
    allow_clipboard_redirection: bool
    idle_timeout_minutes: int
    lockout_threshold: int
    logging_enabled: bool
    privileged_group_count: int
    owner: str

    @classmethod
    def from_dict(cls, row: dict) -> 'RDPHost':
        required = ('host_id','hostname','internet_exposed','nla_enabled','mfa_enabled','restricted_admin','encryption_level','allow_drive_redirection','allow_clipboard_redirection','idle_timeout_minutes','lockout_threshold','logging_enabled','privileged_group_count','owner')
        missing = [k for k in required if k not in row]
        if missing:
            raise ValueError('missing required fields: ' + ', '.join(missing))
        if int(row['idle_timeout_minutes']) < 0 or int(row['lockout_threshold']) < 0 or int(row['privileged_group_count']) < 0:
            raise ValueError('numeric values must be non-negative')
        return cls(str(row['host_id']), str(row['hostname']), bool(row['internet_exposed']), bool(row['nla_enabled']), bool(row['mfa_enabled']), bool(row['restricted_admin']), str(row['encryption_level']), bool(row['allow_drive_redirection']), bool(row['allow_clipboard_redirection']), int(row['idle_timeout_minutes']), int(row['lockout_threshold']), bool(row['logging_enabled']), int(row['privileged_group_count']), str(row['owner']))


@dataclass(frozen=True)
class Finding:
    control_id: str
    title: str
    severity: str
    score: int
    host: str
    rationale: str
    remediation: str
    validation: str
    attack: tuple[str, ...]
