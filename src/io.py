import json
from pathlib import Path
from .models import RDPHost


def load_hosts(path: str) -> list[RDPHost]:
    raw = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(raw, list):
        raise ValueError('input must be a JSON array')
    hosts = [RDPHost.from_dict(x) for x in raw]
    ids = [h.host_id for h in hosts]
    if len(ids) != len(set(ids)):
        raise ValueError('duplicate host_id')
    return hosts
