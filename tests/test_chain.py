import os

import pytest

from qbb.chain import ChainLogger, verify_chain


@pytest.fixture
def logfile(tmp_path):
    key0 = os.urandom(32)
    p = str(tmp_path / "t.log")
    lg = ChainLogger(p, key0)
    for i in range(10):
        lg.append(f"event {i}", ts=1000.0 + i)
    return p, key0


def _rewrite(path, fn):
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    fn(lines)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def test_clean_log_verifies(logfile):
    p, k = logfile
    r = verify_chain(p, k)
    assert r.ok and r.entries == 10


def test_edit_detected_at_index(logfile):
    p, k = logfile
    _rewrite(p, lambda L: L.__setitem__(3, L[3].replace("event 3", "event X")))
    r = verify_chain(p, k)
    assert not r.ok and r.bad_index == 3


def test_deletion_detected(logfile):
    p, k = logfile
    _rewrite(p, lambda L: L.pop(4))
    r = verify_chain(p, k)
    assert not r.ok and r.bad_index == 4


def test_wrong_key_rejected(logfile):
    p, _ = logfile
    assert not verify_chain(p, os.urandom(32)).ok


def test_refuses_overwrite(logfile):
    p, k = logfile
    with pytest.raises(FileExistsError):
        ChainLogger(p, k)
