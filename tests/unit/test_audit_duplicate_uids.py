#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import Centos7Audit

test = Centos7Audit()


def mock_duplicate_uids_pass(self, cmd):
    returncode = 0
    stderr = ['']
    stdout = ['']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_duplicate_uids_fail(self, cmd):
    returncode = 0
    stderr = ['']
    stdout = ['1000']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(Centos7Audit, "_shellexec", mock_duplicate_uids_pass)
def test_audit_duplicate_uids_pass():
    state = test.audit_duplicate_uids()
    assert state == 0


@patch.object(Centos7Audit, "_shellexec", mock_duplicate_uids_fail)
def test_audit_duplicate_uids_fail():
    state = test.audit_duplicate_uids()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
