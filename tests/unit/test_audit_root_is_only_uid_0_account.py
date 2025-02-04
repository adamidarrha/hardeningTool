#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import Centos7Audit

test = Centos7Audit()


def mock_root_is_only_uid_0_account_pass(self, cmd):
    returncode = 0
    stderr = ['']
    stdout = ['root']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_root_is_only_uid_0_account_fail(self, cmd):
    returncode = 0
    stderr = ['']
    stdout = ['root', 'pytest']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(Centos7Audit, "_shellexec", mock_root_is_only_uid_0_account_pass)
def test_audit_root_is_only_uid_0_account_pass():
    state = test.audit_root_is_only_uid_0_account()
    assert state == 0


@patch.object(Centos7Audit, "_shellexec", mock_root_is_only_uid_0_account_fail)
def test_audit_root_is_only_uid_0_account_fail():
    state = test.audit_root_is_only_uid_0_account()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
