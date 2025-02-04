#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import Centos7Audit

test = Centos7Audit()


def mock_password_inactive_lock_is_configured_pass(self, cmd):
    returncode = 0
    stderr = ['']

    if 'INACTIVE' in cmd:
        stdout = ['INACTIVE=30']
    elif 'shadow' in cmd:
        stdout = [
            'root:30',
            'vagrant:30',
        ]

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_password_inactive_lock_is_configured_fail(self, cmd):
    returncode = 0
    stderr = ['']

    if 'INACTIVE' in cmd:
        stdout = ['INACTIVE=99999']
    elif 'shadow' in cmd:
        stdout = [
            'root:99999',
            'vagrant:99999',
        ]

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_password_inactive_lock_is_configured_fail_disabled(self, cmd):
    returncode = 0
    stderr = ['']

    if 'INACTIVE' in cmd:
        stdout = ['INACTIVE=-1']
    elif 'shadow' in cmd:
        stdout = [
            'root:',
            'vagrant:',
        ]

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(Centos7Audit, "_shellexec", mock_password_inactive_lock_is_configured_pass)
def test_audit_password_inactive_lock_is_configured_pass():
    state = test.audit_password_inactive_lock_is_configured()
    assert state == 0


@patch.object(Centos7Audit, "_shellexec", mock_password_inactive_lock_is_configured_fail)
def test_audit_password_inactive_lock_is_configured_fail():
    state = test.audit_password_inactive_lock_is_configured()
    assert state == 3


@patch.object(Centos7Audit, "_shellexec", mock_password_inactive_lock_is_configured_fail_disabled)
def test_audit_password_inactive_lock_is_configured_fail_disabled():
    state = test.audit_password_inactive_lock_is_configured()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
