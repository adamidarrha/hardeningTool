#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import Centos7Audit

test = Centos7Audit()


def mock_password_expiration_min_days_is_configured_pass(self, cmd):
    returncode = 0
    stderr = ['']

    if 'PASS_MIN_DAYS' in cmd:
        stdout = ['PASS_MIN_DAYS    1']
    elif 'shadow' in cmd:
        stdout = [
            'root:1',
            'vagrant:1',
        ]

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_password_expiration_min_days_is_configured_fail(self, cmd):
    returncode = 0
    stderr = ['']

    if 'PASS_MIN_DAYS' in cmd:
        stdout = ['PASS_MIN_DAYS    0']
    elif 'shadow' in cmd:
        stdout = [
            'root:0',
            'vagrant:0',
        ]

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(Centos7Audit, "_shellexec", mock_password_expiration_min_days_is_configured_pass)
def test_audit_password_expiration_min_days_is_configured_pass():
    state = test.audit_password_change_minimum_delay()
    assert state == 0


@patch.object(Centos7Audit, "_shellexec", mock_password_expiration_min_days_is_configured_fail)
def test_audit_password_expiration_min_days_is_configured_pass_fail():
    state = test.audit_password_change_minimum_delay()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
