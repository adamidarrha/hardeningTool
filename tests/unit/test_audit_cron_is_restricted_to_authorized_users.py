#!/usr/bin/env python3

import os
from unittest.mock import patch

import pytest

from cis_audit import Centos7Audit


def mock_os_path_exists_pass(file):
    if file == '/etc/cron.deny':
        return False
    elif file == '/etc/cron.allow':
        return True
    else:
        raise Exception


def mock_os_path_exists_fail(file):
    if file == '/etc/cron.deny':
        return True
    elif file == '/etc/cron.allow':
        return False
    else:
        raise Exception


@patch.object(os.path, "exists", mock_os_path_exists_pass)
@patch.object(Centos7Audit, "audit_file_permissions", return_value=0)
def test_audit_cron_is_restricted_to_authorized_users_pass(*args):
    state = Centos7Audit().audit_cron_is_restricted_to_authorized_users()
    assert state == 0


@patch.object(os.path, "exists", mock_os_path_exists_fail)
@patch.object(Centos7Audit, "audit_file_permissions", return_value=1)
def test_audit_cron_is_restricted_to_authorized_users_fail_exists(*args):
    state = Centos7Audit().audit_cron_is_restricted_to_authorized_users()
    assert state == 3


@patch.object(os.path, "exists", return_value=True)
@patch.object(Centos7Audit, "audit_file_permissions", return_value=1)
def test_audit_cron_is_restricted_to_authorized_users_fail_permissions(*args):
    state = Centos7Audit().audit_cron_is_restricted_to_authorized_users()
    assert state == 5


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
