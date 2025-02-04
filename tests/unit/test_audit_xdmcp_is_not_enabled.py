#!/usr/bin/env python3

import os
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import Centos7Audit

test = Centos7Audit()


def mock_xdmcp_not_enabled_pass(*args, **kwargs):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_xdmcp_not_enabled_fail(*args, **kwargs):
    stdout = ['Enabled=true']
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_os_path_exists_pass(file):
    return True


@patch.object(Centos7Audit, "_shellexec", mock_xdmcp_not_enabled_pass)
def test_audit_xdmcp_not_enabled_pass():
    state = test.audit_xdmcp_not_enabled()
    assert state == 0


@patch.object(os.path, "exists", mock_os_path_exists_pass)
@patch.object(Centos7Audit, "_shellexec", mock_xdmcp_not_enabled_fail)
def test_audit_xdmcp_not_enabled_fail():
    state = test.audit_xdmcp_not_enabled()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
