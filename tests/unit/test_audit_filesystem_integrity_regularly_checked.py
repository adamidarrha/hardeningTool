#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import Centos7Audit


def mock_filesystem_integrity_pass_cron(self, cmd):
    output = ['/etc/cron.d/aide-check']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_filesystem_integrity_pass_systemd(self, cmd, *args, **kwargs):
    if 'is-enabled' in cmd:
        output = ['enabled']
        error = ['']
        returncode = 0
    elif 'is-active' in cmd:
        output = ['active']
        error = ['']
        returncode = 0
    else:
        output = ['']
        error = ['']
        returncode = 1

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_filesystem_integrity_fail(self, cmd):
    output = ['']
    error = ['']
    returncode = 1

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_filesystem_integrity_error(self, cmd):
    raise Exception


@patch.object(Centos7Audit, "_shellexec", mock_filesystem_integrity_pass_cron)
def test_filesystem_integrity_pass_crond():
    state = Centos7Audit().audit_filesystem_integrity_regularly_checked()
    assert state == 0


@patch.object(Centos7Audit, "_shellexec", mock_filesystem_integrity_pass_systemd)
def test_filesystem_integrity_pass_systemd():
    state = Centos7Audit().audit_filesystem_integrity_regularly_checked()
    assert state == 0


@patch.object(Centos7Audit, "_shellexec", mock_filesystem_integrity_fail)
def test_filesystem_integrity_fail():
    state = Centos7Audit().audit_filesystem_integrity_regularly_checked()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
