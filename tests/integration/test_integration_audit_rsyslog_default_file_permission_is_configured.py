#!/usr/bin/env python3

import os

import pytest

from cis_audit import Centos7Audit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass():
    ## Setup
    print(shellexec("echo '$FileCreateMode 0640' >> /etc/rsyslog.d/pytest.conf"))

    yield None

    ## Tear-down
    os.remove('/etc/rsyslog.d/pytest.conf')


def test_integration_audit_rsyslog_default_file_permission_is_configured_pass(setup_to_pass):
    state = Centos7Audit().audit_rsyslog_default_file_permission_is_configured()
    assert state == 0


def test_integration_audit_rsyslog_default_file_permission_is_configured_fail():
    state = Centos7Audit().audit_rsyslog_default_file_permission_is_configured()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
