#!/usr/bin/env python3

import shutil

import pytest

from cis_audit import Centos7Audit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass():
    ## Setup
    shutil.copy('/etc/login.defs', '/etc/login.defs.bak')
    shutil.copy('/etc/shadow', '/etc/shadow.bak')

    shellexec(R"sed -i 's/^\s*PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs")
    shellexec("sed -i -E '/(root|vagrant):/ s/0:99999/7:99999/' /etc/shadow")

    yield None

    ## Tear-down
    shutil.move('/etc/login.defs.bak', '/etc/login.defs')
    shutil.move('/etc/shadow.bak', '/etc/shadow')


def test_integration_audit_password_expiration_min_days_is_configured_pass(setup_to_pass):
    state = Centos7Audit().audit_password_change_minimum_delay()
    assert state == 0


def test_integration_audit_password_expiration_min_days_is_configured_fail():
    state = Centos7Audit().audit_password_change_minimum_delay()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
