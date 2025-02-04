#!/usr/bin/env python3

import shutil

import pytest

from cis_audit import Centos7Audit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass():
    shutil.copy('/etc/systemd/journald.conf', '/etc/systemd/journald.conf.bak')
    shellexec("sed -i 's/.*Storage=.*/Storage=persistent/' /etc/systemd/journald.conf")

    yield None

    shutil.move('/etc/systemd/journald.conf.bak', '/etc/systemd/journald.conf')


def test_integration_audit_journald_configured_to_write_logfiles_to_disk_pass(setup_to_pass):
    state = Centos7Audit().audit_journald_configured_to_write_logfiles_to_disk()
    assert state == 0


def test_integration_audit_journald_configured_to_write_logfiles_to_disk_fail():
    state = Centos7Audit().audit_journald_configured_to_write_logfiles_to_disk()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
