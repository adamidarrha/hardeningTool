#!/usr/bin/env python3


import pytest

from cis_audit import Centos7Audit
from tests.integration import shellexec


@pytest.fixture
def setup_to_pass_masked():
    shellexec('systemctl mask rsyncd')

    yield None

    shellexec('systemctl unmask rsyncd')


@pytest.fixture
def setup_to_pass_not_installed():
    shellexec('yum remove -y rsync')

    yield None

    shellexec('yum install -y rsync')


def test_audit_package_not_installed_or_service_is_masked_pass_not_installed(setup_to_pass_not_installed):
    state = Centos7Audit().audit_package_not_installed_or_service_is_masked(package='rsync', service='rsyncd')
    assert state == 0


def test_audit_package_not_installed_or_service_is_masked_pass_masked(setup_to_pass_masked):
    state = Centos7Audit().audit_package_not_installed_or_service_is_masked(package='rsync', service='rsyncd')
    assert state == 0


def test_audit_package_not_installed_or_service_is_masked_fail():
    state = Centos7Audit().audit_package_not_installed_or_service_is_masked(package='rsync', service='rsyncd')
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
