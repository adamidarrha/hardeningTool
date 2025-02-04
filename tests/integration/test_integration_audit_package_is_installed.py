#!/usr/bin/env python3

import pytest

from cis_audit import Centos7Audit


def test_integration_audit_package_is_installed_pass():
    state = Centos7Audit().audit_package_is_installed(package='rsync')
    assert state == 0


def test_integration_audit_package_is_installed_fail():
    state = Centos7Audit().audit_package_is_installed(package='pytest')
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
