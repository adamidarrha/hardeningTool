#!/usr/bin/env python3

import pytest

from cis_audit import Centos7Audit


def test_integration_audit_selinux_mode_not_disabled_pass_enforcing(setup_selinux_enforcing):
    state = Centos7Audit().audit_selinux_mode_not_disabled()
    assert state == 0


def test_integration_audit_selinux_mode_not_disabled_pass_permissive(setup_selinux_permissive):
    state = Centos7Audit().audit_selinux_mode_not_disabled()
    assert state == 0


def test_integration_audit_selinux_mode_not_disabled_fail_disabled(setup_selinux_disabled):
    state = Centos7Audit().audit_selinux_mode_not_disabled()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
