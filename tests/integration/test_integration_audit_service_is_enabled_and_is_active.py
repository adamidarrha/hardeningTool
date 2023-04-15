#!/usr/bin/env python3

import pytest

from cis_audit import Centos7Audit


def test_service_is_enabled_and_is_active_pass():
    state = Centos7Audit().audit_service_is_enabled_and_is_active(service='sshd')
    assert state == 0


def test_service_is_enabled_and_is_active_fail():
    state = Centos7Audit().audit_service_is_enabled_and_is_active(service='rsyncd')
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
