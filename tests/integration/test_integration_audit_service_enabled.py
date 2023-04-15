#!/usr/bin/env python3

import pytest

from cis_audit import Centos7Audit


def test_integration_audit_service_enabled_pass():
    state = Centos7Audit().audit_service_is_enabled(service='sshd')
    assert state == 0


def test_integration_audit_service_enabled_fail():
    state = Centos7Audit().audit_service_is_enabled(service='rsyncd')
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
