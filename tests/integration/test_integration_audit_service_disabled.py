#!/usr/bin/env python3

import pytest

from cis_audit import Centos7Audit


def test_integration_audit_service_disabled_pass():
    state = Centos7Audit().audit_service_is_disabled(service='rsyncd')
    assert state == 0


def test_integration_audit_service_disabled_fail():
    state = Centos7Audit().audit_service_is_disabled(service='sshd')
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
