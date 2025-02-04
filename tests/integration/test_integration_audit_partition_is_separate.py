#!/usr/bin/env python3

import pytest

from cis_audit import Centos7Audit


def test_integration_audit_partition_is_separate():
    state = Centos7Audit().audit_partition_is_separate(partition='/boot')
    assert state == 0


def test_integration_audit_partition_is_not_separate():
    state = Centos7Audit().audit_partition_is_separate(partition='/var')
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
