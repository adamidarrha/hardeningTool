#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import Centos7Audit


def mock_mta_pass(self, cmd):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_mta_fail(self, cmd):
    stdout = ['0.0.0.0:25']
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


class TestMTAIsLocalhost:
    test = Centos7Audit()
    test_id = '1.1'

    @patch.object(Centos7Audit, "_shellexec", mock_mta_pass)
    def test_mta_is_localhost_pass(self):
        state = self.test.audit_mta_is_localhost_only()
        assert state == 0

    @patch.object(Centos7Audit, "_shellexec", mock_mta_fail)
    def test_mta_is_localhost_fail(self):
        state = self.test.audit_mta_is_localhost_only()
        assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
