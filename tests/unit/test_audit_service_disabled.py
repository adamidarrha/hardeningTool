#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import Centos7Audit


def mock_disabled(*args, **kwargs):
    output = ['disabled']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_enabled(*args, **kwargs):
    output = ['enabled']
    error = ['']
    returncode = 0

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


def mock_error(*args, **kwargs):
    output = ['']
    error = ['Failed to get unit file state for pytest.service: No such file or directory']
    returncode = 1

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)


class TestServiceDisabled:
    test = Centos7Audit()
    test_id = '1.1'
    test_service = 'pytest'

    @patch.object(Centos7Audit, "_shellexec", mock_disabled)
    def test_service_disabled_pass(self):
        state = self.test.audit_service_is_disabled(self.test_service)
        assert state == 0

    @patch.object(Centos7Audit, "_shellexec", mock_enabled)
    def test_service_disabled_fail(self):
        state = self.test.audit_service_is_disabled(self.test_service)
        assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
