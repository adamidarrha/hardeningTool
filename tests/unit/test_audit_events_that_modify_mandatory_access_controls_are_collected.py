#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import Centos7Audit

test = Centos7Audit()


def mock_audit_events_that_modify_mandatory_access_controls_are_collected_pass(self, cmd):
    stdout = [
        '-w /etc/selinux -p wa -k MAC-policy',
        '-w /usr/share/selinux -p wa -k MAC-policy',
    ]
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_audit_events_that_modify_mandatory_access_controls_are_collected_fail(self, cmd):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(Centos7Audit, "_shellexec", mock_audit_events_that_modify_mandatory_access_controls_are_collected_pass)
def test_audit_events_that_modify_mandatory_access_controls_are_collected_pass():
    state = test.audit_events_that_modify_mandatory_access_controls_are_collected()
    assert state == 0


@patch.object(Centos7Audit, "_shellexec", mock_audit_events_that_modify_mandatory_access_controls_are_collected_fail)
def test_audit_events_that_modify_mandatory_access_controls_are_collected_fail():
    state = test.audit_events_that_modify_mandatory_access_controls_are_collected()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
