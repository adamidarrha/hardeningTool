#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import Centos7Audit

test = Centos7Audit()


def mock_audit_events_for_file_deletion_by_users_are_collected_pass(self, cmd):
    if 'auditctl' in cmd:
        stdout = [
            "-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete",
            "-a always,exit -F arch=b32 -S unlink,rename,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete",
        ]
    else:
        stdout = [
            "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete",
            "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete",
        ]
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_audit_events_for_file_deletion_by_users_are_collected_fail(self, cmd):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(Centos7Audit, "_shellexec", mock_audit_events_for_file_deletion_by_users_are_collected_pass)
def test_audit_events_for_file_deletion_by_users_are_collected_pass():
    state = test.audit_events_for_file_deletion_by_users_are_collected()
    assert state == 0


@patch.object(Centos7Audit, "_shellexec", mock_audit_events_for_file_deletion_by_users_are_collected_fail)
def test_audit_events_for_file_deletion_by_users_are_collected_fail():
    state = test.audit_events_for_file_deletion_by_users_are_collected()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
