#!/usr/bin/env python3

import os

import pytest

from cis_audit import Centos7Audit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_pass():
    file_rules = [
        '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access',
        '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access',
        '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access',
        '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access',
    ]
    auditctl_rules = [
        "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F 'auid>=1000' -F 'auid!=4294967295' -k access",
        "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F 'auid>=1000' -F 'auid!=4294967295' -k access",
        "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F 'auid>=1000' -F 'auid!=4294967295' -k access",
        "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F 'auid>=1000' -F 'auid!=4294967295' -k access",
    ]

    for rule in file_rules:
        print(shellexec(f'echo "{rule}" >> /etc/audit/rules.d/pytest.rules'))

    for rule in auditctl_rules:
        print(shellexec(f'auditctl {rule}'))

    yield None

    print(shellexec('cat /etc/audit/rules.d/pytest.rules'))
    print(shellexec('auditctl -l'))

    os.remove('/etc/audit/rules.d/pytest.rules')
    shellexec('auditctl -D')


def test_integration_audit_events_for_unsuccessful_file_access_attempts_are_collected_pass(setup_to_pass):
    state = Centos7Audit().audit_events_for_unsuccessful_file_access_attempts_are_collected()
    assert state == 0


def test_integration_audit_events_for_unsuccessful_file_access_attempts_are_collected_fail():
    state = Centos7Audit().audit_events_for_unsuccessful_file_access_attempts_are_collected()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
