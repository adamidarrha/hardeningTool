#!/usr/bin/env python3

import os

import pytest

from cis_audit import Centos7Audit
from tests.integration import shellexec


@pytest.fixture()
def setup_to_pass():
    rules = [
        '-w /var/run/utmp -p wa -k session',
        '-w /var/log/wtmp -p wa -k logins',
        '-w /var/log/btmp -p wa -k logins',
    ]

    for rule in rules:
        print(shellexec(f'echo "{rule}" >> /etc/audit/rules.d/pytest.rules'))
        print(shellexec(f'auditctl {rule}'))

    yield None

    print(shellexec('cat /etc/audit/rules.d/pytest.rules'))
    print(shellexec('auditctl -l'))

    os.remove('/etc/audit/rules.d/pytest.rules')
    shellexec('auditctl -D')


def test_integration_audit_events_for_session_initiation_are_collected_pass(setup_to_pass):
    state = Centos7Audit().audit_events_for_session_initiation_are_collected()
    assert state == 0


def test_integration_audit_events_for_session_initiation_are_collected_fail():
    state = Centos7Audit().audit_events_for_session_initiation_are_collected()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
