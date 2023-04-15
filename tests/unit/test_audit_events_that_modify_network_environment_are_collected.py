#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import Centos7Audit

test = Centos7Audit()


def mock_audit_events_that_modify_network_environment_are_collected_pass(self, cmd):
    if 'auditctl' in cmd:
        stdout = [
            '-a always,exit -F arch=b64 -S sethostname,setdomainname -F key=system-locale',
            '-a always,exit -F arch=b32 -S sethostname,setdomainname -F key=system-locale',
            '-w /etc/issue -p wa -k system-locale',
            '-w /etc/issue.net -p wa -k system-locale',
            '-w /etc/hosts -p wa -k system-locale',
            '-w /etc/sysconfig/network -p wa -k system-locale',
        ]
    else:
        stdout = [
            '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale',
            '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale',
            '-w /etc/issue -p wa -k system-locale',
            '-w /etc/issue.net -p wa -k system-locale',
            '-w /etc/hosts -p wa -k system-locale',
            '-w /etc/sysconfig/network -p wa -k system-locale',
        ]
    stderr = ['']
    returncode = 0

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_audit_events_that_modify_network_environment_are_collected_fail(self, cmd):
    stdout = ['']
    stderr = ['']
    returncode = 1

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


@patch.object(Centos7Audit, "_shellexec", mock_audit_events_that_modify_network_environment_are_collected_pass)
def test_audit_events_that_modify_network_environment_are_collected_pass():
    state = test.audit_events_that_modify_network_environment_are_collected()
    assert state == 0


@patch.object(Centos7Audit, "_shellexec", mock_audit_events_that_modify_network_environment_are_collected_fail)
def test_audit_events_that_modify_network_environment_are_collected_fail():
    state = test.audit_events_that_modify_network_environment_are_collected()
    assert state == 3


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
