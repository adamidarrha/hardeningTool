#!/usr/bin/env python3

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cis_audit import Centos7Audit


def mock_iptables_default_deny_pass(self, cmd):
    returncode = 0
    stderr = ['']

    if 'INPUT' in cmd:
        stdout = ['-P INPUT DROP']
    elif 'FORWARD' in cmd:
        stdout = ['-P FORWARD DROP']
    elif 'OUTPUT' in cmd:
        stdout = ['-P OUTPUT DROP']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


def mock_iptables_default_deny_fail(self, cmd):
    stderr = ['']
    returncode = 1

    if 'INPUT' in cmd:
        stdout = ['-P INPUT ACCEPT']
    elif 'FORWARD' in cmd:
        stdout = ['-P FORWARD ACCEPT']
    elif 'OUTPUT' in cmd:
        stdout = ['-P OUTPUT ACCEPT']

    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)


test = Centos7Audit()


@patch.object(Centos7Audit, "_shellexec", mock_iptables_default_deny_pass)
def test_audit_iptables_default_deny_pass_ipv4():
    state = test.audit_iptables_default_deny_policy(ip_version='ipv4')
    assert state == 0


@patch.object(Centos7Audit, "_shellexec", mock_iptables_default_deny_fail)
def test_audit_iptables_default_deny_fail_ipv4():
    state = test.audit_iptables_default_deny_policy(ip_version='ipv4')
    assert state == 7


@patch.object(Centos7Audit, "_shellexec", mock_iptables_default_deny_pass)
def test_audit_iptables_default_deny_pass_ipv6():
    state = test.audit_iptables_default_deny_policy(ip_version='ipv6')
    assert state == 0


@patch.object(Centos7Audit, "_shellexec", mock_iptables_default_deny_fail)
def test_audit_iptables_default_deny_fail_ipv6():
    state = test.audit_iptables_default_deny_policy(ip_version='ipv6')
    assert state == 7


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
