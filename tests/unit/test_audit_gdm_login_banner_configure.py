#!/usr/bin/env python3

import os
from unittest.mock import mock_open, patch

import pytest

# from cis_audit import Centos7Audit
import cis_audit

test = cis_audit.Centos7Audit()


def mock_audit_package_is_installed_true(*args, **kwargs):
    return 0


def mock_audit_package_is_installed_false(*args, **kwargs):
    return 1


@patch.object(cis_audit.Centos7Audit, "audit_package_is_installed", mock_audit_package_is_installed_false)
def test_audit_gdm_login_banner_configured_skipped():
    state = test.audit_gdm_login_banner_configured()
    assert state == -2


@patch.object(cis_audit.Centos7Audit, "audit_package_is_installed", mock_audit_package_is_installed_true)
def test_audit_gdm_login_banner_configured_fail_files_not_found():
    state = test.audit_gdm_login_banner_configured()
    assert state == 17


@patch.object(cis_audit, "open", mock_open())
@patch.object(os.path, "exists", return_value=True)
@patch.object(cis_audit.Centos7Audit, "audit_package_is_installed", mock_audit_package_is_installed_true)
def test_audit_gdm_login_banner_configured_fail(MagickMock):
    state = test.audit_gdm_login_banner_configured()
    assert state == 46


@patch.object(cis_audit, "open", mock_open(read_data='user-db:user\nsystem-db:gdm\nfile-db:/usr/share/gdm/greeter-dconf-defaults\n[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text='))
@patch.object(os.path, "exists", return_value=True)
@patch.object(cis_audit.Centos7Audit, "audit_package_is_installed", mock_audit_package_is_installed_true)
def test_audit_gdm_login_banner_configured_pass(MagickMock):
    state = test.audit_gdm_login_banner_configured()
    assert state == 0


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
