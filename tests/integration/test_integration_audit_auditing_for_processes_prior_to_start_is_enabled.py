#!/usr/bin/env python3

import os
import shutil

import pytest

from cis_audit import Centos7Audit
from tests.integration import shellexec

efi_contents = [
    '''#''',
    '''# DO NOT EDIT THIS FILE''',
    '''#''',
    '''# It is automatically generated by grub2-mkconfig using templates''',
    '''# from /etc/grub.d and settings from /etc/default/grub''',
    '''#''',
    '''''',
    '''### BEGIN /etc/grub.d/00_header ###''',
    '''set pager=1''',
    '''''',
    '''if [ -s $prefix/grubenv ]; then''',
    '''  load_env''',
    '''fi''',
    '''if [ "${next_entry}" ] ; then''',
    '''   set default="${next_entry}"''',
    '''   set next_entry=''',
    '''   save_env next_entry''',
    '''   set boot_once=true''',
    '''else''',
    '''   set default="${saved_entry}"''',
    '''fi''',
    '''''',
    '''if [ x"${feature_menuentry_id}" = xy ]; then''',
    '''  menuentry_id_option="--id"''',
    '''else''',
    '''  menuentry_id_option=""''',
    '''fi''',
    '''''',
    '''export menuentry_id_option''',
    '''''',
    '''if [ "${prev_saved_entry}" ]; then''',
    '''  set saved_entry="${prev_saved_entry}"''',
    '''  save_env saved_entry''',
    '''  set prev_saved_entry=''',
    '''  save_env prev_saved_entry''',
    '''  set boot_once=true''',
    '''fi''',
    '''''',
    '''function savedefault {''',
    '''  if [ -z "${boot_once}" ]; then''',
    '''    saved_entry="${chosen}"''',
    '''    save_env saved_entry''',
    '''  fi''',
    '''}''',
    '''''',
    '''function load_video {''',
    '''  if [ x$feature_all_video_module = xy ]; then''',
    '''    insmod all_video''',
    '''  else''',
    '''    insmod efi_gop''',
    '''    insmod efi_uga''',
    '''    insmod ieee1275_fb''',
    '''    insmod vbe''',
    '''    insmod vga''',
    '''    insmod video_bochs''',
    '''    insmod video_cirrus''',
    '''  fi''',
    '''}''',
    '''''',
    '''terminal_output console''',
    '''if [ x$feature_timeout_style = xy ] ; then''',
    '''  set timeout_style=menu''',
    '''  set timeout=5''',
    '''# Fallback normal timeout code in case the timeout_style feature is''',
    '''# unavailable.''',
    '''else''',
    '''  set timeout=5''',
    '''fi''',
    '''### END /etc/grub.d/00_header ###''',
    '''''',
    '''### BEGIN /etc/grub.d/00_tuned ###''',
    '''set tuned_params=""''',
    '''set tuned_initrd=""''',
    '''### END /etc/grub.d/00_tuned ###''',
    '''''',
    '''### BEGIN /etc/grub.d/01_users ###''',
    '''if [ -f ${prefix}/user.cfg ]; then''',
    '''  source ${prefix}/user.cfg''',
    '''  if [ -n "${GRUB2_PASSWORD}" ]; then''',
    '''    set superusers="root"''',
    '''    export superusers''',
    '''    password_pbkdf2 root ${GRUB2_PASSWORD}''',
    '''  fi''',
    '''fi''',
    '''### END /etc/grub.d/01_users ###''',
    '''''',
    '''### BEGIN /etc/grub.d/10_linux ###''',
    '''menuentry 'Red Hat Enterprise Linux Server (3.10.0-1160.76.1.el7.x86_64) 7.9 (Maipo)' --class red --class gnu-linux --class gnu --class os --unrestricted $menuentry_id_option 'gnulinux-3.10.0-1160.el7.x86_64-advanced-d10c891f-66e6-49ea-9622-9aac355376b8' {''',
    '''	load_video''',
    '''	set gfxpayload=keep''',
    '''	insmod gzio''',
    '''	insmod part_gpt''',
    '''	insmod xfs''',
    '''	set root='hd0,gpt2' ''',
    '''	if [ x$feature_platform_search_hint = xy ]; then''',
    '''	  search --no-floppy --fs-uuid --set=root --hint-bios=hd0,gpt2 --hint-efi=hd0,gpt2 --hint-baremetal=ahci0,gpt2  4117a0a4-0a7b-4961-a6ea-60bff72b59ae''',
    '''	else''',
    '''	  search --no-floppy --fs-uuid --set=root 4117a0a4-0a7b-4961-a6ea-60bff72b59ae''',
    '''	fi''',
    '''	linuxefi /vmlinuz-3.10.0-1160.76.1.el7.x86_64 root=/dev/mapper/luks--vg0-root ro spectre_v2=retpoline rd.luks.uuid=luks-b9618ac8-12e9-4a22-912e-7618180959d1 rd.lvm.lv=luks-vg0/root rd.lvm.lv=luks-vg0/swap rhgb quiet LANG=en_NZ.UTF-8''',
    '''	initrdefi /initramfs-3.10.0-1160.76.1.el7.x86_64.img''',
    '''}''',
    '''menuentry 'Red Hat Enterprise Linux Server (3.10.0-1160.71.1.el7.x86_64) 7.9 (Maipo)' --class red --class gnu-linux --class gnu --class os --unrestricted $menuentry_id_option 'gnulinux-3.10.0-1160.el7.x86_64-advanced-d10c891f-66e6-49ea-9622-9aac355376b8' {''',
    '''	load_video''',
    '''	set gfxpayload=keep''',
    '''	insmod gzio''',
    '''	insmod part_gpt''',
    '''	insmod xfs''',
    '''	set root='hd0,gpt2' ''',
    '''	if [ x$feature_platform_search_hint = xy ]; then''',
    '''	  search --no-floppy --fs-uuid --set=root --hint-bios=hd0,gpt2 --hint-efi=hd0,gpt2 --hint-baremetal=ahci0,gpt2  4117a0a4-0a7b-4961-a6ea-60bff72b59ae''',
    '''	else''',
    '''	  search --no-floppy --fs-uuid --set=root 4117a0a4-0a7b-4961-a6ea-60bff72b59ae''',
    '''	fi''',
    '''	linuxefi /vmlinuz-3.10.0-1160.71.1.el7.x86_64 root=/dev/mapper/luks--vg0-root ro spectre_v2=retpoline rd.luks.uuid=luks-b9618ac8-12e9-4a22-912e-7618180959d1 rd.lvm.lv=luks-vg0/root rd.lvm.lv=luks-vg0/swap rhgb quiet LANG=en_NZ.UTF-8''',
    '''	initrdefi /initramfs-3.10.0-1160.71.1.el7.x86_64.img''',
    '''}''',
    '''menuentry 'Red Hat Enterprise Linux Server (3.10.0-1160.66.1.el7.x86_64) 7.9 (Maipo)' --class red --class gnu-linux --class gnu --class os --unrestricted $menuentry_id_option 'gnulinux-3.10.0-1160.el7.x86_64-advanced-d10c891f-66e6-49ea-9622-9aac355376b8' {''',
    '''	load_video''',
    '''	set gfxpayload=keep''',
    '''	insmod gzio''',
    '''	insmod part_gpt''',
    '''	insmod xfs''',
    '''	set root='hd0,gpt2' ''',
    '''	if [ x$feature_platform_search_hint = xy ]; then''',
    '''	  search --no-floppy --fs-uuid --set=root --hint-bios=hd0,gpt2 --hint-efi=hd0,gpt2 --hint-baremetal=ahci0,gpt2  4117a0a4-0a7b-4961-a6ea-60bff72b59ae''',
    '''	else''',
    '''	  search --no-floppy --fs-uuid --set=root 4117a0a4-0a7b-4961-a6ea-60bff72b59ae''',
    '''	fi''',
    '''	linuxefi /vmlinuz-3.10.0-1160.66.1.el7.x86_64 root=/dev/mapper/luks--vg0-root ro spectre_v2=retpoline rd.luks.uuid=luks-b9618ac8-12e9-4a22-912e-7618180959d1 rd.lvm.lv=luks-vg0/root rd.lvm.lv=luks-vg0/swap rhgb quiet LANG=en_NZ.UTF-8''',
    '''	initrdefi /initramfs-3.10.0-1160.66.1.el7.x86_64.img''',
    '''}''',
    '''menuentry 'Red Hat Enterprise Linux Server (3.10.0-1160.62.1.el7.x86_64) 7.9 (Maipo)' --class red --class gnu-linux --class gnu --class os --unrestricted $menuentry_id_option 'gnulinux-3.10.0-1160.el7.x86_64-advanced-d10c891f-66e6-49ea-9622-9aac355376b8' {''',
    '''	load_video''',
    '''	set gfxpayload=keep''',
    '''	insmod gzio''',
    '''	insmod part_gpt''',
    '''	insmod xfs''',
    '''	set root='hd0,gpt2' ''',
    '''	if [ x$feature_platform_search_hint = xy ]; then''',
    '''	  search --no-floppy --fs-uuid --set=root --hint-bios=hd0,gpt2 --hint-efi=hd0,gpt2 --hint-baremetal=ahci0,gpt2  4117a0a4-0a7b-4961-a6ea-60bff72b59ae''',
    '''	else''',
    '''	  search --no-floppy --fs-uuid --set=root 4117a0a4-0a7b-4961-a6ea-60bff72b59ae''',
    '''	fi''',
    '''	linuxefi /vmlinuz-3.10.0-1160.62.1.el7.x86_64 root=/dev/mapper/luks--vg0-root ro spectre_v2=retpoline rd.luks.uuid=luks-b9618ac8-12e9-4a22-912e-7618180959d1 rd.lvm.lv=luks-vg0/root rd.lvm.lv=luks-vg0/swap rhgb quiet LANG=en_NZ.UTF-8''',
    '''	initrdefi /initramfs-3.10.0-1160.62.1.el7.x86_64.img''',
    '''}''',
    '''menuentry 'Red Hat Enterprise Linux Server (3.10.0-1160.59.1.el7.x86_64) 7.9 (Maipo)' --class red --class gnu-linux --class gnu --class os --unrestricted $menuentry_id_option 'gnulinux-3.10.0-1160.el7.x86_64-advanced-d10c891f-66e6-49ea-9622-9aac355376b8' {''',
    '''	load_video''',
    '''	set gfxpayload=keep''',
    '''	insmod gzio''',
    '''	insmod part_gpt''',
    '''	insmod xfs''',
    '''	set root='hd0,gpt2' ''',
    '''	if [ x$feature_platform_search_hint = xy ]; then''',
    '''	  search --no-floppy --fs-uuid --set=root --hint-bios=hd0,gpt2 --hint-efi=hd0,gpt2 --hint-baremetal=ahci0,gpt2  4117a0a4-0a7b-4961-a6ea-60bff72b59ae''',
    '''	else''',
    '''	  search --no-floppy --fs-uuid --set=root 4117a0a4-0a7b-4961-a6ea-60bff72b59ae''',
    '''	fi''',
    '''	linuxefi /vmlinuz-3.10.0-1160.59.1.el7.x86_64 root=/dev/mapper/luks--vg0-root ro spectre_v2=retpoline rd.luks.uuid=luks-b9618ac8-12e9-4a22-912e-7618180959d1 rd.lvm.lv=luks-vg0/root rd.lvm.lv=luks-vg0/swap rhgb quiet LANG=en_NZ.UTF-8''',
    '''	initrdefi /initramfs-3.10.0-1160.59.1.el7.x86_64.img''',
    '''}''',
    '''menuentry 'Red Hat Enterprise Linux Server (0-rescue-7964c89d229140d1be4c8001e4952e50) 7.9 (Maipo)' --class red --class gnu-linux --class gnu --class os --unrestricted $menuentry_id_option 'gnulinux-0-rescue-7964c89d229140d1be4c8001e4952e50-advanced-d10c891f-66e6-49ea-9622-9aac355376b8' {''',
    '''	load_video''',
    '''	insmod gzio''',
    '''	insmod part_gpt''',
    '''	insmod xfs''',
    '''	set root='hd0,gpt2' ''',
    '''	if [ x$feature_platform_search_hint = xy ]; then''',
    '''	  search --no-floppy --fs-uuid --set=root --hint-bios=hd0,gpt2 --hint-efi=hd0,gpt2 --hint-baremetal=ahci0,gpt2  4117a0a4-0a7b-4961-a6ea-60bff72b59ae''',
    '''	else''',
    '''	  search --no-floppy --fs-uuid --set=root 4117a0a4-0a7b-4961-a6ea-60bff72b59ae''',
    '''	fi''',
    '''	linuxefi /vmlinuz-0-rescue-7964c89d229140d1be4c8001e4952e50 root=/dev/mapper/luks--vg0-root ro spectre_v2=retpoline rd.luks.uuid=luks-b9618ac8-12e9-4a22-912e-7618180959d1 rd.lvm.lv=luks-vg0/root rd.lvm.lv=luks-vg0/swap rhgb quiet''',
    '''	initrdefi /initramfs-0-rescue-7964c89d229140d1be4c8001e4952e50.img''',
    '''}''',
    '''''',
    '''### END /etc/grub.d/10_linux ###''',
    '''''',
    '''### BEGIN /etc/grub.d/20_linux_xen ###''',
    '''### END /etc/grub.d/20_linux_xen ###''',
    '''''',
    '''### BEGIN /etc/grub.d/20_ppc_terminfo ###''',
    '''### END /etc/grub.d/20_ppc_terminfo ###''',
    '''''',
    '''### BEGIN /etc/grub.d/30_os-prober ###''',
    '''### END /etc/grub.d/30_os-prober ###''',
    '''''',
    '''### BEGIN /etc/grub.d/40_custom ###''',
    '''# This file provides an easy way to add custom menu entries.  Simply type the''',
    '''# menu entries you want to add after this comment.  Be careful not to change''',
    '''# the 'exec tail' line above.''',
    '''### END /etc/grub.d/40_custom ###''',
    '''''',
    '''### BEGIN /etc/grub.d/41_custom ###''',
    '''if [ -f  ${config_directory}/custom.cfg ]; then''',
    '''  source ${config_directory}/custom.cfg''',
    '''elif [ -z "${config_directory}" -a -f  $prefix/custom.cfg ]; then''',
    '''  source $prefix/custom.cfg;''',
    '''fi''',
    '''### END /etc/grub.d/41_custom ###''',
]


@pytest.fixture()
def setup_to_pass_grub():
    shutil.copy('/boot/grub2/grub.cfg', '/boot/grub2/grub.cfg.bak')
    shellexec("sed -i '/linux16/ s/$/ audit=1/' /boot/grub2/grub.cfg")

    yield None

    shutil.move('/boot/grub2/grub.cfg.bak', '/boot/grub2/grub.cfg')


@pytest.fixture
def setup_to_pass_efi():
    shutil.move('/boot/grub2/grub.cfg', '/boot/grub2/grub.cfg.bak')

    if not os.path.exists('/boot/efi/EFI/redhat/'):
        os.mkdir('/boot/efi/EFI/redhat/')

    with open('/boot/efi/EFI/redhat/grub.cfg', 'w') as f:
        f.writelines(efi_contents)

    yield None

    os.remove('/boot/efi/EFI/redhat/grub.cfg')
    shutil.move('/boot/grub2/grub.cfg.bak', '/boot/grub2/grub.cfg')


@pytest.fixture
def setup_to_fail():
    shutil.move('/boot/grub2/grub.cfg', '/boot/grub2/grub.cfg.bak')

    yield None

    shutil.move('/boot/grub2/grub.cfg.bak', '/boot/grub2/grub.cfg')


def test_audit_auditing_for_processes_prior_to_start_is_enabled_pass_efidir(setup_to_pass_efi):
    state = Centos7Audit().audit_auditing_for_processes_prior_to_start_is_enabled()
    assert state == 0


def test_audit_auditing_for_processes_prior_to_start_is_enabled_pass_grub(setup_to_pass_grub):
    state = Centos7Audit().audit_auditing_for_processes_prior_to_start_is_enabled()
    assert state == 0


def test_audit_auditing_for_processes_prior_to_start_is_enabled_fail(setup_to_fail):
    state = Centos7Audit().audit_auditing_for_processes_prior_to_start_is_enabled()
    assert state == 1


if __name__ == '__main__':
    pytest.main([__file__, '--no-cov'])
