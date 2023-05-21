import subprocess

def check_apparmor_grub():
    grep_output = subprocess.run('grep "^\s*kernel" /boot/grub/menu.lst', shell=True, capture_output=True, text=True)

    if grep_output.returncode == 0:
        kernel_lines = grep_output.stdout.strip().split('\n')
        apparmor_present = False

        for line in kernel_lines:
            if 'apparmor=0' in line:
                apparmor_present = True
                break

        if apparmor_present:
            print("AppArmor parameter (apparmor=0) is set in /boot/grub/menu.lst")
        else:
            print("AppArmor parameter is not set in /boot/grub/menu.lst")
    else:
        print("Unable to find /boot/grub/menu.lst file")

def check_apparmor_grub2():
    grep_output = subprocess.run('grep "^\s*linux" /boot/grub/grub.cfg', shell=True, capture_output=True, text=True)

    if grep_output.returncode == 0:
        linux_lines = grep_output.stdout.strip().split('\n')
        apparmor_present = False

        for line in linux_lines:
            if 'apparmor=0' in line:
                apparmor_present = True
                break

        if apparmor_present:
            print("AppArmor parameter (apparmor=0) is set in /boot/grub/grub.cfg")
        else:
            print("AppArmor parameter is not set in /boot/grub/grub.cfg")
    else:
        print("Unable to find /boot/grub/grub.cfg file")

# Run the audit
check_apparmor_grub()

# Run the audit
check_apparmor_grub2()
