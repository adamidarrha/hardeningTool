import subprocess

def check_interactive_boot():
    grep_output = subprocess.run('grep "^PROMPT_FOR_CONFIRM=" /etc/sysconfig/boot', shell=True, capture_output=True, text=True)

    if grep_output.returncode == 0:
        prompt_for_confirm = grep_output.stdout.strip().split('=')[1].strip('"')
        if prompt_for_confirm == 'no':
            print("Interactive boot is disabled")
        else:
            print("Interactive boot is enabled")
    else:
        print("Unable to find the PROMPT_FOR_CONFIRM option in /etc/sysconfig/boot")

# Run the audit
check_interactive_boot()
