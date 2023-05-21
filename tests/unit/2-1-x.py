import subprocess

def run_module_audit(module_name):
    state = 1

    grep_command = f'grep -R "^{module_name}" /etc/inetd.*'
    module_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True)

    if module_output.returncode == 0 and not module_output.stdout:
        xinetd_conf_command = f'grep "disable = yes" /etc/xinetd.conf'
        xinetd_d_command = f'grep "disable = yes" /etc/xinetd.d/*'
        xinetd_conf_output = subprocess.run(xinetd_conf_command, shell=True, capture_output=True, text=True)
        xinetd_d_output = subprocess.run(xinetd_d_command, shell=True, capture_output=True, text=True)

        if xinetd_conf_output.returncode == 0 and not xinetd_conf_output.stdout and \
           xinetd_d_output.returncode == 0 and not xinetd_d_output.stdout:
            print(f"{module_name} service is not enabled.")
            state = 0
    else:
        state = 2
    return state

# Example usage
module = 'chargen'
state = run_module_audit(module)
print("State:", state)
