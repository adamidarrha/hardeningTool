import subprocess

def get_package_management_system(self):
        package_managers = {
            'rpm': ['rpm'],
            'dpkg': ['dpkg']
        }

        for manager, commands in package_managers.items():
            for command in commands:
                try:
                    self._shellexec(command)
                    return manager
                except FileNotFoundError:
                    pass

        return None

def check_x_windows_installed():
    package_management = get_package_management_system()

    if package_management == 'rpm':
        command = 'rpm -qa xorg-x11*'
    elif package_management == 'dpkg':
        command = 'dpkg -l xserver-xorg*'
    else:
        print("Unsupported package management system.")
        return None

    try:
        output = subprocess.run(command, shell=True, capture_output=True, text=True)
        if output.returncode == 0 and not output.stdout:
            print("X Window System is not installed.")
            return 0
        else:
            print("X Window System is installed.")
            return 1
    except FileNotFoundError:
        print("Package management command not found.")
        return None

# Example usage
state = check_x_windows_installed()
if state is not None:
    print("State:", state)
