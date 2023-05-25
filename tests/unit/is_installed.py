import subprocess

def get_package_management_system():
    package_managers = {
        'rpm': ['rpm'],
        'dpkg': ['dpkg']
    }

    for manager, commands in package_managers.items():
        for command in commands:
            try:
                subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return manager
            except FileNotFoundError:
                pass

    return None

def check_module_installed(module_name):
    package_management = get_package_management_system()

    if package_management == 'rpm':
        command = f'rpm -q {module_name}'
    elif package_management == 'dpkg':
        command = f'dpkg -s {module_name}'
    else:
        print("Unsupported package management system.")
        return None

    try:
        output = subprocess.run(command, shell=True, capture_output=True, text=True)
        if output.returncode == 0:
            print(f"{module_name} is installed.")
            return 0
        else:
            print(f"{module_name} is not installed.")
            return 1
    except FileNotFoundError:
        print("Package management command not found.")
        return None

# Example usage
module_name = input("Enter the module name to check: ")
state = check_module_installed(module_name)
if state is not None:
    print("State:", state)
