import subprocess

def run_apparmor_audit():
    apparmor_output = subprocess.run('apparmor_status', shell=True, capture_output=True, text=True)

    if apparmor_output.returncode == 0:
        apparmor_lines = apparmor_output.stdout.strip().split('\n')
        loaded_profiles = []
        enforce_profiles = []
        complain_profiles = []
        defined_processes = []
        enforce_processes = []
        unconfined_processes = []

        for line in apparmor_lines:
            if 'profiles are loaded.' in line:
                loaded_profiles_count = int(line.split()[0])
            elif 'profiles are in enforce mode.' in line:
                enforce_profiles_count = int(line.split()[0])
            elif 'profiles are in complain mode.' in line:
                complain_profiles_count = int(line.split()[0])
            elif 'processes have profiles defined.' in line:
                defined_processes_count = int(line.split()[0])
            elif 'processes are in enforce mode' in line:
                enforce_processes_count = int(line.split()[0])
            elif 'processes are in complain mode' in line:
                complain_processes_count = int(line.split()[0])
            elif 'processes are unconfined but have a profile defined' in line:
                unconfined_processes_count = int(line.split()[0])
            else:
                # Parse profile and process information
                if line.startswith('/'):
                    profile, process = line.split()
                    loaded_profiles.append(profile)
                    defined_processes.append(process)
                    if '(enforce)' in line:
                        enforce_profiles.append(profile)
                        enforce_processes.append(process)
                    elif '(complain)' in line:
                        complain_profiles.append(profile)
                    elif '(unconfined)' in line:
                        unconfined_processes.append(process)

        print("AppArmor module is loaded.")
        print(f"{loaded_profiles_count} profiles are loaded.")
        print(f"{enforce_profiles_count} profiles are in enforce mode.")
        print('\n'.join(loaded_profiles))
        print(f"{complain_profiles_count} profiles are in complain mode.")
        print(f"{defined_processes_count} processes have profiles defined.")
        print(f"{enforce_processes_count} processes are in enforce mode:")
        print('\n'.join(enforce_processes))
        print(f"{complain_processes_count} processes are in complain mode.")
        print(f"{unconfined_processes_count} processes are unconfined but have a profile defined.")
    else:
        print("Unable to run apparmor_status command.")

# Run the audit
run_apparmor_audit()
