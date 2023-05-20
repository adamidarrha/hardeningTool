from types import (
    SimpleNamespace,  # https://docs.python.org/3/library/types.html#types.SimpleNamespace
)
from typing import Generator
from tests.integration import (
    shellexec,  # https://docs.python.org/3/library/typing.html#typing.Generator
)
import subprocess  # https://docs.python.org/3/library/subprocess.html

def _shellexec(command: str) -> "SimpleNamespace[str, str, int]":
        """Execute shell command on the system. Supports piped commands

        Parameters
        ----------
        command : string, required
            Shell command to execute

        Returns
        -------
        Namespace:

        """

        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output = result.stdout.decode('UTF-8').split('\n')
        error = result.stderr.decode('UTF-8').split('\n')
        returncode = result.returncode

        if len(output) > 1:
            output.pop(-1)

        if len(error) > 1:
            error.pop(-1)

        data = SimpleNamespace(stdout=output, stderr=error, returncode=returncode)

        return data
    

def audit_kernel_module_is_disabled(module: str) -> int:
        state = 0
        
        cmd1 = f'modprobe -n -v {module}'
        cmd2 = f'lsmod | grep {module}'

        r1 = _shellexec(cmd1)
        r2 = _shellexec(cmd2)

        if r1.stdout[0] == 'install /bin/true ':
            pass
        elif r1.stderr[0] == f'modprobe: FATAL: Module {module} not found.':
            pass
        else:
            state = 1

        if module in r2.stdout[0]:
            state = 2

        print(state)
        return state

def fat(module):
     if module == "vfat":
        uefi_enabled = _shellexec('ls /sys/firmware/efi', shell=True, capture_output=True).returncode == 0

        if uefi_enabled:
            fstab_output = _shellexec('grep -i vfat /etc/fstab', shell=True, capture_output=True, text=True)
        if fstab_output.stdout:
            print("UEFI: FAT filesystem found in /etc/fstab")
            print(fstab_output.stdout)
        else:
            print("UEFI: No FAT filesystem found in /etc/fstab")
        
        audit_kernel_module_is_disabled("vfat")

fat("vfat")