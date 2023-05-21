#!/usr/bin/env python3

# Copyright (C) 2022 Andy Dustin <andy.dustin@gmail.com>
# This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.
# https://creativecommons.org/licenses/by-nc-sa/4.0/

# This unofficial tool checks for your system against published CIS Hardening Benchmarks and offers an indication of your system's preparedness for compliance to the official standard.

# You can obtain a copy of the CIS Benchmarks from https://www.cisecurity.org/cis-benchmarks/
# Use of the CIS Benchmarks are subject to the Terms of Use for Non-Member CIS Products - https://www.cisecurity.org/terms-of-use-for-non-member-cis-products

### Imports ###
import platform # https://docs.python.org/3/library/platform.html
import json  # https://docs.python.org/3/library/json.html
import logging  # https://docs.python.org/3/library/logging.html
import os  # https://docs.python.org/3/library/os.html
import pdb  # noqa https://docs.python.org/3/library/pdb.html
import re  # https://docs.python.org/3/library/re.html
import stat  # https://docs.python.org/3/library/stat.html
import subprocess  # https://docs.python.org/3/library/subprocess.html
from datetime import (
    datetime,  # https://docs.python.org/3/library/datetime.html#datetime.datetime
)
if platform.system() == "Linux":
    from grp import getgrgid  # https://docs.python.org/3/library/grp.html#grp.getgrgid
    from pwd import getpwuid  # https://docs.python.org/3/library/pwd.html#pwd.getpwuid
from types import (
    SimpleNamespace,  # https://docs.python.org/3/library/types.html#types.SimpleNamespace
)
from typing import Generator
from tests.integration import (
    shellexec,  # https://docs.python.org/3/library/typing.html#typing.Generator
)


### Classes ###
#put all os independant functions here
class CISAudit:
    def __init__(self, config):
        if config:
            self.config = config
        else:
            self.config = SimpleNamespace(includes=None, excludes=None, level=0, system_type='server', log_level='DEBUG')

        logging.basicConfig(
            format='%(asctime)s [%(levelname)s]: %(funcName)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
        )

        self.log = logging.getLogger(__name__)
        self.log.setLevel(self.config.log_level)
    
    def output(self, format: str, data: list) -> None:
        if format in ['csv', 'psv', 'tsv']:
            if format == 'csv':
                sep = ','
            elif format == 'psv':
                sep = '|'
            elif format == 'tsv':
                sep = '\t'

            self.output_csv(data, separator=sep)

        elif format == 'json':
            self.output_json(data)

        elif format == 'text':
            self.output_text(data)

    def output_csv(self, data: list, separator: str):
        ## Shorten the variable name so that it's easier to construct the print's below
        sep = separator

        ## Print Header
        print(f'ID{sep}Description{sep}Level{sep}Result{sep}Duration')

        ## Print Data
        for record in data:
            if len(record) == 2:
                print(f'{record[0]}{sep}"{record[1]}"{sep}{sep}{sep}')
            elif len(record) == 4:
                print(f'{record[0]}{sep}"{record[1]}"{sep}{record[2]}{sep}{record[3]}{sep}')
            elif len(record) == 5:
                print(f'{record[0]}{sep}"{record[1]}"{sep}{record[2]}{sep}{record[3]}{sep}{record[4]}')

    def output_json(self, data):
        output = {}

        for record in data:
            id = record[0]
            output[id] = {}
            output[id]['description'] = record[1]

            if len(record) >= 3:
                output[id]['level'] = record[2]

            if len(record) >= 4:
                output[id]['result'] = record[3]

            if len(record) >= 5:
                output[id]['duration'] = record[4]

        print(json.dumps(output))

    def output_text(self, data):
        ## Set starting/minimum width of columns to fit the column headers
        width_id = len("ID")
        width_description = len("Description")
        width_level = len("Level")
        width_result = len("Result")
        width_duration = len("Duration")

        ## Find the max width of each column
        for row in data:
            row_length = len(row)

            ## In the following section, len_level and len_duration are commented out because the
            ## headers are wider than the data in the rows, so they currently don't need expanding.
            ## If I leave them uncommented, then codecov complains about the tests not covering them.

            len_id = len(str(row[0])) if row_length >= 1 else None
            len_description = len(str(row[1])) if row_length >= 2 else None
            # len_level = len(str(row[2])) if row_length >= 3 else None
            len_result = len(str(row[3])) if row_length >= 4 else None
            # len_duration = len(str(row[4])) if row_length >= 5 else None

            if len_id and len_id > width_id:
                width_id = len_id
                # print(f'Width for ID expanded to {width_id}')

            if len_description and len_description > width_description:
                width_description = len_description

            # if len_level and len_level > width_level:
            #    width_level = len_level

            if len_result and len_result > width_result:
                width_result = len_result

            # if len_duration and len_duration > width_duration:
            #    width_duration = len_duration

        ## Print column headers
        print(f'{"ID" : <{width_id}}  {"Description" : <{width_description}}  {"Level" : ^{width_level}}  {"Result" : ^{width_result}}  {"Duration" : >{width_duration}}')
        print(f'{"--" :-<{width_id}}  {"-----------" :-<{width_description}}  {"-----" :-^{width_level}}  {"------" :-^{width_result}}  {"--------" :->{width_duration}}')

        ## Print Data
        for row in data:
            id = row[0] if len(row) >= 1 else ""
            description = row[1] if len(row) >= 2 else ""
            level = row[2] if len(row) >= 3 else ""
            result = row[3] if len(row) >= 4 else ""
            duration = row[4] if len(row) >= 5 else ""

            ## Print blank row before new major sections
            if len(id) == 1:
                print()

            print(f'{id: <{width_id}}  {description: <{width_description}}  {level: ^{width_level}}  {result: ^{width_result}}  {duration: >{width_duration}}')

    def _is_test_included(self, test_id, test_level) -> bool:
        """Check whether a test_id should be tested or not

        Parameters
        ----------

        test_id : string, required
            test_id of be checked

        test_level : int, required
            Hardening level of the test_id, per the CIS Benchmarks

        config : namespace, required
            Script configuration from parse_args()

        Returns
        -------
        bool
            Returns a boolean indicating whether a test should be executed (True), or not (False)
        """

        self.log.debug(f'Checking whether to run test {test_id}')

        is_test_included = True

        ## Check if the level is one we're going to run
        if self.config.level != 0:
            if test_level != self.config.level:
                self.log.debug(f'Excluding level {test_level} test {test_id}')
                is_test_included = False

        ## Check if there were explicitly included tests:
        if self.config.includes:
            is_parent_test = False
            is_child_test = False

            ## Check if include starts with test_id
            for include in self.config.includes:
                if include.startswith(test_id):
                    is_parent_test = True
                    break

            ## Check if test_id starts with include
            for include in self.config.includes:
                if test_id.startswith(include):
                    is_child_test = True
                    break

            ## Check if the test_id is in the included tests
            if test_id in self.config.includes:
                self.log.debug(f'Test {test_id} was explicitly included')
                is_test_included = True

            elif is_parent_test:
                self.log.debug(f'Test {test_id} is the parent of an included test')
                is_test_included = True

            elif is_child_test:
                self.log.debug(f'Test {test_id} is the child of an included test')
                is_test_included = True

            elif self.config.level == 0:
                self.log.debug(f'Excluding test {test_id} (Not found in the include list)')
                is_test_included = False

        ## If this test_id was included in the tests, check it wasn't then excluded
        if self.config.excludes:
            is_parent_excluded = False

            for exclude in self.config.excludes:
                if test_id.startswith(exclude):
                    is_parent_excluded = True
                    break

            if test_id in self.config.excludes:
                self.log.debug(f'Test {test_id} was explicitly excluded')
                is_test_included = False

            elif is_parent_excluded:
                self.log.debug(f'Test {test_id} is the child of an excluded test')
                is_test_included = False

        if is_test_included:
            self.log.debug(f'Including test {test_id}')
        else:
            self.log.debug(f'Not including test {test_id}')

        return is_test_included

    def run_tests(self, tests: "list[dict]") -> dict:
        results = []

        for test in tests:
            result = ""

            ## Test ID
            test_id = test['_id']

            ## Test Description
            test_description = test['description']

            ## Test Function
            if "function" in test:
                test_function = test['function']
            else:
                test_function = None

            ## Test kwargs
            if 'kwargs' in test:
                kwargs = test['kwargs']
            else:
                kwargs = None

            ## Test Level
            if "levels" in test:
                if self.config.system_type in test['levels']:
                    test_level = test['levels'][self.config.system_type]
            else:
                test_level = None

            ## Test Type
            if "type" in test:
                test_type = test['type']
            else:
                self.log.debug(f'Test {test_id} does not explicitly define a type, so assuming it is a test')
                test_type = 'test'

            ## If a test doesn't have a function associated with it, we assume it's unimplemented
            if test_type == 'test' and test_function is None:
                test_type = 'notimplemented'

            ## Check whether this test_id is included
            if self._is_test_included(test_id, test_level):
                if test_type == 'header':
                    results.append((test_id, test_description))

                elif test_type == 'manual':
                    results.append((test_id, test_description, test_level, 'Manual'))

                elif test_type == 'skip':
                    results.append((test_id, test_description, test_level, 'Skipped'))

                elif test_type == 'notimplemented':
                    results.append((test_id, test_description, test_level, 'Not Implemented'))

                elif test_type == 'test':
                    start_time = self._get_utcnow()

                    try:
                        if kwargs:
                            self.log.debug(f'Requesting test {test_id}, {test_function.__name__} with kwargs: {kwargs}')
                            state = test_function(self, **kwargs)
                        else:
                            self.log.debug(f'Requesting test {test_id}, {test_function.__name__}')
                            state = test_function(self)

                    except Exception as e:
                        self.log.warning(f'Test {test_id} encountered an error: "{e}"')
                        state = -1

                    end_time = self._get_utcnow()
                    duration = f'{int((end_time.microsecond - start_time.microsecond) / 1000)}ms'

                    if state == 0:
                        self.log.debug(f'Test {test_id} passed')
                        result = "Pass"
                    elif state == -1:
                        result = "Error"
                    elif state == -2:
                        result = "Skipped"
                    else:
                        self.log.debug(f'Test {test_id} failed with state {state}')
                        result = "Fail"

                    results.append((test_id, test_description, test_level, result, duration))

        return results

#put all linux independent functions here
class LinuxIndependentAudit(CISAudit):
    def __init__(self, config=None):
        super().__init__(config)
    
    def audit_access_to_su_command_is_restricted(self) -> int:
        state = 0
        cmd = R"grep -Pi '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$' /etc/pam.d/su"

        r = self._shellexec(cmd)

        if r.stdout[0] == '':
            state += 1
        else:
            for entry in r.stdout[0].split():
                if entry.startswith('group='):
                    group = entry.split('=')[1]
                    break

            cmd = f'grep {group} /etc/group'
            r = self._shellexec(cmd)
            regex = re.compile('^[a-z-]+:x:[0-9]+:$')

            if not regex.match(r.stdout[0]):
                state += 2

        return state
    
    def _get_homedirs(self) -> "Generator[str, int, str]":
        cmd = R"awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1,$3,$6 }' /etc/passwd"
        r = self._shellexec(cmd)

        for row in r.stdout:
            if row != "":
                user, uid, homedir = row.split(' ')

                yield user, int(uid), homedir
    
    def _get_utcnow(self) -> datetime:
        return datetime.utcnow()
    
    def _shellexec(self, command: str) -> "SimpleNamespace[str, str, int]":
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

        self.log.debug(f"'{command}', {data}")

        return data
    
    def audit_audit_config_is_immutable(self) -> int:
        cmd = R'grep -h "^\s*[^#]" /etc/audit/rules.d/*.rules | tail -1'
        r = self._shellexec(cmd)

        if r.stdout[0] == '-e 2':
            state = 0
        else:
            state = 1

        return state
    
    def audit_audit_log_size_is_configured(self) -> int:
        cmd = R"grep -P '^max_log_file\s*=\s*[0-9]+' /etc/audit/auditd.conf"
        r = self._shellexec(cmd)

        if r.returncode == 0:
            state = 0
        else:
            state = 1

        return state

    def audit_audit_logs_not_automatically_deleted(self) -> int:
        cmd = R"grep '^max_log_file_action\s*=\s*keep_logs' /etc/audit/auditd.conf"
        r = self._shellexec(cmd)

        if r.returncode == 0:
            state = 0
        else:
            state = 1

        return state
    
    def audit_bootloader_password_is_set(self) -> int:
        state = 0

        cmd = R'grep "^\s*GRUB2_PASSWORD" /boot/grub2/user.cfg'
        r = self._shellexec(cmd)

        if not r.stdout[0].startswith('GRUB2_PASSWORD='):
            state += 1

        return state
    
    def audit_core_dumps_restricted(self) -> int:
        state = 0

        cmd = R'grep -hE "^\s*\*\s+hard\s+core" /etc/security/limits.conf /etc/security/limits.d/*'
        r = self._shellexec(cmd)
        if not re.match(r'\s*\*\s+hard\s+core\s+0', r.stdout[0]):
            state += 1

        cmd = R"sysctl fs.suid_dumpable"
        r = self._shellexec(cmd)
        if r.stdout[0] != "fs.suid_dumpable = 0":
            state += 2

        cmd = R'grep -h "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*'
        r = self._shellexec(cmd)
        if r.stdout[0] != "fs.suid_dumpable = 0":
            state += 4

        return state
    
    def audit_auth_for_single_user_mode(self) -> int:
        state = 0
        success_strings = [
            'ExecStart=-/bin/sh -c "/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"',
            'ExecStart=-/bin/sh -c "/sbin/sulogin; /usr/bin/systemctl --job-mode=fail --no-block default"',
            'ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"',
            'ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --job-mode=fail --no-block default"',
        ]

        cmd = R"grep ExecStart= /usr/lib/systemd/system/rescue.service"
        r = self._shellexec(cmd)
        if r.stdout[0] not in success_strings:
            state += 1

        cmd = R"grep ExecStart= /usr/lib/systemd/system/rescue.service"
        r = self._shellexec(cmd)
        if r.stdout[0] not in success_strings:
            state += 2

        return state
    
    def audit_homedirs_exist(self) -> int:
        state = 0

        for user, uid, homedir in self._get_homedirs():
            if homedir != '':
                if not os.path.isdir(homedir):
                    self.log.warning(f'The homedir {homedir} does not exist')
                    state = 1

        return state
    
    def audit_sshd_config_option(self, parameter: str, expected_value: str, comparison: str = "eq") -> int:
        state = 0
        cmd = R"/usr/sbin/sshd -T"
        r = self._shellexec(cmd)

        ## Fail check if the config test fails because we can't trust the config file is correct
        if r.returncode != 0:
            state += 1

        ## Check if the parameter in the sshd_config file matches the expected_value
        for line in r.stdout:
            if line.startswith(parameter):
                ## I didn't know of a better way of doing this
                if comparison == 'eq':
                    if not line.split()[1] == expected_value:
                        state += 2

                elif comparison == 'ne':
                    if not line.split()[1] != expected_value:
                        state += 2

                elif comparison == 'ge':
                    if not int(line.split()[1]) >= int(expected_value):
                        state += 2

                elif comparison == 'gt':
                    if not int(line.split()[1]) > int(expected_value):
                        state += 2

                elif comparison == 'le':
                    if not int(line.split()[1]) <= int(expected_value):
                        state += 2

                elif comparison == 'lt':
                    if not int(line.split()[1]) < int(expected_value):
                        state += 2

                ## No need to keep checking the other lines, so we break the loop
                break

        return state

    def audit_homedirs_ownership(self) -> int:
        state = 0

        for user, uid, homedir in self._get_homedirs():
            dir = os.stat(homedir)

            if dir.st_uid != int(uid):
                state = 1
                self.log.warning(f'{user}({uid}) does not own {homedir}')

        return state
    
    def audit_homedirs_permissions(self) -> int:
        state = 0

        for user, uid, homedir in self._get_homedirs():
            if self.audit_file_permissions(homedir, '0750') != 0:
                state = 1
                self.log.warning(f'Homedir {homedir} is not 0750 or more restrictive')

        return state

    def audit_duplicate_uids(self) -> int:
        state = 0
        cmd = R'cut -d: -f3 /etc/passwd | sort | uniq -d'

        r = self._shellexec(cmd)
        if r.stdout[0] != '':
            state = 1

        return state

    def audit_duplicate_gids(self) -> int:
        state = 0
        cmd = R'cut -d: -f3 /etc/group | sort | uniq -d'

        r = self._shellexec(cmd)
        if r.stdout[0] != '':
            state = 1

        return state

    def audit_duplicate_group_names(self) -> int:
        state = 0
        cmd = R'cut -d: -f1 /etc/group | sort | uniq -d'

        r = self._shellexec(cmd)
        if r.stdout[0] != '':
            state = 1

        return state

    def audit_duplicate_user_names(self) -> int:
        state = 0
        cmd = R'cut -d: -f1 /etc/passwd | sort | uniq -d'

        r = self._shellexec(cmd)
        if r.stdout[0] != '':
            state = 1

        return state

    def audit_shadow_group_is_empty(self) -> int:
        state = 0
        cmd = R"awk -F: '/^shadow:/ {print $4}' /etc/group"
        r = self._shellexec(cmd)

        if r.stdout[0] != '':
            state += 1

        gid = shellexec("awk -F: '/^shadow:/ {print $3}' /etc/group").stdout[0]

        cmd = f"awk -F: '($4 == \"{gid}\") {{print $1}}' /etc/passwd"
        r = self._shellexec(cmd)
        if r.stdout != ['']:
            state += 2

        return state

    def audit_root_is_only_uid_0_account(self) -> int:
        state = 0
        cmd = R"awk -F: '($3 == 0) { print $1 }' /etc/passwd"
        r = self._shellexec(cmd)

        if r.stdout != ['root']:
            state += 1

        return state

    def audit_file_permissions(self, file: str, expected_mode: str, expected_user: str = None, expected_group: str = None) -> int:
        """Check that a file's ownership matches the expected_user and expected_group, and that the file's permissions match or are more restrictive than the expected_mode.

        Parameters
        ----------
        test_id: str, required
            The ID of the recommendation to be tested, per the CIS Benchmarks

        file: str, required
            The file to be tested

        expected_user: str, required
            The expected user for the file

        expected_group: str, required
            The expected group membership for the file

        expected_mode: str, required
            The octal file mode that the file should not exceed. e.g. 2750, 664, 0400.

        Response
        --------
        int:
            Exit state for tests as a sum of individual failures:
            -1 >= Error
             0 == Pass
             1 <= Fail

        """
        """
            When looping over each of the permission bits. If the bits do not match or are not more restrictive, increment the failure state value by a unique amount, per below. This allows us to determine from the return value, which permissions did not match:

              index | penalty | description
             -------|---------|-------------
                -   |   1     | User did not match
                -   |   2     | Group did not match
                0   |   4     | SetUID bit did not match
                1   |   8     | SetGID bit did not match
                2   |   16    | Sticky bit did not match
                3   |   32    | User Read bit did not match
                4   |   64    | User Write bit did not match
                5   |   128   | User Execute bit did not match
                6   |   256   | Group Read bit did not match
                7   |   512   | Group Write bit did not match
                8   |   1024  | Group Execute bit did not match
                9   |   2048  | Other Read bit did not match
                10  |   4096  | Other Write bit did not match
                11  |   8192  | Other Execute bit did not match
        """
        state = 0

        ## Convert expected_mode to binary string
        if len(expected_mode) in [3, 4]:
            if expected_mode[0] == '0':
                expected_mode = expected_mode[-3:]  # Strip leading zero otherwise it can break things, e.g. 0750 -> 750
        else:
            raise ValueError(f'The "expected_mode" for {file} should be 3 or 4 characters long, not {len(expected_mode)}')
        octal_expected_mode = oct(int(expected_mode, 8))  # Convert octal (base8) file mode to decimal (base10)
        binary_expected_mode = str(format(int(octal_expected_mode, 8), '012b'))  # Convert decimal (base10) to binary (base2) for bit-by-bit comparison

        ## Get file stats and user/group
        try:
            file_stat = os.stat(file)
        except Exception as e:
            self.log.warning(f'Error trying to stat file {file}: "{e}"')
            return -1

        file_user = getpwuid(file_stat.st_uid).pw_name
        file_group = getgrgid(file_stat.st_gid).gr_name

        ## Convert file_mode to binary string
        file_mode = int(stat.S_IMODE(file_stat.st_mode))
        octal_file_mode = oct(file_mode)
        binary_file_mode = str(format(int(file_mode), '012b'))

        if expected_user is not None:
            ## Set fail state if user does not match expectation
            if file_user != expected_user:
                state += 1
                self.log.debug(f'Test failure: file_user "{file_user}" for {file} did not match expected_user "{expected_user}"')

        if expected_group is not None:
            ## Set fail state if group does not match expecation
            if file_group != expected_group:
                state += 2
                self.log.debug(f'Test failure: file_group "{file_group}" for {file} did not match expected_group "{expected_group}"')

        ## Iterate over all bits in the binary_file_mode to ensure they're equal to, or more restrictive than, the expected_mode. Refer to the table in the description above for what the individual 'this_failure_score' values refer to.
        for i in range(len(binary_file_mode)):
            if binary_expected_mode[i] == '0':
                if binary_file_mode[i] != '0':
                    ## Add unique state so we can identify which bit a permission failed on, for debugging
                    this_failure_score = 2 ** (i + 2)
                    state += this_failure_score
                    self.log.debug(f'Test comparison for {file}, {octal_expected_mode}>={octal_file_mode} {binary_expected_mode[i]} == {binary_file_mode[i]}. Failed at index {i}. Adding {this_failure_score} to state')
                else:
                    self.log.debug(f'Test comparison for {file}, {octal_expected_mode}>={octal_file_mode} {binary_expected_mode[i]} == {binary_file_mode[i]}. Passed at index {i}')

        return state

    def audit_default_group_for_root(self) -> int:
        cmd = 'grep "^root:" /etc/passwd | cut -f4 -d:'
        r = self._shellexec(cmd)

        if r.stdout[0] == '0':
            state = 0
        else:
            state = 1

        return state

    def audit_system_accounts_are_secured(self) -> int:
        ignored_users = ['root', 'sync', 'shutdown', 'halt']
        uid_min = int(self._shellexec(R"awk '/^\s*UID_MIN/ {print $2}' /etc/login.defs").stdout[0])
        valid_shells = ['/sbin/nologin', '/bin/false']
        state = 0

        passwd_file = self._shellexec('cat /etc/passwd').stdout

        for line in passwd_file:
            if line != '':
                user = line.split(':')[0]
                uid = int(line.split(':')[2])
                shell = line.split(':')[6]

                if user not in ignored_users and uid < uid_min:
                    if shell not in valid_shells:
                        state = 1

        self.log.debug(f'uid_min = {uid_min}')
        self.log.debug(f'{passwd_file}')

        return state

    def audit_password_change_minimum_delay(self, expected_min_days: int = 1) -> int:
        state = 0

        cmd1 = R"grep ^\s*PASS_MIN_DAYS /etc/login.defs"
        cmd2 = R"grep -E '^[^:]+:[^!*]' /etc/shadow | cut -d: -f1,4"

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if not int(r1.stdout[0].split()[1]) >= expected_min_days:
            state += 1

        for line in r2.stdout:
            if line != '':
                days = line.split(':')[1]
                if not int(days) >= expected_min_days:
                    state += 2
                    break

        return state

    def audit_password_expiration_max_days_is_configured(self, expected_max_days: int = 365) -> int:
        state = 0

        cmd1 = R"grep ^\s*PASS_MAX_DAYS /etc/login.defs"
        cmd2 = R"grep -E '^[^:]+:[^!*]' /etc/shadow | cut -d: -f1,5"

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if not int(r1.stdout[0].split()[1]) <= expected_max_days:
            state += 1

        for line in r2.stdout:
            if line != '':
                days = line.split(':')[1]
                if not int(days) <= expected_max_days:
                    state += 2
                    break

        return state

    def audit_password_expiration_warning_is_configured(self, expected_warn_days: int = 7) -> int:
        state = 0

        cmd1 = R"grep ^\s*PASS_WARN_AGE /etc/login.defs"
        cmd2 = R"grep -E '^[^:]+:[^!*]' /etc/shadow | cut -d: -f1,6"

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if not int(r1.stdout[0].split()[1]) >= expected_warn_days:
            state += 1

        for line in r2.stdout:
            if line != '':
                days = line.split(':')[1]
                if not int(days) >= expected_warn_days:
                    state += 2
                    break

        return state

    def audit_password_hashing_algorithm(self) -> int:
        state = 0
        cmd = R"grep -P '^\h*password\h+(sufficient|requisite|required)\h+pam_unix\.so\h+([^#\n\r]+)?sha512(\h+.*)?$' /etc/pam.d/system-auth /etc/pam.d/password-auth"

        r = self._shellexec(cmd)

        if len(r.stdout) < 2:
            state += 1

        return state

    def audit_password_inactive_lock_is_configured(self, expected_inactive_days: int = 30) -> int:
        state = 0

        cmd1 = R"useradd -D | grep INACTIVE"
        cmd2 = R"grep -E '^[^:]+:[^!*]' /etc/shadow | cut -d: -f1,7"

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout[0].split('=')[1]:
            default_inactive_days = int(r1.stdout[0].split('=')[1])

        if default_inactive_days == -1 or default_inactive_days > expected_inactive_days:
            state += 1

        for line in r2.stdout:
            days = line.split(':')[1]

            if days == '' or int(days) > expected_inactive_days:
                state += 2
                break

        return state

    def audit_password_reuse_is_limited(self) -> int:
        state = 0
        cmd1 = R"grep -P '^\s*password\s+(requisite|required)\s+pam_pwhistory\.so\s+([^#]+\s+)*remember=([5-9]|[1-9][0-9]+)\b' /etc/pam.d/system-auth /etc/pam.d/password-auth"
        cmd2 = R"grep -P '^\s*password\s+(sufficient|requisite|required)\s+pam_unix\.so\s+([^#]+\s+)*remember=([5-9]|[1-9][0-9]+)\b' /etc/pam.d/system-auth /etc/pam.d/password-auth"

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if len(r1.stdout) < 2 and len(r2.stdout) < 2:
            state += 1

        return state

    def audit_permissions_on_private_host_key_files(self) -> int:
        state = 0
        counter = 0
        files = []

        ## Get HostKeys from sshd_config
        cmd = R"/usr/sbin/sshd -T"
        r = self._shellexec(cmd)

        regex = re.compile(R'^hostkey\s')
        for line in r.stdout:
            if regex.match(line):
                files.append(line.split()[1])

        ## Check file permissions using audit_file_permissions()
        for counter, file in enumerate(files):
            result = self.audit_file_permissions(file=file, expected_user="root", expected_group="root", expected_mode="0600")

            if result != 0:
                state += 2**counter

        return state

    def audit_permissions_on_public_host_key_files(self) -> int:
        state = 0
        counter = 0
        files = []

        ## Get HostKeys from sshd_config
        cmd = R"/usr/sbin/sshd -T"
        r = self._shellexec(cmd)

        regex = re.compile(R'^hostkey\s')
        for line in r.stdout:
            if regex.match(line):
                files.append(line.split()[1])

        ## Check file permissions using audit_file_permissions()
        for counter, file in enumerate(files):
            result = self.audit_file_permissions(file=file + '.pub', expected_user="root", expected_group="root", expected_mode="0644")

            if result != 0:
                state += 2**counter

        return state

    def audit_service_is_enabled_and_is_active(self, service: str) -> int:
        state = 0

        cmd = f'systemctl is-enabled {service}'
        r = self._shellexec(cmd)
        if r.stdout[0] != 'enabled':
            state += 1

        cmd = f'systemctl is-active {service}'
        r = self._shellexec(cmd)
        if r.stdout[0] != 'active':
            state += 2

        return state 

    def audit_auditing_for_processes_prior_to_start_is_enabled(self) -> int:
        r"""
        #!/bin/bash
        efidir=$(find /boot/efi/EFI/* -type d -not -name 'BOOT')
        gbdir=$(find /boot -maxdepth 1 -type d -name 'grub*')
        if [ -f "$efidir"/grub.cfg ]; then
            grep "^\s*linux" "$efidir"/grub.cfg | grep -Evq "audit=1\b" && echo "FAILED" || echo "PASSED"
        elif [ -f "$gbdir"/grub.cfg ]; then
            grep "^\s*linux" "$gbdir"/grub.cfg | grep -Evq "audit=1\b" && echo "FAILED" || echo "PASSED"
        else
            echo "FAILED"
        fi
        """

        state = 0
        efidirfile = self._shellexec(R"find /boot/efi/EFI/ -type f -name 'grub.cfg' | grep -v BOOT").stdout[0]
        grubdirfile = self._shellexec(R"find /boot -mindepth 1 -maxdepth 2 -type f -name 'grub.cfg'").stdout[0]

        if efidirfile != '':
            cmd = Rf'grep "^\s*linux" "{efidirfile}" | grep -Evq "audit=1\b" && echo "FAILED" || echo "PASSED"'
            r = self._shellexec(cmd)
        elif grubdirfile != '':
            cmd = Rf'grep "^\s*linux" "{grubdirfile}" | grep -Evq "audit=1\b" && echo "FAILED" || echo "PASSED"'
            r = self._shellexec(cmd)
        else:
            r = self._shellexec("echo FAILED")

        if r.stdout[0] != 'PASSED':
            state += 1

        return state

    def audit_chrony_is_configured(self) -> int:
        state = 0

        cmd = R"systemctl is-enabled chronyd"
        r = self._shellexec(cmd)
        if r.stdout[0] != "enabled":
            state += 1

        cmd = R"systemctl is-active chronyd"
        r = self._shellexec(cmd)
        if r.stdout[0] != "active":
            state += 2

        cmd = R'grep -E "^(server|pool)" /etc/chrony.conf'
        r = self._shellexec(cmd)
        if r.stdout[0] == "":
            state += 4

        cmd = R"ps aux | grep chronyd | grep -Ev 'awk|grep'  | awk '/chronyd/ {print $1}'"
        r = self._shellexec(cmd)
        if r.stdout[0] != "chrony":
            state += 8

        return state    

    def audit_cron_is_restricted_to_authorized_users(self) -> int:
        state = 0

        if os.path.exists('/etc/cron.deny'):
            state += 1

        if not os.path.exists('/etc/cron.allow'):
            state += 2
        else:
            if self.audit_file_permissions(file="/etc/cron.allow", expected_user="root", expected_group="root", expected_mode="0600") != 0:
                state += 4

        return state

    def audit_default_group_for_root(self) -> int:
        cmd = 'grep "^root:" /etc/passwd | cut -f4 -d:'
        r = self._shellexec(cmd)

        if r.stdout[0] == '0':
            state = 0
        else:
            state = 1

        return state
    
    def audit_etc_passwd_gids_exist_in_etc_group(self) -> int:
        gids_from_etc_group = self._shellexec("awk -F: '{print $3}' /etc/group | sort -un").stdout
        gids_from_etc_passwd = self._shellexec("awk -F: '{print $4}' /etc/passwd | sort -un").stdout
        state = 0

        for gid in gids_from_etc_passwd:
            if gid not in gids_from_etc_group:
                self.log.warning(f'GID {gid} exists in /etc/passwd but not in /etc/group')
                state = 1

        return state
    
    def audit_events_for_discretionary_access_control_changes_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -h perm_mod /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep perm_mod"

        expected_file_output = [
            '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod',
            '-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod',
            '-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod',
            '-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod',
            '-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod',
            '-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod',
        ]

        expected_auditctl_output = [
            '-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod',
            '-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod',
            '-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod',
            '-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod',
            '-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod',
            '-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_file_output:
            state += 1

        if r2.stdout != expected_auditctl_output:
            state += 2

        return state
    
    def audit_events_for_file_deletion_by_users_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -h delete /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep delete"

        expected_file_output = [
            '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete',
            '-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete',
        ]

        expected_auditctl_output = [
            '-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete',
            '-a always,exit -F arch=b32 -S unlink,rename,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_file_output:
            state += 1

        if r2.stdout != expected_auditctl_output:
            state += 2

        return state

    def audit_events_for_kernel_module_loading_and_unloading_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -h modules /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep modules"

        expected_file_output = [
            '-w /sbin/insmod -p x -k modules',
            '-w /sbin/rmmod -p x -k modules',
            '-w /sbin/modprobe -p x -k modules',
            '-a always,exit -F arch=b64 -S init_module -S delete_module -k modules',
        ]

        expected_auditctl_output = [
            '-w /sbin/insmod -p x -k modules',
            '-w /sbin/rmmod -p x -k modules',
            '-w /sbin/modprobe -p x -k modules',
            '-a always,exit -F arch=b64 -S init_module,delete_module -F key=modules',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_file_output:
            state += 1

        if r2.stdout != expected_auditctl_output:
            state += 2

        return state

    def audit_events_for_login_and_logout_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -h logins /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep logins"

        expected_output = [
            '-w /var/log/lastlog -p wa -k logins',
            '-w /var/run/faillock -p wa -k logins',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_output:
            state += 1

        if r2.stdout != expected_output:
            state += 2

        return state

    def audit_events_for_session_initiation_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -h '[buw]tmp' /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep '[buw]tmp'"

        expected_output = [
            '-w /var/run/utmp -p wa -k session',
            '-w /var/log/wtmp -p wa -k logins',
            '-w /var/log/btmp -p wa -k logins',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_output:
            state += 1

        if r2.stdout != expected_output:
            state += 2

        return state

    def audit_events_for_successful_file_system_mounts_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -h mounts /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep mounts"

        expected_file_output = [
            '-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts',
            '-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts',
        ]

        expected_auditctl_output = [
            '-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts',
            '-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_file_output:
            state += 1

        if r2.stdout != expected_auditctl_output:
            state += 2

        return state

    def audit_events_for_system_administrator_commands_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -h actions /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep actions"

        expected_file_output = [
            '-a exit,always -F arch=b64 -C euid!=uid -F euid=0 -F auid>=1000 -F auid!=4294967295 -S execve -k actions',
            '-a exit,always -F arch=b32 -C euid!=uid -F euid=0 -F auid>=1000 -F auid!=4294967295 -S execve -k actions',
        ]
        expected_auditctl_output = [
            '-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F auid>=1000 -F auid!=-1 -F key=actions',
            '-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F auid>=1000 -F auid!=-1 -F key=actions',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_file_output:
            state += 1

        if r2.stdout != expected_auditctl_output:
            state += 2

        return state

    def audit_events_for_unsuccessful_file_access_attempts_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -h access /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep access"

        expected_file_output = [
            '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access',
            '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access',
            '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access',
            '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access',
        ]
        expected_auditctl_output = [
            '-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access',
            '-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access',
            '-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access',
            '-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_file_output:
            state += 1

        if r2.stdout != expected_auditctl_output:
            state += 2

        return state

    def audit_events_that_modify_datetime_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -h time-change /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep time-change"

        expected_file_output = [
            '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change',
            '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change',
            '-a always,exit -F arch=b64 -S clock_settime -k time-change',
            '-a always,exit -F arch=b32 -S clock_settime -k time-change',
            '-w /etc/localtime -p wa -k time-change',
        ]

        expected_auditctl_output = [
            '-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=time-change',
            '-a always,exit -F arch=b32 -S stime,settimeofday,adjtimex -F key=time-change',
            '-a always,exit -F arch=b64 -S clock_settime -F key=time-change',
            '-a always,exit -F arch=b32 -S clock_settime -F key=time-change',
            '-w /etc/localtime -p wa -k time-change',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_file_output:
            state += 1

        if r2.stdout != expected_auditctl_output:
            state += 2

        return state

    def audit_events_that_modify_mandatory_access_controls_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -h MAC-policy /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep MAC-policy"

        expected_output = [
            '-w /etc/selinux -p wa -k MAC-policy',
            '-w /usr/share/selinux -p wa -k MAC-policy',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_output:
            state += 1

        if r2.stdout != expected_output:
            state += 2

        return state

    def audit_events_that_modify_network_environment_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -h system-locale /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep system-locale"

        expected_file_output = [
            '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale',
            '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale',
            '-w /etc/issue -p wa -k system-locale',
            '-w /etc/issue.net -p wa -k system-locale',
            '-w /etc/hosts -p wa -k system-locale',
            '-w /etc/sysconfig/network -p wa -k system-locale',
        ]

        expected_auditctl_output = [
            '-a always,exit -F arch=b64 -S sethostname,setdomainname -F key=system-locale',
            '-a always,exit -F arch=b32 -S sethostname,setdomainname -F key=system-locale',
            '-w /etc/issue -p wa -k system-locale',
            '-w /etc/issue.net -p wa -k system-locale',
            '-w /etc/hosts -p wa -k system-locale',
            '-w /etc/sysconfig/network -p wa -k system-locale',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_file_output:
            state += 1

        if r2.stdout != expected_auditctl_output:
            state += 2

        return state

    def audit_events_that_modify_usergroup_info_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -h identity /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep identity"

        expected_file_output = [
            '-w /etc/group -p wa -k identity',
            '-w /etc/passwd -p wa -k identity',
            '-w /etc/gshadow -p wa -k identity',
            '-w /etc/shadow -p wa -k identity',
            '-w /etc/security/opasswd -p wa -k identity',
        ]

        expected_auditctl_output = [
            '-w /etc/group -p wa -k identity',
            '-w /etc/passwd -p wa -k identity',
            '-w /etc/gshadow -p wa -k identity',
            '-w /etc/shadow -p wa -k identity',
            '-w /etc/security/opasswd -p wa -k identity',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_file_output:
            state += 1

        if r2.stdout != expected_auditctl_output:
            state += 2

        return state
    
    def audit_sysctl_flags_are_set(self, flags: "list[str]", value: int) -> int:
        state = 0

        for i, flag in enumerate(flags):
            cmd = f'sysctl {flag}'
            r = self._shellexec(cmd)
            if r.stdout[0] != f'{flag} = {value}':
                state += 2 ** (i * 2)

            cmd = f'grep -h "{flag}" /etc/sysctl.conf /etc/sysctl.d/*.conf'
            r = self._shellexec(cmd)

            if r.stdout != [f'{flag} = {value}']:
                state += 2 ** (i * 2 + 1)

        return state

    def audit_system_is_disabled_when_audit_logs_are_full(self) -> int:
        state = 0

        cmd1 = R"grep '^space_left_action =' /etc/audit/auditd.conf"
        cmd2 = R"grep '^action_mail_acct =' /etc/audit/auditd.conf"
        cmd3 = R"grep '^admin_space_left_action =' /etc/audit/auditd.conf"

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)
        r3 = self._shellexec(cmd3)

        if r1.stdout[0] != 'space_left_action = email':
            state += 1

        if r2.stdout[0] != 'action_mail_acct = root':
            state += 2

        if r3.stdout[0] != 'admin_space_left_action = halt':
            state += 4

        return state
    
    def audit_partition_is_separate(self, partition: str) -> int:
        state = 0
        cmd = Rf'mount | grep -E "\s{partition}\s"'
        r = self._shellexec(cmd)
        if partition not in r.stdout[0]:
            state += 1

        return state

#here
    def audit_partition_option_is_set(self, partition: str, option: str) -> int:
        state = 1
        cmd = Rf'mount | grep -E "\s{partition}\s" | grep {option}'
        r = self._shellexec(cmd)

        if partition in r.stdout[0] and option in r.stdout[0]:
            state = 0

        return state

    def audit_removable_partition_option_is_set(self, option: str) -> int:
        state = 0
        removable_mountpoints = self._shellexec("lsblk -o RM,MOUNTPOINT | awk '/1/ {print $2}'").stdout

        for mountpoint in removable_mountpoints:  # pragma: no cover
            if mountpoint != "":
                cmd = Rf'findmnt -n "{mountpoint}" | grep -Ev "\b{option}\b"'
                r = self._shellexec(cmd)

                if r.stdout[0] != "":
                    state = 1

        return state

    def audit_sticky_bit_on_world_writable_dirs(self) -> int:
        cmd = R"df --local -P 2> /dev/null | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \)"
        r = self._shellexec(cmd)

        if r.returncode == 0 and r.stdout[0] == '':
            state = 0
        elif r.returncode == 0 and r.stdout[0] != '':
            state = 1

        return state

    def audit_service_is_disabled(self, service: str) -> int:
        state = 0

        cmd = f'systemctl is-enabled {service}'
        r = self._shellexec(cmd)
        if r.stdout[0] != 'disabled':
            state += 1

        return state

    def audit_kernel_module_is_disabled(self, module: str) -> int:
        state = 0
        cmd1 = f'modprobe -n -v {module}'
        cmd2 = f'lsmod | grep {module}'

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout[0] == 'install /bin/true ':
            pass
        elif r1.stderr[0] == f'modprobe: FATAL: Module {module} not found.':
            pass
        else:
            state = 1

        if module in r2.stdout[0]:
            state = 2

        return state

    def audit_package_is_installed(self, package: str) -> int:
        cmd = f'rpm -q {package}'
        r = self._shellexec(cmd)

        self.log.debug(f"'{cmd}', '{r}'")

        if r.returncode != 0:
            state = 1
        else:
            state = 0

        return state
    
    def audit_filesystem_integrity_regularly_checked(self) -> int:
        state = 1

        cmd = R"grep -Ers '^([^#]+\s+)?(\/usr\/s?bin\/|^\s*)aide(\.wrapper)?\s(--?\S+\s)*(--(check|update)|\$AIDEARGS)\b' /etc/cron.* /etc/crontab /var/spool/cron/root /etc/anacrontab"
        r = self._shellexec(cmd)

        if r.stdout[0] != '':
            state = 0

        else:
            cmd1 = 'systemctl is-enabled aidecheck.service'
            cmd2 = 'systemctl is-enabled aidecheck.timer'
            cmd3 = 'systemctl is-active aidecheck.timer'

            r1 = self._shellexec(cmd1)
            r2 = self._shellexec(cmd2)
            r3 = self._shellexec(cmd3)

            if all(
                [
                    r1.stdout[0] == 'enabled',
                    r2.stdout[0] == 'enabled',
                    r3.stdout[0] == 'active',
                ]
            ):
                state = 0

        return state

    def audit_nxdx_support_enabled(self) -> int:
        state = 0
        cmd = R'dmesg | grep "protection: active"'
        r = self._shellexec(cmd)

        if "protection: active" not in r.stdout[0]:
            state += 1

        return state

    def audit_package_not_installed(self, package: str) -> int:
        cmd = f'rpm -q {package}'
        r = self._shellexec(cmd)

        self.log.debug(f"'{cmd}', '{r}'")

        if r.returncode == 1:
            state = 0
        else:
            state = 1

        return state

    def audit_selinux_not_disabled_in_bootloader(self) -> int:
        state = 0
        file_paths = []
        for dirpath, dirnames, filenames in os.walk('/boot/'):
            if "grub.cfg" in filenames:
                file_paths.append(dirpath)

        if len(file_paths) == 0:
            state = -1

        else:
            for i, path in enumerate(file_paths):
                cmd = Rf'grep "^\s*linux" {path}/grub.cfg | grep -E "selinux=0|enforcing=0"'
                r = self._shellexec(cmd)

                if r.stdout != ['']:
                    state += 2 ** (i + 1)

        return state

    def audit_selinux_policy_is_configured(self) -> int:
        state = 0

        cmd = R"awk -F= '/^SELINUXTYPE=/ {print $2}' /etc/selinux/config"
        r = self._shellexec(cmd)
        if r.stdout[0] != "targeted":
            state += 1

        cmd = R"sestatus | awk -F: '/Loaded policy/ {print $2}' | sed 's/\s*//'"
        r = self._shellexec(cmd)
        if r.stdout[0] != "targeted":
            state += 2

        return state

    def audit_updates_installed(self) -> int:
        cmd = R'yum -q check-update'
        r = self._shellexec(cmd)

        ## From man 8 yum
        ## Returns exit value of 100 if there are packages available for an update. Also returns a list of the packages to be updated in list format.
        ## Returns 0 if no packages are available for update.
        ## Returns 1 if an error occurred.

        if r.returncode == 0:
            state = 0
        elif r.returncode == 1:
            state = -1
        elif r.returncode == 100:
            state = 1

        return state

    def audit_only_one_package_is_installed(self, packages: str) -> int:
        ### Similar to audit_package_is_installed but requires one of many (xor) package is installed
        cmd = f'rpm -q {packages} | grep -v "not installed"'
        r = self._shellexec(cmd)

        ## e.g. print(r.stdout) will show:
        ##  ['chrony-3.4-1.el7.x86_64']
        ##  ['chrony-3.4-1.el7.x86_64', 'ntp-4.2.6p5-29.el7.centos.2.x86_64']

        if len(r.stdout) == 1 and r.stdout != ['']:
            state = 0
        else:
            state = 1

        return state

    def audit_ntp_is_configured(self) -> int:
        state = 0

        cmd = R"systemctl is-enabled ntpd"
        r = self._shellexec(cmd)
        if r.stdout[0] != "enabled":
            state += 1

        cmd = R"systemctl is-active ntpd"
        r = self._shellexec(cmd)
        if r.stdout[0] != "active":
            state += 2

        cmd = R'grep -E "^(server|pool)" /etc/ntp.conf'
        r = self._shellexec(cmd)
        if r.stdout[0] == "":
            state += 4

        cmd = R'grep "^restrict.*default" /etc/ntp.conf'
        r = self._shellexec(cmd)
        options = ["kod", "nomodify", "notrap", "nopeer", "noquery"]
        for option in options:
            for line in r.stdout:
                if option not in line:
                    state += 8
                    self.log.debug(f'Option "{option}" not in line "{line}"')
                    break
            else:
                continue
            break

        cmd = R"ps aux | grep ntpd | grep -v grep"
        r = self._shellexec(cmd)
        if "-u ntp:ntp" not in r.stdout[0]:
            state += 16

        return state

    def audit_package_not_installed_or_service_is_masked(self, package: str, service: str) -> int:
        state = 0

        package_installed = bool(not self.audit_package_is_installed(package))
        self.log.debug(f'package_installed = {package_installed}')

        if package_installed:
            service_masked = bool(not self.audit_service_is_masked(service))
            self.log.debug(f'service_masked = {service_masked}')

            if not service_masked:
                state += 1

        return state
    
    def audit_mta_is_localhost_only(self) -> int:
        state = 0

        cmd = R"ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|\[?::1\]?):25\s'"
        r = self._shellexec(cmd)
        if r.stdout[0] != "":
            state += 1

        return state

    def audit_iptables_default_deny_policy(self, ip_version: str) -> int:
        state = 0

        if ip_version == 'ipv4':
            cmd1 = 'iptables -S INPUT'
            cmd2 = 'iptables -S FORWARD'
            cmd3 = 'iptables -S OUTPUT'
        elif ip_version == 'ipv6':
            cmd1 = 'ip6tables -S INPUT'
            cmd2 = 'ip6tables -S FORWARD'
            cmd3 = 'ip6tables -S OUTPUT'

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)
        r3 = self._shellexec(cmd3)

        if r1.stdout[0] != '-P INPUT DROP':
            state += 1

        if r2.stdout[0] != '-P FORWARD DROP':
            state += 2

        if r3.stdout[0] != '-P OUTPUT DROP':
            state += 4

        return state

    def audit_iptables_loopback_is_configured(self, ip_version: str) -> int:
        state = 0

        if ip_version == 'ipv4':
            cmd1 = "iptables -S INPUT"
            cmd2 = "iptables -S OUTPUT"
        elif ip_version == 'ipv6':
            cmd1 = "ip6tables -S INPUT"
            cmd2 = "ip6tables -S OUTPUT"

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        self.log.debug(r1)
        self.log.debug(r2)

        if len(r1.stdout) < 2 or r1.stdout[1] != '-A INPUT -i lo -j ACCEPT':
            state += 1

        if ip_version == 'ipv4':
            if len(r1.stdout) < 3 or r1.stdout[2] != '-A INPUT -s 127.0.0.0/8 -j DROP':
                state += 2
        elif ip_version == 'ipv6':
            if len(r1.stdout) < 3 or r1.stdout[2] != '-A INPUT -s ::1/128 -j DROP':
                state += 2

        if len(r2.stdout) < 2 or r2.stdout[1] != '-A OUTPUT -o lo -j ACCEPT':
            state += 4

        return state

    def audit_iptables_outbound_and_established_connections(self, ip_version: str) -> int:
        state = 0

        if ip_version == 'ipv4':
            cmd = R"iptables -S"
        elif ip_version == 'ipv6':
            cmd = R"ip6tables -S"

        r = self._shellexec(cmd)

        self.log.debug(r)

        if '-A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT' not in r.stdout:
            state += 1

        if '-A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT' not in r.stdout:
            state += 2

        if '-A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT' not in r.stdout:
            state += 4

        if '-A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT' not in r.stdout:
            state += 8

        if '-A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT' not in r.stdout:
            state += 16

        if '-A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT' not in r.stdout:
            state += 32

        return state

    def audit_etc_passwd_accounts_use_shadowed_passwords(self) -> int:
        """audit_etc_passwd_accounts_use_shadowed_passwords _summary_

        Returns
        -------
        int
            _description_
        """
        """
        Refer to passwd(5) for details on the fields in the file
        """
        state = 0
        ## Note: the 'awk' command from the benchmark would be the better/tidier way to do it, but I couldn't get the mixed quote marks to work from Python, so I ended up with the following:
        ## Original - awk -F: '($2 != "x" ) {print $1}' /etc/passwd
        cmd = R"grep -Ev '^[a-z-]+:x:' /etc/passwd"
        r = self._shellexec(cmd)

        if r.stdout[0] != '':
            state += 1

        return state

    def audit_rsyslog_default_file_permission_is_configured(self) -> int:
        cmd = R'grep -h ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf'
        r = self._shellexec(cmd)

        if r.stdout[0] == '$FileCreateMode 0640':
            state = 0
        else:
            state = 1

        return state

    def audit_rsyslog_sends_logs_to_a_remote_log_host(self) -> int:
        cmd1 = R'grep -Eh "^\s*([^#]+\s+)?action\(([^#]+\s+)?\btarget=\"?[^#\"]+\"?\b" /etc/rsyslog.conf /etc/rsyslog.d/*.conf'  # https://regex101.com/r/Ud69Ey/4
        cmd2 = R"grep -Eh '^\s*[^#\s]*\.\*\s+@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf"  # https://regex101.com/r/DMX1lZ/1

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout[0] != '' or r2.stdout[0] != '':
            state = 0
        else:
            state = 1

        return state

    def audit_journald_configured_to_send_logs_to_rsyslog(self) -> int:
        cmd = R'grep -E ^\s*ForwardToSyslog= /etc/systemd/journald.conf'
        r = self._shellexec(cmd)

        if r.stdout[0] == 'ForwardToSyslog=yes':
            state = 0
        else:
            state = 1

        return state

    def audit_journald_configured_to_compress_large_logs(self) -> int:
        cmd = R'grep -E ^\s*Compress= /etc/systemd/journald.conf'
        r = self._shellexec(cmd)

        if r.stdout[0] == 'Compress=yes':
            state = 0
        else:
            state = 1

        return state

    def audit_journald_configured_to_write_logfiles_to_disk(self) -> int:
        cmd = R'grep -E ^\s*Storage= /etc/systemd/journald.conf'
        r = self._shellexec(cmd)

        if r.stdout[0] == 'Storage=persistent':
            state = 0
        else:
            state = 1

        return state

    def audit_permissions_on_log_files(self) -> int:
        cmd = R'find /var/log -type f -perm /g+wx,o+rwx -exec ls -l {} \;'
        r = self._shellexec(cmd)

        if r.stdout[0] == '':
            state = 0
        else:
            state = 1

        return state

    def audit_selinux_state_is_enforcing(self) -> int:
        state = 0

        cmd = R"sestatus | awk -F: '/^Current mode:/ {print $2}' | sed 's/\s*//'"
        r = self._shellexec(cmd)
        if r.stdout[0] != "enforcing":
            state += 1

        cmd = R"sestatus | awk -F: '/^Mode from config file:/ {print $2}' | sed 's/\s*//'"
        r = self._shellexec(cmd)
        if r.stdout[0] != "enforcing":
            state += 2

        return state
    
    def audit_events_for_changes_to_sysadmin_scope_are_collected(self) -> int:
        state = 0
        cmd1 = R"grep -h scope /etc/audit/rules.d/*.rules"
        cmd2 = R"auditctl -l | grep scope"

        expected_output = [
            '-w /etc/sudoers -p wa -k scope',
            '-w /etc/sudoers.d -p wa -k scope',
        ]

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        if r1.stdout != expected_output:
            state += 1

        if r2.stdout != expected_output:
            state += 2

        return state

    
    #need to check these functions
    
    #doesn't exist in benchmark
    def audit_selinux_mode_not_disabled(self) -> int:
        state = 0

        cmd = R"sestatus | awk -F: '/^Current mode:/ {print $2}' | sed 's/\s*//'"
        r = self._shellexec(cmd)
        if r.stdout[0] not in ["permissive", "enforcing"]:
            state += 1

        cmd = R"sestatus | awk -F: '/^Mode from config file:/ {print $2}' | sed 's/\s*//'"
        r = self._shellexec(cmd)
        if r.stdout[0] not in ["permissive", "enforcing"]:
            state += 2

        return state
    #different description
    def audit_no_unconfined_services(self) -> int:
        state = 0

        cmd = R"ps -eZ | grep unconfined_service_t"
        r = self._shellexec(cmd)

        if r.stdout[0] != "":
            state += 1

        return state
    
    #new ones just created
    def audit_interactive_boot_not_enabled(self) -> int:
        state = 0
        grep_output = self._shellexec('grep "^PROMPT_FOR_CONFIRM=" /etc/sysconfig/boot')

        if grep_output.returncode == 0:
            prompt_for_confirm = grep_output.stdout.strip().split('=')[1].strip('"')
            if prompt_for_confirm == 'no':
                pass
            else:
                state = 1
        else:
            state = 2
        return state
    
    def check_grub_version(self):
        grub_directory = '/boot/grub'

        if os.path.exists(grub_directory):
            if os.path.exists(os.path.join(grub_directory, 'grub.cfg')):
                return "GRUB2"
            elif os.path.exists(os.path.join(grub_directory, 'menu.lst')):
                return "GRUB"

    def audit_apparmor_is_not_disabled(self) -> int:
        
        state = 0

        if self.check_grub_version() == "GRUB":

            grep_output = self._shellexec('grep "^\s*kernel" /boot/grub/menu.lst')

            if grep_output.returncode == 0:
                kernel_lines = grep_output.stdout.strip().split('\n')
                apparmor_present = False

                for line in kernel_lines:
                    if 'apparmor=0' in line:
                        apparmor_present = True
                        break

                if apparmor_present:
                    state = 1
                else:
                    state = 0
            else:
                state = 2

        else:
            grep_output = self._shellexec('grep "^\s*linux" /boot/grub/grub.cfg')

            if grep_output.returncode == 0:
                linux_lines = grep_output.stdout.strip().split('\n')
                apparmor_present = False

                for line in linux_lines:
                    if 'apparmor=0' in line:
                        apparmor_present = True
                        break

                if apparmor_present:
                    state = 1
                else:
                    state = 0
            else:
                state = 2

        return state

    def audit_apparmor_profiles_are_enforcing(self):
        apparmor_output = self._shellexec('apparmor_status')
        if apparmor_output.returncode == 0:
            linux_lines = apparmor_output.stdout.strip().split('\n')

            complainMode = False
            confinedMode = False

            for line in linux_lines:
                if "0 processes are in complain mode." in line:
                    complainMode = True
                elif "0 processes are unconfined" in line:
                    confinedMode = True

            if complainMode and confinedMode:
                state = 0
            else:
                state = 1
        else:
            state = 2
        
        return state

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

    def audit_x_windows_not_installed(self):
        package_management = self.get_package_management_system()

        if package_management == 'rpm':
            command = 'rpm -qa xorg-x11*'
        elif package_management == 'dpkg':
            command = 'dpkg -l xserver-xorg*'
        else:
            return 2

        try:
            output = self._shellexec(command)
            if output.returncode == 0 and not output.stdout:
                state = 0
            else:
                state = 1
        except FileNotFoundError:
            state = 2
        return state

class Centos7Audit(LinuxIndependentAudit):
    def __init__(self, config=None):
        super().__init__(config)

    def audit_gpgcheck_is_activated(self) -> int:
        state = 0

        cmd = R'grep ^\s*gpgcheck /etc/yum.conf'
        r = self._shellexec(cmd)
        if r.stdout[0] != 'gpgcheck=1':
            state += 1

        cmd = R"grep -P '^\h*gpgcheck=[^1\n\r]+\b(\h+.*)?$' /etc/yum.repos.d/*.repo"
        # cmd = R"awk -v 'RS=[' -F '\n' '/\n\s*name\s*=\s*.*$/ && ! /\n\s*enabled\s*=\s*0(\W.*)?$/ && ! /\n\s*gpgcheck\s*=\s*1(\W.*)?$/ { t=substr($1, 1, index($1, \"]\")-1); print t, \"does not have gpgcheck enabled.\" }' /etc/yum.repos.d/*.repo"
        r = self._shellexec(cmd)

        if r.stdout[0] != '':
            state += 2

        return state

    def audit_gdm_last_user_logged_in_disabled(self) -> int:
        state = 0

        if self.audit_package_is_installed(package="gdm") == 0:
            ## Test contents of /etc/dconf/profile/gdm if it exists
            file = "/etc/dconf/profile/gdm"
            if os.path.exists(file):
                with open(file) as f:
                    contents = f.read()
                    if "user-db:user" not in contents:
                        state += 2
                    if "system-db:gdm" not in contents:
                        state += 4
                    if "file-db:/usr/share/gdm/greeter-dconf-defaults" not in contents:
                        state += 8
            else:
                state += 1

            ## Test contents of /etc/dconf/db/gdm.d/01-banner-message, if it exists
            file = "/etc/dconf/db/gdm.d/00-login-screen"
            if os.path.exists(file):
                with open(file) as f:
                    contents = f.read()
                    if "[org/gnome/login-screen]\ndisable-user-list=true" not in contents:
                        state += 32
            else:
                state += 16

        else:
            state = -2

        return state

    def audit_xdmcp_not_enabled(self) -> int:
        state = 0

        if os.path.exists('/etc/gdm/'):
            cmd = R'''awk '{RS="["} /xdmcp/ {print $0}' /etc/gdm/custom.conf | grep -Eis '^\s*Enable\s*=\s*true' '''
            r = self._shellexec(cmd)

            if r.stdout != ['']:
                state += 1

        return state
    def audit_service_is_enabled(self, service: str) -> int:
        state = 0

        cmd = f'systemctl is-enabled {service}'
        r = self._shellexec(cmd)
        if r.stdout[0] != 'enabled':
            state += 1

        return state

    def audit_iptables_is_flushed(self) -> int:
        state = 0

        cmd = R"iptables -S | grep -v -- -P"
        r = self._shellexec(cmd)
        if r.stdout != ['']:
            state += 1

        cmd = R"ip6tables -S | grep -v -- -P"
        r = self._shellexec(cmd)
        if r.stdout != ['']:
            state += 2

        return state

    def audit_iptables_rules_are_saved(self, ip_version: str) -> int:
        if ip_version == 'ipv4':
            # cmd = R"diff -qs -y <(iptables-save | grep -v '^#' | sed 's/\[[0-9]*:[0-9]*\]//' | sort) <(grep -v '^#' /etc/sysconfig/iptables | sed 's/\[[0-9]*:[0-9]*\]//' | sort)"
            cmd1 = R"iptables-save | grep -v '^#' | sed 's/\[[0-9]*:[0-9]*\]//' | sort"
            cmd2 = R"grep -v '^#' /etc/sysconfig/iptables | sed 's/\[[0-9]*:[0-9]*\]//' | sort"
        elif ip_version == 'ipv6':
            # cmd = R"diff -qs -y <(ip6tables-save | grep -v '^#' | sed 's/\[[0-9]*:[0-9]*\]//' | sort) <(grep -v '^#' /etc/sysconfig/ip6tables | sed 's/\[[0-9]*:[0-9]*\]//' | sort)"
            cmd1 = R"ip6tables-save | grep -v '^#' | sed 's/\[[0-9]*:[0-9]*\]//' | sort"
            cmd2 = R"grep -v '^#' /etc/sysconfig/ip6tables | sed 's/\[[0-9]*:[0-9]*\]//' | sort"

        # r = self._shellexec(cmd)
        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        self.log.debug(r1)
        self.log.debug(r2)

        if r1.returncode == 0 and r2.returncode == 0 and r1.stdout == r2.stdout:
            state = 0
        else:
            state = 1

        return state

    def audit_gdm_login_banner_configured(self) -> int:
        state = 0

        if self.audit_package_is_installed(package="gdm") == 0:
            ## Test contents of /etc/dconf/profile/gdm if it exists
            file = "/etc/dconf/profile/gdm"
            if os.path.exists(file):
                with open(file) as f:
                    contents = f.read()
                    if "user-db:user" not in contents:
                        state += 2
                    if "system-db:gdm" not in contents:
                        state += 4
                    if "file-db:/usr/share/gdm/greeter-dconf-defaults" not in contents:
                        state += 8
            else:
                state += 1

            ## Test contents of /etc/dconf/db/gdm.d/01-banner-message, if it exists
            file = "/etc/dconf/db/gdm.d/01-banner-message"
            if os.path.exists(file):
                with open(file) as f:
                    contents = f.read()
                    if "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text=" not in contents:
                        state += 32
            else:
                state += 16
        else:
            state = -2

        return state

    def audit_etc_shadow_password_fields_are_not_empty(self) -> int:
        state = 0

        cmd = R"grep -E '^[a-z-]+::' /etc/shadow"
        r = self._shellexec(cmd)

        if r.stdout[0] != '':
            state += 1

        return state

    def audit_firewalld_default_zone_is_set(self) -> int:
        cmd = 'firewall-cmd --get-default-zone'
        r = self._shellexec(cmd)

        if r.stdout[0] != '':
            state = 0
        else:
            state = 1

        return state

    def audit_nftables_base_chains_exist(self) -> int:
        state = 0

        cmd1 = 'nft list ruleset | grep "hook input"'
        cmd2 = 'nft list ruleset | grep "hook forward"'
        cmd3 = 'nft list ruleset | grep "hook output"'

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)
        r3 = self._shellexec(cmd3)

        if r1.stdout == ['']:
            state += 1

        if r2.stdout == ['']:
            state += 2

        if r3.stdout == ['']:
            state += 4

        return state

    def audit_nftables_outbound_and_established_connections(self) -> int:
        state = 0

        cmd1 = 'nft list ruleset | grep "hook input"'
        cmd2 = 'nft list ruleset | grep "hook output"'

        cmd1 = R"nft list ruleset | awk '/hook input/,/}/' | grep -E 'ip protocol (tcp|udp|icmp) ct state' | sed 's/^\s*//'"
        cmd2 = R"nft list ruleset | awk '/hook output/,/}/' | grep -E 'ip protocol (tcp|udp|icmp) ct state' | sed 's/^\s*//'"

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)

        self.log.debug(f"'{cmd1}', '{r1}'")
        self.log.debug(f"'{cmd2}', '{r2}'")

        if r1.stdout != [
            'ip protocol tcp ct state established accept',
            'ip protocol udp ct state established accept',
            'ip protocol icmp ct state established accept',
        ]:
            state += 1

        if r2.stdout != [
            'ip protocol tcp ct state established,related,new accept',
            'ip protocol udp ct state established,related,new accept',
            'ip protocol icmp ct state established,related,new accept',
        ]:
            state += 2

        return state

    def audit_nftables_default_deny_policy(self) -> int:
        state = 0

        cmd1 = R"nft list ruleset | grep 'hook input' | sed 's/^\s*//'"
        cmd2 = R"nft list ruleset | grep 'hook forward' | sed 's/^\s*//'"
        cmd3 = R"nft list ruleset | grep 'hook output' | sed 's/^\s*//'"

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)
        r3 = self._shellexec(cmd3)

        self.log.debug(f"'{cmd1}', '{r1}'")
        self.log.debug(f"'{cmd2}', '{r2}'")
        self.log.debug(f"'{cmd3}', '{r3}'")

        if r1.stdout[0] != 'type filter hook input priority 0; policy drop;':
            state += 1

        if r2.stdout[0] != 'type filter hook forward priority 0; policy drop;':
            state += 2

        if r3.stdout[0] != 'type filter hook output priority 0; policy drop;':
            state += 4

        return state

    def audit_nftables_loopback_is_configured(self) -> int:
        state = 0

        cmd1 = R"nft list ruleset | awk '/hook input/,/}/' | grep 'iif \"lo\" accept' | sed 's/^\s*//'"
        cmd2 = R"nft list ruleset | awk '/hook input/,/}/' | grep 'ip saddr 127.0.0.0/8' | sed 's/^\s*//'"
        cmd3 = R"nft list ruleset | awk '/hook input/,/}/' | grep 'ip6 saddr ::1' | sed 's/^\s*//'"

        r1 = self._shellexec(cmd1)
        r2 = self._shellexec(cmd2)
        r3 = self._shellexec(cmd3)

        self.log.debug(f"'{cmd1}', '{r1}'")
        self.log.debug(f"'{cmd2}', '{r2}'")
        self.log.debug(f"'{cmd3}', '{r3}'")

        if r1.stdout[0] != 'iif "lo" accept':
            state += 1

        ## See what these re.search()'s are looking for here https://regex101.com/r/9uHJ4o/1
        regex = re.compile(R'ip6? saddr (127.0.0.0\/8|::1) counter packets [0-9]+ bytes [0-9]+ drop')
        # if not search(r'ip6? saddr (127.0.0.0\/8|::1) counter packets [0-9]+ bytes [0-9]+ drop', r2.stdout[0]):
        if not regex.match(r2.stdout[0]):
            state += 2

        # if not search(r'ip6? saddr (127.0.0.0\/8|::1) counter packets [0-9]+ bytes [0-9]+ drop', r3.stdout[0]):
        if not regex.match(r3.stdout[0]):
            state += 4

        return state

    def audit_nftables_table_exists(self) -> int:
        state = 0

        cmd = R'nft list tables'
        r = self._shellexec(cmd)
        if r.stdout == ['']:
            state += 1

        return state

    def audit_service_is_active(self, service: str) -> int:
        state = 0

        cmd = f'systemctl is-active {service}'
        r = self._shellexec(cmd)
        if r.stdout[0] != 'active':
            state += 1

        return state

    def audit_service_is_masked(self, service) -> int:
        state = 0

        cmd = f'systemctl is-enabled {service}'
        r = self._shellexec(cmd)

        self.log.debug(f"'{cmd}', '{r}'")

        if r.stdout[0] != 'masked':
            state += 1

        return state

    def audit_sudo_commands_use_pty(self) -> int:
        state = 0
        cmd = R"grep -hEi '^\s*Defaults\s+([^#]\S+,\s*)?use_pty\b' /etc/sudoers /etc/sudoers.d/*"
        r = self._shellexec(cmd)

        if r.stdout[0] != 'Defaults use_pty':
            state += 1

        return state

    def audit_sudo_log_exists(self) -> int:
        state = 0
        cmd = R"grep -hEi '^\s*Defaults\s+([^#;]+,\s*)?logfile\s*=\s*(\")?[^#;]+(\")?' /etc/sudoers /etc/sudoers.d/*"
        r = self._shellexec(cmd)

        if r.stdout[0] != 'Defaults logfile="/var/log/sudo.log"':
            state += 1

        return state


    

    

    





