# CIS Benchmarks Audit
This repo provides an unofficial, standalone, zero-install, zero-dependency, Python 3 script which can check your system against published CIS Hardening Benchmarks to offer an indication of your system's preparedness for compliance to the official standard.


### How do I use this?
#### Download:

    git clone https://github.com/adamidarrha/hardeningTool

#### Run
```
#usage: python3 mainProgram.py [-h] [--level {1,2}] [--include INCLUDES [INCLUDES ...]]
                    [--exclude EXCLUDES [EXCLUDES ...]]
                    [-l {DEBUG,INFO,WARNING,CRITICAL}] [--debug] [--nice]
                    [--no-nice] [--no-colour]
                    [--system-type {server,workstation}] [--server]
                    [--workstation] [--outformat {csv,json,psv,text,tsv}]
                    [--text] [--json] [--csv] [--psv] [--tsv] [-V] [-c CONFIG]

This script runs tests on the system to check for compliance against the CIS Benchmarks. No changes are made to system files by this script.
it automatically checks for operating system and distribution and applies the benchmark if found.

optional arguments:
  -h, --help            show this help message and exit
  --level {1,2}         Run tests for the specified level only
  --include INCLUDES [INCLUDES ...]
                        Space delimited list of tests to include
  --exclude EXCLUDES [EXCLUDES ...]
                        Space delimited list of tests to exclude
  -l {DEBUG,INFO,WARNING,CRITICAL}, --log-level {DEBUG,INFO,WARNING,CRITICAL}
                        Set log output level
  --debug               Run script with debug output turned on. Equivalent to --log-level DEBUG
  --nice                Lower the CPU priority for test execution. This is the default behaviour.
  --no-nice             Do not lower CPU priority for test execution. This may make the tests complete faster but at the cost of putting a higher load on the server. Setting this overrides the --nice option.
  --no-colour, --no-color
                        Disable colouring for STDOUT. Output redirected to a file/pipe is never coloured.
  --system-type {server,workstation}
                        Set which test level to reference
  --server              Use "server" levels to determine which tests to run. Equivalent to --system-type server [Default]
  --workstation         Use "workstation" levels to determine which tests to run. Equivalent to --system-type workstation
  --outformat {csv,json,psv,text,tsv}
                        Output type for results
  --text                Output results as text. Equivalent to --output text [default]
  --json                Output results as json. Equivalent to --output json
  --csv                 Output results as comma-separated values. Equivalent to --output csv
  --psv                 Output results as pipe-separated values. Equivalent to --output psv
  --tsv                 Output results as tab-separated values. Equivalent to --output tsv
  -V, --version         Print version and exit
  -c CONFIG, --config CONFIG
                        Location of config file to load

Examples:
    
    Run with debug enabled:
    python3 mainProgram.py --debug
        
    Exclude tests from section 1.1 and 1.3.2:
    python3 mainProgram.py --exclude 1.1 1.3.2
        
    Include tests only from section 4.1 but exclude tests from section 4.1.1:
    python3 mainProgram.py --include 4.1 --exclude 4.1.1
        
    Run only level 1 tests
    python3 mainProgram.py --level 1
        
    Run level 1 tests and include some but not all SELinux questions
    python3 mainProgram.py --level 1 --include 1.6 --exclude 1.6.1.2

```

### Example Results
```
# python3 mainProgram.py --include 5.2
[00:00:01] (✓) 14 of 14 tests completed 

 CIS CentOS 7 Benchmark v2.2.0 Results 
---------------------------------------
ID      Description                                                Scoring  Level  Result  Duration
--      -----------                                                -------  -----  ------  --------

5       Access Authentication and Authorization
5.2     SSH Server Configuration
5.2.1   Ensure permissions on /etc/ssh/sshd_config are configured  Scored   1      Pass    33ms
5.2.2   Ensure SSH Protocol is set to 2                            Scored   1      Pass    5ms
5.2.3   Ensure SSH LogLevel is set to INFO                         Scored   1      Pass    6ms
5.2.4   Ensure SSH X11 forwarding is disabled                      Scored   1      Pass    4ms
5.2.5   Ensure SSH MaxAuthTries is set to 4 or less                Scored   1      Pass    9ms
5.2.6   Ensure SSH IgnoreRhosts is enabled                         Scored   1      Pass    5ms
5.2.7   Ensure SSH HostbasedAuthentication is disabled             Scored   1      Pass    5ms
5.2.8   Ensure SSH root login is disabled                          Scored   1      Fail    8ms
5.2.9   Ensure SSH PermitEmptyPasswords is disabled                Scored   1      Pass    5ms
5.2.10  Ensure SSH PermitUserEnvironment is disabled               Scored   1      Pass    8ms
5.2.11  Ensure only approved ciphers are used                      Scored   1      Pass    16ms
5.2.12  Ensure only approved MAC algorithms are used               Scored   1      Pass    45ms
5.2.13  Ensure SSH Idle Timeout Interval is configured             Scored   1      Fail    15ms
5.2.14  Ensure SSH LoginGraceTime is set to one minute or less     Scored   1      Pass    11ms
5.2.15  Ensure SSH access is limited                               Skipped  1              
5.2.16  Ensure SSH warning banner is configured                    Scored   1      Pass    6ms

Passed 13 of 15 tests in 1 seconds (1 Skipped, 0 Errors)
```

### Supported Versions
OS|Benchmark Versions|Python Version
---|---|---
CentOS 7|3.1.2|3.6
DistributionIndependentLinux|2.0.0|3.6

#### Python 3
##### CentOS 7
Whilst this repo intends to follow a zero dependency approach, it is not practical to support Python 2.7, which is what is installed by default on CentOS 7. You can however easily install Python 3.6 via yum, which I hope is ok for your environment:
```
$ sudo yum install python3 -y
```
##### Ubuntu or Debian
```
$ sudo apt-get install python3
```
##### Fedora
```
$ sudo dnf install python3
```
##### Arch Linux
```
$sudo pacman -S python
```
##### openSUSE
```
$ sudo zypper install python3
```
