from Benchmarks import benchmarks
from cis_audit import Centos7Audit
from cis_audit import LinuxIndependentAudit
import distro
import platform
import logging  # https://docs.python.org/3/library/logging.html
import sys  # https://docs.python.org/3/library/sys.html
import os  # https://docs.python.org/3/library/os.html
from argparse import (
    ArgumentParser,  # https://docs.python.org/3/library/argparse.html#argparse.ArgumentParser
)
from argparse import (
    RawTextHelpFormatter,  # https://docs.python.org/3/library/argparse.html#argparse.RawTextHelpFormatter
)
__version__ = '0.20.0-alpha.3'

## Script Functions ##
def main():  # pragma: no cover
    #load arguments the the program ran with
    config = parse_arguments()
    #check for operating system (linux, windows, darwin'macOS')
    if platform.system() == "Linux":
        #check for linux distribution and version
        print("linux distro")
        if distro.name() == "CentOS Linux":
            #initialise the audit class
            audit = Centos7Audit(config=config)
            #set the values for the benchmarks dictionary
            host_os = 'centos7'
            benchmark_version = '3.1.2'
        else:
            audit = LinuxIndependentAudit(config=config)
            host_os = 'linuxIndependent'
            benchmark_version = '2.0.0'
    else:
        print("we dont support windows and darwin platform yet")
        sys.exit()
    # test_list = audit.get_tests_list(host_os, benchmarks_version)
    test_list = benchmarks[host_os][benchmark_version]
    #run the audit tests and store the results
    results = audit.run_tests(test_list)
    #print the results in the output format (json, csv...)
    audit.output(config.outformat, results)


def parse_arguments(argv=sys.argv):
    description = "This script runs tests on the system to check for compliance against the CIS benchmarks. No changes are made to system files by this script."
    epilog = f"""
Examples:

    Run with debug enabled:
    {__file__} --debug

    Exclude tests from section 1.1 and 1.3.2:
    {__file__} --exclude 1.1 1.3.2

    Include tests only from section 4.1 but exclude tests from section 4.1.1:
    {__file__} --include 4.1 --exclude 4.1.1

    Run only level 1 tests
    {__file__} --level 1

    Run level 1 tests and include some but not all SELinux questions
    {__file__} --level 1 --include 1.6 --exclude 1.6.1.2
    """

    level_choices = [1, 2]
    log_level_choices = ['DEBUG', 'INFO', 'WARNING', 'CRITICAL']
    output_choices = ['csv', 'json', 'psv', 'text', 'tsv']
    system_type_choices = ['server', 'workstation']
    version_str = f'{os.path.basename(__file__)} {__version__})'

    parser = ArgumentParser(description=description, epilog=epilog, formatter_class=RawTextHelpFormatter)

    parser.add_argument('--level', action='store', choices=level_choices, default=0, type=int, help='Run tests for the specified level only')
    parser.add_argument('--include', action='store', nargs='+', dest='includes', help='Space delimited list of tests to include')
    parser.add_argument('--exclude', action='store', nargs='+', dest='excludes', help='Space delimited list of tests to exclude')
    parser.add_argument('-l', '--log-level', action='store', choices=log_level_choices, default='INFO', help='Set log output level')
    parser.add_argument('--debug', action='store_const', const='DEBUG', dest='log_level', help='Run script with debug output turned on. Equivalent to --log-level DEBUG')
    parser.add_argument('--nice', action='store_true', default=True, help='Lower the CPU priority for test execution. This is the default behaviour.')
    parser.add_argument('--no-nice', action='store_false', dest='nice', help='Do not lower CPU priority for test execution. This may make the tests complete faster but at the cost of putting a higher load on the server. Setting this overrides the --nice option.')
    parser.add_argument('--no-colour', '--no-color', action='store_true', help='Disable colouring for STDOUT. Output redirected to a file/pipe is never coloured.')
    parser.add_argument('--system-type', action='store', choices=system_type_choices, default='server', help='Set which test level to reference')
    parser.add_argument('--server', action='store_const', const='server', dest='system_type', help='Use "server" levels to determine which tests to run. Equivalent to --system-type server [Default]')
    parser.add_argument('--workstation', action='store_const', const='workstation', dest='system_type', help='Use "workstation" levels to determine which tests to run. Equivalent to --system-type workstation')
    parser.add_argument('--outformat', action='store', choices=output_choices, default='text', help='Output type for results')
    parser.add_argument('--text', action='store_const', const='text', dest='outformat', help='Output results as text. Equivalent to --output text [default]')
    parser.add_argument('--json', action='store_const', const='json', dest='outformat', help='Output results as json. Equivalent to --output json')
    parser.add_argument('--csv', action='store_const', const='csv', dest='outformat', help='Output results as comma-separated values. Equivalent to --output csv')
    parser.add_argument('--psv', action='store_const', const='psv', dest='outformat', help='Output results as pipe-separated values. Equivalent to --output psv')
    parser.add_argument('--tsv', action='store_const', const='tsv', dest='outformat', help='Output results as tab-separated values. Equivalent to --output tsv')
    parser.add_argument('-V', '--version', action='version', version=version_str, help='Print version and exit')
    parser.add_argument('-c', '--config', action='store', help='Location of config file to load')

    args = parser.parse_args(argv[1:])

    logger = logging.getLogger(__name__)

    ## --log-level
    if args.log_level == 'DEBUG':
        logger.setLevel(level=args.log_level)
        logger.debug('Debugging enabled')

    ## --nice
    if args.nice:
        logger.debug('Tests will run with reduced CPU priority')

    ## --no-colour
    if args.no_colour:
        logger.debug('Coloured output will be disabled')

    ## --include
    if args.includes:
        logger.debug(f'Include list is populated "{args.includes}"')
    else:
        logger.debug('Include list is empty')

    ## --exclude
    if args.excludes:
        logger.debug(f'Exclude list is populated "{args.excludes}"')
    else:
        logger.debug('Exclude list is empty')

    ## --level
    if args.level == 0:
        logger.debug('Going to run tests from any level')
    elif args.level == 1:
        logger.debug('Going to run Level 1 tests')
    elif args.level == 2:
        logger.debug('Going to run Level 2 tests')

    ## --system-type
    if args.system_type == 'server':
        logger.debug('Going to use "server" levels for test determination')
    elif args.system_type == 'workstation':
        logger.debug('Going to use "workstation" levels for test determination')

    ## --outformat
    if args.outformat == 'text':
        logger.debug('Going to use "text" outputter')
    elif args.outformat == 'json':
        logger.debug('Going to use "json" outputter')
    elif args.outformat == 'csv':
        logger.debug('Going to use "csv" outputter')

    return args


### Entrypoint ###
if __name__ == '__main__':  # pragma: no cover
    main()
