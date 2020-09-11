#!/usr/bin/env python3
# Thunderstorm (THOR Service) API Command Line Client
# Florian Roth, 2020

__version__ = "0.1.0"

import os
import json
import time
import logging
import platform
import argparse
import time
import traceback
import fnmatch
import urllib3
from thunderstormAPI.thunderstorm import ThunderstormAPI

LEVELS = {
    'Debug': 1,
    'Info': 2,
    'Notice': 3,
    'Error': 4,
    'Warning': 5,
    'Alert': 6
}

urllib3.disable_warnings()


def main():
    """
    Main Function (used as entry point)
    :return:
    """
    # Parse Arguments
    parser = argparse.ArgumentParser(description='THOR-Thunderstorm-CLI')

    parser.add_argument('-t', '--thor_host', help='THOR service host', metavar='host', default='127.0.0.1')
    parser.add_argument('-p', '--thor_port', help='THOR service port', metavar='port', default=8080)
    parser.add_argument('--ssl', action='store_true', help='Use TLS/SSL (HTTPS)', default=False)
    parser.add_argument('--strict_ssl', help='Use strict TLS/SSL (deny self-signed SSL certificates)',
                        metavar='strict-ssl', default=False)
    parser.add_argument('-o', '--source', help='Source identifier (used in Thunderstorm server log)',
                        metavar='source', default=platform.uname()[1])

    group_status = parser.add_argument_group(
        '=======================================================================\nInfo')
    group_status.add_argument('--status', action='store_true', default=False,
                              help='Get status information from the service (processed samples, errors, runtime)')
    group_status.add_argument('--info', action='store_true', default=False,
                              help='Get general information (versions, license info)')
    group_status.add_argument('--result', action='store_true', default=False,
                              help='Get information on a certain sample id')
    group_status.add_argument('-r', '--id', help='Sample ID returned in asynchronous result', metavar='sample-id')

    group_transmit = parser.add_argument_group(
        '=======================================================================\nScan')
    group_transmit.add_argument('-s', '--scan', action='store_true', default=False,
                                help='Transmit sample file to get it scanned')
    group_transmit.add_argument('-f', '--file', help='Sample file', metavar='sample')
    group_transmit.add_argument('-d', '--dir', help='Sample directory', metavar='sample-dir')
    group_transmit.add_argument('-e', '--exclude', action='append', nargs='+',
                                help='Exclude pattern (can be used multiple times)')
    group_transmit.add_argument('-i', '--include', action='append', nargs='+',
                                help='Include pattern (can be used multiple times)')
    group_transmit.add_argument('-l', '--lookback', metavar='lookback', default=0,
                                help='Only submit files created or modified within the last X seconds')
    group_transmit.add_argument('-n', '--threads', help='Number of threads', metavar='threads', default=12)
    group_transmit.add_argument('-m', '--min_level',
                                help='Minimum level to report (Debug=1, Info=2, Notice=3, Error=4, Warning=5, Alert=6)',
                                metavar='minimum-level', default=3)
    group_transmit.add_argument('--asyn', action='store_true', default=False,
                                help='Asynchronous transmission (server just returns a send receipt and not a result, '
                                     'which allows a much fast transmission)')

    group_proxy = parser.add_argument_group(
        '=======================================================================\nProxy')
    group_proxy.add_argument('-ps', '--proxy', help='proxy URL (e.g. https://my.proxy.net:8080)', metavar='proxy-url', default='')
    group_proxy.add_argument('-pu', '--proxy_user', help='proxy user', metavar='proxy-user', default='')
    group_proxy.add_argument('-pp', '--proxy_pass', help='proxy password', metavar='proxy-pass', default='')

    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')
    parser.add_argument('--trace', action='store_true', default=False, help='Trace output')

    args = parser.parse_args()

    print(" ")
    print("=======================================================================")
    print("    ________                __            __                ")
    print("   /_  __/ /  __ _____  ___/ /__ _______ / /____  ______ _  ")
    print("    / / / _ \\/ // / _ \\/ _  / -_) __(_-</ __/ _ \\/ __/  ' \\ ")
    print("   /_/ /_//_/\\_,_/_//_/\\_,_/\\__/_/ /___/\\__/\\___/_/ /_/_/_/ ")
    print("   THOR Service API Client                                  ")
    print("   Version %s, Florian Roth, 2020                        " % __version__)
    print(" ")

    print("=======================================================================")
    print(" ")

    # Logging
    logFormatter = logging.Formatter("[%(levelname)-5.5s] %(message)s")
    logFormatterRemote = logging.Formatter("{0} [%(levelname)-5.5s] %(message)s".format(platform.uname()[1]))
    Log = logging.getLogger(__name__)
    Log.setLevel(logging.INFO)
    # Console Handler
    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(logFormatter)
    Log.addHandler(consoleHandler)

    # Debug
    if args.debug:
        Log.setLevel(logging.DEBUG)

    use_ssl = "without"
    if args.ssl:
        use_ssl = "with"
    Log.info("Using THOR Thunderstorm service on host %s port %s %s SSL/TLS" % (args.thor_host, args.thor_port, use_ssl))
    thorapi = ThunderstormAPI(host=args.thor_host, port=args.thor_port, use_ssl=args.ssl, verify_ssl=args.strict_ssl)

    # Set Proxy
    if args.proxy:
        thorapi.set_proxy(args.proxy, args.proxy_user, args.proxy_pass)

    # If no option has been selected
    if not args.status and not args.info and not args.scan and not args.result:
        print("You have to select one these actions: --info, --status or --scan")

    # Status
    if args.status:
        result = thorapi.get_status(debug=args.debug)
        print(json.dumps(result, indent=4, sort_keys=True))

    # Info
    if args.info:
        result = thorapi.get_info(debug=args.debug)
        print(json.dumps(result, indent=4, sort_keys=True))

    # Sample Info
    if args.result:
        if args.id:
            result = thorapi.get_async_result(id=args.id)
            print(json.dumps(result, indent=4, sort_keys=True))
        else:
            print("Cannot query for a reuslt without an id (--id X)")

    # Transmit samples to the scan service
    if args.scan:
        # Get some status information from the host
        status = thorapi.get_status()
        if 'status' in status:
            if status['status'] == 'error':
                Log.error("Error: %s" % status['message'])
        else:
            try:
                av_scan_time = "N/A"
                if 'avg_scan_time_milliseconds' in status:
                    av_scan_time = "%sms" % status['avg_scan_time_milliseconds']
                Log.info("Thunderstorm service stats UPTIME: %s SCANNED_SAMPLES: %d AVG_SCAN_TIME: %s" % (
                    time.strftime('%Hh:%Mm:%Ss', time.gmtime(int(status['uptime_seconds']))),
                    int(status['scanned_samples']),
                    av_scan_time
                ))
            except KeyError as e:
                traceback.print_exc()
                Log.error("JSON response contains unexpected content")
                print(status)
            # Scan a single file
            if args.file:
                result = thorapi.scan(args.file, asyn=args.asyn, debug=args.debug, trace=args.trace)
                if args.debug:
                    Log.info("Submitting file %s for scanning ..." % args.file)
                print(result)
            # Scan a complete directory
            if args.dir:
                Log.info("Submitting samples from %s using %d threads" % (args.dir, int(args.threads)))
                num_found = 0
                num_selected = 0
                num_processed = 0
                for path, directories, files in os.walk(args.dir):
                    # Counters
                    num_found += len(files)
                    # Set filtered
                    filtered_files = files
                    # Exclude / Include
                    if args.exclude:
                        for e in args.exclude:
                            exclude = e[0]
                            if args.trace:
                                print("Exclude: %s" % exclude)
                            matching = fnmatch.filter(files, exclude)
                            if args.trace:
                                print("Exclude: %s" % matching)
                            filtered_files = [exclude for exclude in files if exclude not in matching]
                    if args.include:
                        for i in args.include:
                            include = i[0]
                            if args.trace:
                                print("Include: %s" % include)
                            matching = fnmatch.filter(files, include)
                            if args.trace:
                                print("Including: %s" % matching)
                            filtered_files = [include for include in files if include in matching]

                    # List of files to process
                    dir_files = [os.path.join(path, fi) for fi in filtered_files]

                    # Look-back
                    if int(args.lookback) > 0:
                        current_ts = time.time()
                        max_ts = current_ts - int(args.lookback)
                        selected_dir_files = []
                        for filepath in dir_files:
                            st = os.stat(filepath)
                            mtime = st.st_mtime
                            ctime = st.st_ctime
                            if ctime > max_ts or mtime > max_ts:
                                selected_dir_files.append(filepath)
                        dir_files = selected_dir_files

                    # Starting the scan
                    num_selected += len(dir_files)
                    if args.debug:
                        Log.info("Scanning path: %s with %d elements " % (path, len(dir_files)))

                    # Scan List of Files
                    results = thorapi.scan_multi(
                        filelist=dir_files,
                        num_threads=int(args.threads),
                        asyn=args.asyn,
                        debug=args.debug,
                        trace=args.trace
                    )
                    num_processed += len(results)

                    # Only process the results in synchronous mode
                    if not args.asyn:
                        # Process the results
                        for result in results:
                            #
                            if len(result) != 0:
                                if args.trace:
                                    print("MULTI SCAN MATCHES: %s" % json.dumps(results, indent=4))
                                # Not an error
                                if 'status' not in result:
                                    # Process all matches
                                    for match in result:
                                        # Lookup the level value from the static LEVEL dictionary
                                        if 'level' not in match:
                                            Log.error(
                                                "Something is wrong with the match object! Cannot process it: %s" % match)
                                            continue
                                        m_level = LEVELS[match['level']]
                                        # Original filename
                                        orig_name = match['context']['file']
                                        # If the match level is higher or equal to minimum level to report
                                        if m_level >= int(args.min_level):
                                            match_string = "Result returned for FILE: %s MATCH: %s" % (orig_name, match)
                                            if match['level']:
                                                if match['level'] == 'Debug':
                                                    Log.debug(match_string)
                                                if match['level'] == 'Info':
                                                    Log.debug(match_string)
                                                if match['level'] == 'Notice':
                                                    Log.info(match_string)
                                                if match['level'] == 'Warning':
                                                    Log.warning(match_string)
                                                if match['level'] == 'Alert':
                                                    Log.critical(match_string)

                Log.info("Finished submission FOUND: %d SELECTED: %d PROCESSED: %d" % (num_found, num_selected, num_processed))

        if not args.file and not args.dir:
            Log.error("You've used -s/--scan without providing a sample file (-f) or directory (-d) to scan")


if __name__ == "__main__":
    main()
