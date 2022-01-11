#!/usr/bin/env python3

import shell as Shell
import argparse
import constants
from os.path import exists


def __main__():
    shell = Shell.Prompt()

    parser = argparse.ArgumentParser(description="Qualys Vulnerability Hunter (qvh) v" + constants.VERSION)
    parser.add_argument("--report", help="Path to the CSV report to parse")
    parser.add_argument("--ips", help="Comma-separated list of IPs to use (requires --report)")
    #parser.add_argument("--command")
    #parser.add_argument("--one-shot")
    args = parser.parse_args()
    if args.report is not None and args.report != "":
        # Can we open the file?
        if not exists(args.report):
            print("Report file does not exist: {}".format(args.report))
            return
        shell.set_report_file_from_cli(args.report)
    if args.ips is not None and args.ips != "":
        # Make sure we have a report too
        if args.report is None or args.report == "":
            print("You must set a report on the command line to use --ips")
            return
        shell.set_ips_from_cli(args.ips)

    shell.cmdloop()


__main__()
