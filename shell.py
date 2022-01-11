from cmd import Cmd
from enum import Enum
import parse_qualys_report as report
import constants


class CommandState(Enum):
    ROOT = "root"
    REPORT = "report"
    IPS = "ips"


class Prompt(Cmd):
    prompt =constants.DEFAULT_PROMPT
    intro = "Welcome to the qvh shell v" + constants.VERSION + "! Type ? to list commands"

    def __init__(self, *args, **kwargs):
        super(Prompt, self).__init__(*args, **kwargs)
        self.report = report.ReportData()
        self._state = CommandState.ROOT
        self._reportfile = ""
        self._ips = []
        self._ips_to_use = []
        self._outfile = False

    # Private functions
    def _set_report_file(self, filename):
        print("Loading {}...".format(filename))
        self._reportfile = filename
        if not self.report.load_report(filename):
            return

        self._ips = self.report.get_all_hosts()
        self._ips_to_use = []
        self.report.colorize = True
        self._state = CommandState.REPORT
        self.prompt = "qvh:report> "

    def _set_ips(self, ip_string):
        if ip_string == "":
            return

        self._ips_to_use = []
        if ip_string == "all":
            print("Using all IPs")
            for ip in self._ips:
                self._ips_to_use.append(str(ip))
        else:
            ip_string = ip_string.strip(',')
            ips = ip_string.split()
            for ip in ips:
                if ip not in self._ips_to_use:
                    self._ips_to_use.append(ip.strip())

        self._state = CommandState.IPS
        self.prompt = "qvh:report:ips> "

    # Public general functions
    def set_report_file_from_cli(self, filename):
        self._set_report_file(filename)

    def set_ips_from_cli(self, ips):
        self._set_ips(ips)

    # Commands
    def do_EOF(self):
        self._state = CommandState.ROOT
        self.report = None
        self.prompt = constants.DEFAULT_PROMPT

    def do_exit(self, inp):
        print("See ya!")
        return True

    def do_load(self, inp):
        self._set_report_file(inp)

    def do_gethosts(self, inp):
        if not self.check_state_report():
            return
        if self.report is None:
            print("You must load the report first using the 'load' command!")
            return

        # Parse additional params
        if inp != "":
            params = inp.split()
            if params[0].strip() == "sort":
                self.report.find_all_hosts(True)
                return

        self.report.find_all_hosts()

    def do_getloadedreport(self, inp):
        if not self.check_state_report():
            return
        print(self._reportfile)

    def do_getstate(self, inp):
        print(self._state)

    def do_ip(self, inp):
        if self.check_state_ips(False) and inp == "":   # Just show our assigned IPs
            for ip in self._ips_to_use:
                print(str(ip))
            return
        elif not self.check_state_ips(False) and inp == "":
            print("You must be in the ips context to use this command with no parameters")
            return
        elif not (self.check_state_report(False) or self.check_state_ips(False)):
            print("Command not available in this context")
            return

        self._set_ips(inp)

    def do_ssh(self, inp):
        if not self.check_state_ips(False) or len(self._ips_to_use) == 0:
            print("You must input IPs before you can use this command")
            return

        self.report.get_ssh_vulns(self._ips_to_use)

    def do_ssh_table_summary(self, inp):
        if not self.check_state_ips(False) or len(self._ips_to_use) == 0:
            print("You must input IPs before you can use this command")
            return

        self.report.get_ssh_vuln_summary_table(self._ips_to_use)

    def do_ssh_table_version(self, inp):
        if not self.check_state_ips(False) or len(self._ips_to_use) == 0:
            print("You must input IPs before you can use this command")
            return

        self.report.get_ssh_vuln_version_table(self._ips_to_use)

    def do_ssh_table_smallkey(self, inp):
        if not self.check_state_ips(False) or len(self._ips_to_use) == 0:
            print("You must input IPs before you can use this command")
            return

        self.report.get_ssh_smallkey_table(self._ips_to_use)

    def do_ssh_table_weaksettings(self, inp):
        if not self.check_state_ips(False) or len(self._ips_to_use) == 0:
            print("You must input IPs before you can use this command")
            return

        self.report.get_ssh_weaksettings_table(self._ips_to_use)

    def do_ssh_table_rollup(self, inp):
        if not self.check_state_ips(False) or len(self._ips_to_use) == 0:
            print("You must input IPs before you can use this command")
            return

        self.report.get_ssh_vuln_rollup_table()

    def do_test(self, inp):
        self.report.get_all_vulns_for_host("")

    def do_ssl(self, inp):
        if not self.check_state_report():
            return

        self.report.get_ssl_vuln_table(["", "", ""])

    def do_ssl_table_sweet32(self, inp):
        if not self.check_state_ips(False) or len(self._ips_to_use) == 0:
            print("You must input IPs before you can use this command")
            return

        self.report.get_ssl_sweet32_table()

    def do_tcp(self, inp):
        if not self.check_state_report():
            return

        self.report.get_tcp_table("")

    def do_qid_details(self, inp):
        if not (self.check_state_report() or self.check_state_ips()):
            return

        if inp != "":
            self.report.get_details_for_qid(inp)
        else:
            print("You must specify a QID")
            return

    def do_vuln_yaml(self, inp):
        if not self.check_state_ips(False) or len(self._ips_to_use) == 0:
            print("You must input IPs before you can use this command")
            return

        if inp == "":
            print("You must specify a QID")
            return

        for ip in self._ips_to_use:
            self.report.get_vuln_yaml(ip, inp, self._outfile)

    def do_outfile(self, inp):
        if inp == "":
            return "Disabled" if self._outfile else "Enabled"

        inp = inp.lower()
        if inp == "true" or inp == "1":
            self._outfile = True
            print("File output enabled")
        else:
            self._outfile = False
            print("File output disabled")

    # Help for commands
    def help_exit(self):
        print("exit: Exits the qvh shell")

    def help_load(self):
        print("load (filename): Loads the report specified by filename")

    def help_gethosts(self):
        print("gethosts [sort]: Gets a list of all hosts within the report (report must be loaded first). Sorts IPs if 'sort' is included")

    def help_getstate(self):
        print("getstate: Returns current command prompt state")

    def help_getloadedreport(self):
        print("getloadedreport: Returns current loaded report")
    def help_ip(self):
        print("ip [list_of_ips]: A comma and/or space-separated list of IPs to report on. A keyword of 'all' will add all unique IPs in the report. With no arguments, shows all IPs that will be used to generate results.")

    def help_ssh(self):
        print("ssh: To do")

    def help_ssh_table_rollup(self):
        print("ssh_table_rollup: Shows a list of SSH vulnerabilities grouped by frequency")

    def help_ssh_table_smallkey(self):
        print("ssh_table_smallkey: Shows a list IP addresses that have unacceptably short SSH keys along with the key lengths")

    def help_ssh_table_summary(self):
        print("ssh_table_summary: Displays a table of IP addresses and associated SSH vulnerabilities")

    def help_ssh_table_version(self):
        print("ssh_table_version: Displays a table of SSH versions per IP address")

    def help_ssh_table_weaksettings(self):
        print("ssh_table_weaksettings: Displays a table of weak SSH settings (ciphers, key exchange, etc.) per IP address")

    def help_ssl_table_sweet32(self):
        print("ssl_table_sweet32: Displays a table of SSL services vulnerable to SWEET32")

    def help_tcp(self):
        print("tcp: Shows a list of listening TCP ports/services")

    def help_EOF(self):
        print("Returns to the root qvh command prompt")

    # Helpers
    def check_state_root(self, error_out=True):
        if self._state != CommandState.ROOT:
            if error_out:
                print("Command not available in this context")
            return False

        return True

    def check_state_report(self, error_out=True):
        if self._state != CommandState.REPORT:
            if error_out:
                print("Command not available in this context")
            return False

        return True

    def check_state_ips(self, error_out=True):
        if self._state != CommandState.IPS:
            if error_out:
                print("Command not available in this context")
            return False

        return True

