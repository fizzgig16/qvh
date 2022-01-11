from colorama import Fore, Back, Style
import pandas
import ipaddress
import qvh_types as QVHTypes
from cvss import CVSS2, CVSS3


SSH_VULNS = [38611,38623,38679,38692,38725,38726,38738,38739,38788,42382,42384,42413,42428]
SSL_VULNS = [13607,38169,38170,38172,38173,38174,38596,38597,38628,38657,38685,38794]


class ReportData:

    def __init__(self):
        self._dataframe = None
        self.colorize = False

    def _put_results_in_vuln(self, row):
        return self._put_results_in_vuln(self._dataframe, row)

    def _put_results_in_vuln(self, data, row):
        if row is None:
            return None

        vuln = None
        dictVulnData = {}

        dictVulnData["ip"] = data.iloc[row, 0]
        dictVulnData["dns"] = data.iloc[row, 1]
        dictVulnData["netbios"] = data.iloc[row, 2]
        dictVulnData["os"] = data.iloc[row, 3]
        dictVulnData["qid"] = data.iloc[row, 5]
        dictVulnData["title"] = data.iloc[row, 6]
        dictVulnData["category"] = data.iloc[row, 29]
        dictVulnData["cvss_base"] = data.iloc[row, 16]
        dictVulnData["cvss_temporal"] = data.iloc[row, 17]
        dictVulnData["cvss3_base"] = data.iloc[row, 18]
        dictVulnData["cvss3_temporal"] = data.iloc[row, 19]
        dictVulnData["threat"] = data.iloc[row, 20]
        dictVulnData["impact"] = data.iloc[row, 21]
        dictVulnData["solution"] = data.iloc[row, 22]
        dictVulnData["severity"] = data.iloc[row, 8]
        dictVulnData["port"] = data.iloc[row, 9]
        dictVulnData["protocol"] = data.iloc[row, 10]
        dictVulnData["results"] = data.iloc[row, 25]
        vuln = QVHTypes.Vuln()
        vuln.create_vuln_object(dictVulnData)

        return vuln

    def load_report(self, file_to_open):
        try:
            self._dataframe = pandas.read_csv(file_to_open, skiprows=7, header=0)
            self._dataframe.Port = self._dataframe.Port.astype('Int64')
        except Exception as ex:
            print("Unable to read file: " + str(ex))
            return False

        print(self._dataframe)
        return True

    def find_all_hosts(self, sort=False):
        if self._dataframe is None:
            return False

        a = self._dataframe['IP'].drop_duplicates()
        for ip in sorted(ipaddress.ip_address(addr) for addr in a):
            print(ip)

        return True

    def get_all_hosts(self):
        if self._dataframe is None:
            return []

        final_list = []
        for ip in sorted(ipaddress.ip_address(addr) for addr in list(self._dataframe['IP'].unique())):
            final_list.append(ip)

        return final_list

    def get_details_for_qid(self, qid):
        if self._dataframe is None:
            return False

        qid_num = 0
        try:
            qid_num = int(qid)
        except:
            print("QID must be an integer")
            return False

        vulns = []
        result_set = self._dataframe[self._dataframe['QID'] == qid_num]
        for row in range(len(result_set)):
            vuln = self._put_results_in_vuln(row)
            if vuln is not None:
                vulns.append(vuln)
            else:
                print("Vuln was none")

        if len(vulns) == 0:
            print("No results returned")
            return False

        ips = ""
        print("Threat|Solution|IPs")
        for vuln in vulns:
            ips = ips + str(vuln.host.ip) + ", "

        ips = ips.strip().strip(',')
        print("{}|{}|{}".format(vulns[0].threat, vulns[0].solution, ips))
        return True

    def get_all_vulns_for_host(self, ip):
        if self._dataframe is None:
            return False

        result_set = self._dataframe[(self._dataframe['IP'] == ip) & (self._dataframe['Type'] == "Vuln")]
        for row in range(len(result_set)):
            vuln = self._put_results_in_vuln(row)
            vuln.colorize = True
            if vuln is not None:
                print(str(vuln))
            else:
                print("Vuln was none")

        return True

    def get_ssh_vulns(self, hosts):
        if self._dataframe is None:
            return False

        for host in hosts:
            for row in range(len(self._dataframe)):
                if host == self._dataframe.iloc[row, 0]:
                    for ssh_vuln in SSH_VULNS:
                        if str(self._dataframe.iloc[row, 5]) == str(ssh_vuln):
                            vuln = self._put_results_in_vuln(row)
                            if vuln is not None:
                                if self.colorize:
                                    print(Fore.MAGENTA + "IP: " + host + "\n" + Style.RESET_ALL + str(vuln) + "\n----------------------------\n")
                                else:
                                    print("IP: " + host + "\n" + str(vuln) + "\n----------------------------\n")
                                break   # Since we already matched one we can stop searching
                            else:
                                print("Vuln was none")

    def get_ssh_vuln_summary_table(self, hosts):
        if self._dataframe is None:
            return False

        print("IP|Port|Vulnerability")
        for host in hosts:
            for row in range(len(self._dataframe)):
                if host == self._dataframe.iloc[row, 0]:
                    for ssh_vuln in SSH_VULNS:
                        if str(self._dataframe.iloc[row, 5]) == str(ssh_vuln):
                            vuln = self._put_results_in_vuln(row)
                            if vuln is not None:
                                print("{}|{}|{}".format(host, QVHTypes.get_port_string(vuln.port, vuln.protocol, False), vuln.title))
                                break   # Since we already matched one we can stop searching
                            else:
                                print("Vuln was none")

    def get_ssh_vuln_version_table(self, hosts):
        if self._dataframe is None:
            return False

        print("IP|Port|Version")
        for host in hosts:
            for row in range(len(self._dataframe)):
                if host == self._dataframe.iloc[row, 0] and str(self._dataframe.iloc[row, 5]) == "38050":
                    vuln = self._put_results_in_vuln(row)
                    if vuln is not None:
                        print("{}|{}|{}".format(host, QVHTypes.get_port_string(vuln.port, vuln.protocol, False), vuln.results))
                        break  # Since we already matched one we can stop searching
                    else:
                        print("Vuln was none")

    def get_ssh_smallkey_table(self, hosts):
        if self._dataframe is None:
            return False

        print("IP|Port|Key Information")
        for host in hosts:
            for row in range(len(self._dataframe)):
                if host == self._dataframe.iloc[row, 0] and str(self._dataframe.iloc[row, 5]) == "38738":
                    vuln = self._put_results_in_vuln(row)
                    if vuln is not None:
                        # Clean up the results
                        results = '\n'.join(vuln.results.split("\n")[1:])
                        print("{}|{}|{}".format(host, QVHTypes.get_port_string(vuln.port, vuln.protocol, False), results))
                        break  # Since we already matched one we can stop searching
                    else:
                        print("Vuln was none")

    def get_ssh_weaksettings_table(self, hosts):
        if self._dataframe is None:
            return False

        print("IP|Port|Weak Settings")
        for host in hosts:
            for row in range(len(self._dataframe)):
                if host == self._dataframe.iloc[row, 0] and str(self._dataframe.iloc[row, 5]) == "38739":
                    vuln = self._put_results_in_vuln(row)
                    if vuln is not None:
                        # Clean up the results
                        results = ', '.join(vuln.results.split("\n")[1:])
                        results = results.replace('\t', ': ')
                        print("{}|{}|{}".format(host, QVHTypes.get_port_string(vuln.port, vuln.protocol, False), results))
                        break  # Since we already matched one we can stop searching
                    else:
                        print("Vuln was none")

    def get_ssh_vuln_rollup_table(self, hosts=None):
        if self._dataframe is None:
            return False

        rollup = {}
        print("Vulnerability|Count")
        if hosts is None:
            for row in range(len(self._dataframe)):
                for ssh_vuln in SSH_VULNS:
                    if str(self._dataframe.iloc[row, 5]) == str(ssh_vuln):
                        title = self._dataframe.iloc[row, 6]  # title
                        if title in rollup:
                            rollup[title] = rollup[title] + 1
                        else:
                            rollup[title] = 1
        else:
            for host in hosts:
                for row in range(len(self._dataframe)):
                    for ssh_vuln in SSH_VULNS:
                        if host == self._dataframe.iloc[row, 0] and str(self._dataframe.iloc[row, 5]) == str(ssh_vuln):
                            title = self._dataframe.iloc[row, 6]    # title
                            if title in rollup:
                                rollup[title] = rollup[title] + 1
                            else:
                                rollup[title] = 1

        # Create a dictionary sorted by occurrence in descending order
        rollup_list = sorted(((value, key) for (key, value) in rollup.items()), reverse=True)
        sort_rollup = dict([(k, v) for v, k in rollup_list])
        for vuln_name, count in sort_rollup.items():
            print("{}|{}".format(vuln_name, count))

    def get_ssl_vulns(self, hosts):
        if self._dataframe is None:
            return False

        for host in hosts:
            for row in range(len(self._dataframe)):
                if host == self._dataframe.iloc[row, 0]:
                    for ssh_vuln in SSL_VULNS:
                        if str(self._dataframe.iloc[row, 5]) == str(ssh_vuln):
                            vuln = self._put_results_in_vuln(row)
                            if vuln is not None:
                                if self.colorize:
                                    print(Fore.MAGENTA + "IP: " + host + "\n" + Style.RESET_ALL + str(vuln) + "\n----------------------------\n")
                                else:
                                    print("IP: " + host + "\n" + str(vuln) + "\n----------------------------\n")
                                break   # Since we already matched one we can stop searching
                            else:
                                print("Vuln was none")

    def get_ssl_sweet32_table(self, hosts=None):
        if self._dataframe is None:
            return False

        print("IP|Port")
        if hosts is None:
            for row in range(len(self._dataframe)):
                if str(self._dataframe.iloc[row, 5]) == "38657":
                    vuln = self._put_results_in_vuln(row)
                    if vuln is not None:
                        print("{}|{}".format(self._dataframe.iloc[row, 0], QVHTypes.get_port_string(vuln.port, vuln.protocol, False)))
                    else:
                        print("Vuln was none")
        else:
            for host in hosts:
                for row in range(len(self._dataframe)):
                    if host == self._dataframe.iloc[row, 0] and str(self._dataframe.iloc[row, 5]) == "38657":
                        vuln = self._put_results_in_vuln(row)
                        if vuln is not None:
                            print("{}|{}".format(host, QVHTypes.get_port_string(vuln.port, vuln.protocol, False)))
                            break  # Since we already matched one we can stop searching
                        else:
                            print("Vuln was none")

    def get_tcp_table(self, ip):
        if self._dataframe is None:
            return False

        for row in range(len(self._dataframe)):
            if ip == self._dataframe.iloc[row, 0] and str(self._dataframe.iloc[row, 5]) == "82023":
                # We don't need a vuln really, we just care about the results field
                vuln = self._put_results_in_vuln(row)
                print(vuln.results)

        return True

    def _get_cvss_yaml_data(self, vector):
        output = ""

        if vector == "" or vector is None:
            return ""

        cvss = vector.upper()
        if not cvss.startswith("CVSS"):
            vector = "CVSS:3.0/" + vector

        # Parse the CVSS string for real names
        try:
            cvss = CVSS3(vector)
            output = "attack-vector: {}\n".format(cvss.get_value_description("AV"))
            output = output + "attack-complexity: {}\n".format(cvss.get_value_description("AC"))
            output = output + "privileges-required: {}\n".format(cvss.get_value_description("PR"))
            output = output + "user-interaction: {}\n".format(cvss.get_value_description("UI"))
            output = output + "scope: {}\n".format(cvss.get_value_description("S"))
            output = output + "confidentiality: {}\n".format(cvss.get_value_description("C"))
            output = output + "integrity: {}\n".format(cvss.get_value_description("I"))
            output = output + "availability: {}\n".format(cvss.get_value_description("A"))
        except Exception as ex:
            print("Error parsing CVSS: " + str(ex))
            return ""

        return output

    def get_vuln_yaml(self, host, qid, outfile_flag):
        qid_num = 0

        if self._dataframe is None:
            return False

        try:
            qid_num = int(qid)
        except:
            print("QID must be an integer")
            return False

        # Are we also writing to a file?
        file_out = open("output/{}_{}.yml".format(host, qid), 'w')

        result_set = self._dataframe[(self._dataframe['IP'] == host) & (self._dataframe['QID'] == qid_num)]
        for row in range(len(result_set)):
            vuln = self._put_results_in_vuln(result_set, row)
            # Start output for yaml
            print("---")
            print("title: {}".format(vuln.title))
            print()
            print("business-summary: <TO DO>")
            print()
            print("type: <TO DO>")
            print()
            print("cvss:")
            print(self._get_cvss_yaml_data(vuln.cvss.cvss3_base_vector))
            print("business-impact:")
            print("  reputation-damage: True|False")
            print("  non-compliance: True|False")
            print("  financial-damage: True|False")
            print("  privacy-violation: True|False")
            print()
            print("tests-violated:")
            print("  - <TO DO>")
            print()
            print("coria-id: N/A")
            print()
            print("scenario-id: N/A")
            print()
            print("finding-schema-version: 2")
            print()
            print("---")
            print("# Vulnerability Description")
            print(vuln.threat)
            print()
            print("# Vulnerability Impact")
            print(vuln.impact)
            print()
            print("# Details")
            print(vuln.results)
            print()
            print("# Remediation")
            print(vuln.solution)

            # Are we also writing to a file? (Yes this is lazy, but it's a one-off report)
            if outfile_flag:
                print("---", file=file_out)
                print("title: {}".format(vuln.title), file=file_out)
                print(file=file_out)
                print("business-summary: <TO DO>", file=file_out)
                print(file=file_out)
                print("type: <TO DO>", file=file_out)
                print(file=file_out)
                print("cvss:", file=file_out)
                print(self._get_cvss_yaml_data(vuln.cvss.cvss3_base_vector), file=file_out)
                print("business-impact:", file=file_out)
                print("  reputation-damage: True|False", file=file_out)
                print("  non-compliance: True|False", file=file_out)
                print("  financial-damage: True|False", file=file_out)
                print("  privacy-violation: True|False", file=file_out)
                print(file=file_out)
                print("tests-violated:", file=file_out)
                print("  - <TO DO>", file=file_out)
                print(file=file_out)
                print("coria-id: N/A", file=file_out)
                print(file=file_out)
                print("scenario-id: N/A", file=file_out)
                print(file=file_out)
                print("finding-schema-version: 2", file=file_out)
                print(file=file_out)
                print("---", file=file_out)
                print("# Vulnerability Description", file=file_out)
                print(vuln.threat, file=file_out)
                print(file=file_out)
                print("# Vulnerability Impact", file=file_out)
                print(vuln.impact, file=file_out)
                print(file=file_out)
                print("# Details", file=file_out)
                print(vuln.results, file=file_out)
                print(file=file_out)
                print("# Remediation", file=file_out)
                print(vuln.solution, file=file_out)

