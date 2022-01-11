from colorama import Fore, Back, Style
import pandas
import math
from enum import Enum


class CVSS_STRING_TYPE(Enum):
    CVSS2_BASE = "CVSS2 Base"
    CVSS2_TEMPORAL = "CVSS2 Temporal"
    CVSS3_BASE = "CVSS3 Base"
    CVSS3_TEMPORAL = "CVSS3 Temporal"


class SortableIP:   # Can use this to add to a dictionary (make a key of ip_and_port)
    ip = ""
    port = ""
    ip_and_port = ""

    def __init__(self):
        self.ip = ""
        self.port = ""
        self.ip_and_port = ""

    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.ip_and_port = ip + ":" + port


class QVHType:
    def __init__(self):
        self._colorize = False

    def colorize(self):
        return self._colorize

    def colorize(self, color):
        self._colorize = color


class CVSS(QVHType):
    def __init__(self):
        self.cvss_base_score = "N/A"
        self.cvss_temporal_score = "N/A"
        self.cvss3_base_score = "N/A"
        self.cvss3_temporal_score = "N/A"
        self.cvss_base_vector = "N/A"
        self.cvss_temporal_vector = "N/A"
        self.cvss3_base_vector = "N/A"
        self.cvss3_temporal_vector = "N/A"

    def __str__(self):
        return "CVSS Base Score: {}\nCVSS Temporal Score: {}\nCVSS 3 Base Score: {}\nCVSS 3 Temporal Score: {}".format(self._get_colorized_cvss_string(self.cvss_base), self._get_colorized_cvss_string(self.cvss_temporal),
                                                                                                                       self._get_colorized_cvss_string(self.cvss3_base), self._get_colorized_cvss_string(self.cvss3_temporal))

    def _get_cvss_string_tuple(self, cvss_string):
        if cvss_string == "":
            return "", ""

        parts = cvss_string.split("(")
        if len(parts) != 2:
            return "", ""

        cvss_score = parts[0].strip()
        cvss_vector = parts[1].strip(")").strip()

        return cvss_score, cvss_vector

    def parse_qualys_cvss_string(self, cvss, cvss_type):
        # Qualys has a format of score (vector), break it into normal parts
        if cvss == "":
            return

        score, vector = self._get_cvss_string_tuple(cvss)

        if cvss_type == CVSS_STRING_TYPE.CVSS2_BASE:
            self.cvss_base_score = score
            self.cvss_base_vector = vector
        elif cvss_type == CVSS_STRING_TYPE.CVSS2_TEMPORAL:
            self.cvss_temporal_score = score
            self.cvss_temporal_vector = vector
        elif cvss_type == CVSS_STRING_TYPE.CVSS3_BASE:
            self.cvss3_base_score = score
            self.cvss3_base_vector = vector
        elif cvss_type == CVSS_STRING_TYPE.CVSS3_TEMPORAL:
            self.cvss3_temporal_score = score
            self.cvss3_temporal_vector = vector

    def _get_colorized_cvss_string(self, cvss_string):
        if not self.colorize:
            return cvss_string  # We're not coloring the string

        if cvss_string == "" or cvss_string is None or (isinstance(cvss_string, float) and math.isnan(cvss_string)):
            return ""

        # Is this a standalone number?
        if isinstance(cvss_string, float):
            # A float, just color the whole thing
            return self._set_color_for_score(cvss_string)
        else:
            parts = cvss_string.split(" ")
            if len(parts) < 2:
                return cvss_string

            return self._set_color_for_score(parts[0].strip())

        return cvss_string

    def _set_color_for_score(self, score_str):
        score = float(score_str)
        if score == 0.0:
            return Fore.BLUE + str(score) + Style.RESET_ALL
        elif score < 4.0:
            return Fore.GREEN + str(score) + Style.RESET_ALL
        elif 4.0 <= score < 7.0:
            return Fore.YELLOW + str(score) + Style.RESET_ALL
        elif score >= 7.0:
            return Fore.RED + str(score) + Style.RESET_ALL
        else:
            return str(score)


class Vuln(QVHType):
    def __init__(self):
        self.qid = 0
        self.title = ""
        self.category = ""
        self.threat = ""
        self.impact = ""
        self.solution = ""
        self.cvss = None
        self.port = ""
        self.protocol = ""
        self.severity = 0
        self.results = ""
        self.os = ""
        self.cvss = None
        self.host = None

    def __str__(self):
        if self.colorize:
            result = "Title: {}\n""QID: {}\nCategory: {}\nPort: {}\nSeverity: {}\nThreat:\n{}\nImpact:\n{}\nSolution:\n{}\nResults:\n{}".format(self.title, self.qid, self.category, get_port_string(self.port, self.protocol), self.severity, self.threat, self.impact, self.solution, self.results)
        else:
            result = "Title: {}\n""QID: {}\nCategory: {}\nPort: {}\nSeverity: {}\nThreat:\n{}\nImpact:\n{}\nSolution:\n{}\nResults:\n{}".format(self.title, self.qid, self.category, get_port_string(self.port, self.protocol), self.severity, self.threat, self.impact, self.solution, self.results)

        if self.cvss is not None:
            result += "\n" + str(self.cvss)
        return result

    def create_vuln_object(self, dictData):
        if dictData is None:
            return None

        self.cvss = CVSS()
        self.host = Host()

        if "qid" in dictData:
            self.qid = dictData["qid"]
        if "title" in dictData:
            self.title = dictData["title"]
        if "category" in dictData:
            self.category = dictData["category"]
        if "cvss_base" in dictData:
            self.cvss.parse_qualys_cvss_string(dictData["cvss_base"], CVSS_STRING_TYPE.CVSS2_BASE)
        if "cvss_temporal" in dictData:
            self.cvss.parse_qualys_cvss_string(dictData["cvss_temporal"], CVSS_STRING_TYPE.CVSS2_TEMPORAL)
        if "cvss3_base" in dictData:
            self.cvss.parse_qualys_cvss_string(dictData["cvss3_base"], CVSS_STRING_TYPE.CVSS3_BASE)
        if "cvss3_temporal" in dictData:
            self.cvss.parse_qualys_cvss_string(dictData["cvss3_temporal"], CVSS_STRING_TYPE.CVSS3_TEMPORAL)
        if "threat" in dictData:
            self.threat = get_clean_none_string(dictData["threat"])
        if "impact" in dictData:
            self.impact = get_clean_none_string(dictData["impact"])
        if "solution" in dictData:
            self.solution = get_clean_none_string(dictData["solution"])
        if "severity" in dictData:
            self.severity = dictData["severity"]
        if "port" in dictData:
            self.port = dictData["port"]
        if "protocol" in dictData:
            self.protocol = dictData["protocol"]
        if "results" in dictData:
            self.results = get_clean_none_string(dictData["results"])
        if "os" in dictData:
            self.os = dictData["os"]
        if "ip" in dictData:
            self.host.ip = dictData["ip"]
        if "dns" in dictData:
            self.host.dns = dictData["dns"]
        if "netbios" in dictData:
            self.host.netbios = dictData["netbios"]

    def colorize(self, color):
        QVHType.colorize(color)
        if self.cvss is not None:
            self.cvss.colorize(color)
        if self.host is not None:
            self.host.colorize(color)

class Host(QVHType):
    def __init__(self):
        self.ip = ""
        self.dns = ""
        self.netbios = ""


# Helper functions
def check_na_type(value):
    if pandas.isna(value):
        return ""
    return value


def get_port_string(port, protocol, show_na=True):
    if check_na_type(port) == "" or check_na_type(protocol) == "":
        return "N/A" if show_na else ""
    if port == "":
        return "N/A" if show_na else ""
    if protocol == "":
        return str(port)

    return str(port) + "/" + protocol


def get_clean_none_string(string):
    if check_na_type(string) == "":
        return "None"
    if string == "":
        return "None"

    return string
