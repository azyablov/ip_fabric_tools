import re
import os
import ipaddress
import paramiko
import time
import socket
import pandas as pd
import numpy as np
from typing import List, Union, Tuple
from helpers import apply_template
from pprint import pprint as pp
import ipdb
import re
from helpers import color_up_down, ALERT, NO_ALERT
import logging
from abc import ABCMeta, abstractmethod

# ==== Resource variables and matching patterns ====
IP_ADDR_SEARCH_PATTERN = r'[^0-9]*([0-9]{1,3})\.([0-9]+)\.([0-9]+)\.([0-9]{1,3})[^0-9]*'  # TODO: revise pattern

SHOW_RTR_INF = r'show router interface'
SHOW_VER = r'show version'
SHOW_SYS_LLDP = r'show system lldp neighbor'
SHOW_SYS_NTP_SRV = r'show system ntp servers'

# Module logger
mod_log = logging.getLogger("l3topo.sroslib")


class FQDNResolutionError(ValueError):
    def __init__(self, host):
        msg = f"Can't resolve hostname {host}"
        super().__init__(msg)


class TFSMParsingError(ValueError):
    def __init__(self, host):
        msg = f"Can't parse command output correctly. Please check TFSM teamplate or command output."
        super().__init__(msg)


def extract_ipaddr(ip_addr_str: str, debug: bool = False) -> Union[ipaddress.IPv4Address, None]:
    """
    Function parses ip_addr_str and extract all possible IP@.
    :type debug: bool
    :type ip_addr_str: str
    :param ip_addr_str: string which should be parsed
    :param debug: enable/disable debug, disabled by default
    :return IPv4Address or bool
    """
    ip_addr_oct_list = ip_addr_str.split(sep='.')
    if len(ip_addr_oct_list) < 4:
        return None
    ip_addr_tuples = re.findall(IP_ADDR_SEARCH_PATTERN, ip_addr_str)
    # print(ip_addr_tuples)
    if ip_addr_tuples is None:
        return None

    # print('IP@:', list(ip_addr_tuples[0]))
    ip_str = '.'.join(ip_addr_tuples[0])
    try:
        ip_addr_obj = ipaddress.ip_address(ip_str)
    except ValueError as val_err:
        if debug:
            print('Provided string is not valid IP@:', ip_str, val_err.__str__())
        return None
    return ip_addr_obj


class SROSInf:
    """
    Class represents SROS interface state and data for WBXes.
    """

    def __init__(self, textfsm_data: list, *args, **kwargs):
        self._data = {"Name": textfsm_data[0], "AdmStatus": None, "OperStatusIPv4": None, "Port": None,
                      "IPv4Address": None, "PrefixLen": None}
        self.adm_status = textfsm_data[1]
        self.oper_status_ipv4 = textfsm_data[2]
        self._data["Port"] = textfsm_data[3]
        self._data["IPv4Address"] = textfsm_data[4]
        self._data["PrefixLen"] = textfsm_data[5]
        # Extracting proxy to make sure operation status attributes have necessary dependencies setup
        self._proxy = kwargs.get('proxy')
        self._data["IssueFound"] = self.issue_found
        self._data["Pingable"] = self.pingable
        self._data["LLDPNeighbor"] = self.lldp_neighbor

    @property
    def issue_found(self):
        if ("Down" in self._data["AdmStatus"] or
                "Down" in self._data["OperStatusIPv4"]):
            return ALERT
        elif ("Up" in self._data["AdmStatus"] and
              "Up" in self._data["OperStatusIPv4"]):
            return NO_ALERT
        else:
            msg = "Unknown state of AdmStatus or OperStatusIPv4"
            raise ValueError(msg)

    @property
    def adm_status(self):
        return self._data["AdmStatus"]

    @property
    def port(self):
        return self._data["Port"]

    @property
    def port_vlan(self):
        if len(self._data["Port"].split(':')) == 2:
            return self._data["Port"].split(':')[1]
        if len(self._data["Port"].split(':')) == 1:
            return None
        else:
            msg = f"Unable to get port vlan for {self._data['Name']}."
            mod_log.error(msg=msg)
            raise ValueError(msg)

    @adm_status.setter
    def adm_status(self, status: str):
        if status in ["Up", "Down"]:
            self._data["AdmStatus"] = status
        else:
            msg = "Unrecognised interface AdmStatus."
            mod_log.error(msg=msg)
            raise ValueError(msg)

    @property
    def oper_status_ipv4(self):
        return self._data["OperStatusIPv4"]

    @oper_status_ipv4.setter
    def oper_status_ipv4(self, status: str):
        if status in ["Up", "Down"]:
            self._data["OperStatusIPv4"] = status
        else:
            msg = "Unrecognised OperStatusIPv4."
            mod_log.error(msg=msg)
            raise ValueError(msg)

    @property
    def get_labels(self) -> List[str]:
        return list(self._data.keys())

    @property
    def get_status_list(self):
        return list(self._data.values())

    @property
    def json(self) -> dict:
        return self._data

    def __repr__(self):
        return f"<SROSInf: " \
               f"{self.json}>"

    @property
    def pingable(self) -> bool:
        if self._proxy:
            return self._ppingable
        if os.system(f"ping -c 1 {self._data['IPv4Address']} > /dev/null 2>&1") == 0:
            return True
        return False

    @property
    def _ppingable(self) -> bool:
        ping_count = 2
        output = sros_show_ssh_commander(**self._proxy,
                                         commands=[f"ping {self._data['IPv4Address']} interval 1 count {ping_count}"])

        if re.search(f"^{ping_count} packets transmitted, {ping_count} packets received",
                     output[0][1], flags=re.MULTILINE):
            return True
        return False

    @property
    def lldp_neighbor(self):
        if self._data.get("LLDPNeighbor"):
            return self._data["LLDPNeighbor"]
        return None

    @lldp_neighbor.setter
    def lldp_neighbor(self, lldp_nei_sys_name: str):
        self._data["LLDPNeighbor"] = lldp_nei_sys_name


class SROSNode:
    """
    TBD
    """

    def __init__(self, name: str, ip_address: ipaddress.IPv4Address, username: str, *args, **kwargs):
        self._name = None
        self._ip_address = ip_address
        self._username = username
        self._hostname = kwargs.get('hostname')
        self._password = kwargs.get('password')
        self._dev_fs = kwargs.get('dev_fs')
        self._device_type = kwargs.get('device_type')
        self._fabric_proxy = kwargs.get('fabric_proxy')
        self._expected_version = kwargs.get('expected_version')
        self.l3_infs = []
        # TODO: add public key auth cred

    def show_command_parse(self, show_command: str) -> Union[List[str], None]:
        # Execute CLI command against of device.
        output = sros_show_ssh_commander(self.ip_address, self.username, self.password, [show_command])
        mod_log.debug("Raw data from SSH session for '%s' command %s:", show_command, str(output[0][1]))
        inf_res = output[0][1]
        # Apply textfsm template.
        parsed_output = apply_template(f"tfsm/{show_command.replace(' ', '_')}.tfsm", inf_res, False)
        mod_log.debug("Parsed output  for '%s' command %s:", show_command, str(parsed_output))
        if not parsed_output:
            mod_log.error("Failed to recognise software version.")
            raise TFSMParsingError
        return parsed_output

    @property
    def check_expected_version(self) -> Tuple[str]:
        sh_ver_list = self.show_command_parse(SHOW_VER)
        chk = None
        if self._expected_version:
            chk = NO_ALERT if sh_ver_list[0][0].strip() == self._expected_version.strip() else ALERT
            sw_version_control = f"<p> Current verion: {sh_ver_list[0][0]} </p>" \
                                 f"<p> Expected: {self._expected_version.strip()} </p>" \
                                 f"<p style='{color_up_down(chk)}';> IssueFound: {chk}</p>"
            return sw_version_control
        sw_version_control = f"<p> Current verion: {sh_ver_list[0][0]} </p>" \
                             f"<p> Expected: Not provided </p>" \
                             f"<p style='{color_up_down(NO_ALERT)}';> IssueFound: {NO_ALERT}</p>"
        return sw_version_control

    @property
    def hostname(self):
        return self._hostname

    @hostname.setter
    def hostname(self, host: str):
        try:
            resolved_ip = socket.gethostbyname(host)
        except (socket.herror, socket.gaierror) as e:
            mod_log.error("Unable to resolve FQDN: %s", host)
            raise FQDNResolutionError(host + "\n" + str(e))
        if resolved_ip == str(self._ip_address):
            self._hostname = host

    @property
    def ip_address(self):
        return self._ip_address

    @property
    def device_type(self):
        return self._device_type

    @property
    def username(self):
        return self._username

    @property
    def password(self):
        return self._password

    @property
    def json(self):
        return { # TODO: to be reworked to include needed data.
            "ip_address": str(self._ip_address),
            "hostname": self._hostname,
            "username": self.username,
            "password": self.password,
            "dev_fs": self._dev_fs
            #    "device_type": self.device_type
        }

    @property
    def ping_ones(self) -> bool:
        mod_log.debug("Executing ping toward %s", str(self.ip_address))
        if os.system(f"ping -c 1 {self.ip_address} > /dev/null 2>&1") == 0:
            return True
        return False

    @property
    def get_l3_infs_df_state(self) -> Union[pd.DataFrame, None]:
        if not self.l3_infs:
            self.fetch_infs()
            if not self.l3_infs:
                return None
        # Creating numpy array and pd DataFrame
        data = np.array([inf.get_status_list for inf in self.l3_infs])
        return pd.DataFrame(data, columns=self.l3_infs[0].get_labels)

    def fetch_infs(self):
        # Execute CLI command against of device.
        inf_data_list = self.show_command_parse(SHOW_RTR_INF)
        # output = sros_show_ssh_commander(self.ip_address, self.username, self.password, [SHOW_RTR_INF])
        # inf_res = output[0][1]
        # # Apply textfsm template.
        # inf_data_list = apply_template(f"tfsm/{SHOW_RTR_INF.replace(' ', '_')}.tfsm", inf_res, False)
        # Refreshing l3 inf list before populating with updated ones.
        if self.l3_infs:
            self.l3_infs = []
        for inf_data in inf_data_list:
            self.l3_infs.append(SROSInf(inf_data, proxy=self._fabric_proxy))

    def __repr__(self):
        print(self.json)

    def create_running_backup(self) -> bool:
        pass

    def fetch_lldp(self):
        # Execute CLI command against of device to retrieve LLDP neighbours
        lldp_nei_list = self.show_command_parse(SHOW_SYS_LLDP)
        for port, lldp_nei in map(lambda e: (e[0], e[2]), lldp_nei_list):
            inf = [sros_inf for sros_inf in self.l3_infs
                   if port == sros_inf.port.split(':')[0]
                   and sros_inf.port_vlan in ["1", None]]
            if inf:
                inf[0].lldp_neighbor = lldp_nei

    def ntp_status(self):
        # Execute CLI command against of device to retrieve NTP state
        ntp_servers = self.show_command_parse(SHOW_SYS_NTP_SRV)
        if not ntp_servers:
            return f"<p style='{color_up_down(ALERT)}';>NTP service is shutdown.</p>" \
                   f"<p style='{color_up_down(ALERT)}';>IssueFound: {ALERT}</p>"
        reject, chosen = 0, 0
        for ntp_server in ntp_servers:
            if ntp_server[0].strip() == "reject":
                reject += 1
            if ntp_server[0].strip() == "chosen":
                chosen += 1
        if chosen > 0:
            return f"<p style='{color_up_down(NO_ALERT)}';>NTP is synchronized.</p>" \
                   f"<p style='{color_up_down(NO_ALERT)}';>Servers in sync: {chosen}</p>" \
                   f"<p style='{color_up_down('Warn')}';>Servers out of sync: {reject}</p>" \
                   f"<p style='{color_up_down(NO_ALERT)}';>IssueFound: {NO_ALERT}</p>"
        else:
            return f"<p style='{color_up_down(ALERT)}';>NTP is not synchronized.</p>" \
                   f"<p style='{color_up_down(ALERT)}';>Servers out of sync: {reject}</p>" \
                   f"<p style='{color_up_down(ALERT)}';>IssueFound: {ALERT}</p>"


def sros_show_ssh_commander(ip_address: ipaddress.IPv4Address, username: str,
                            password: str, commands: List[str], debug: bool = False, speed_factor: int = 10,
                            host_key_policy_enforce: int = 0) -> Union[List[Tuple], None]:
    """Description...
    :param speed_factor:
    :type host_key_policy_enforce: int
    :type commands: list
    :type username: str
    :type ip_address: ipaddress.IPv4Address
    :type password: str
    """
    ssh_client = paramiko.SSHClient()
    if host_key_policy_enforce == 0:
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    elif host_key_policy_enforce == 1:
        ssh_client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        ssh_client.connect(ip_address.__str__(), username=username, password=password, timeout=30.0)
    except socket.timeout as val_err:
        mod_log.warning('Connection timeout for IP@: %s '
                      '%s', ip_address.__str__(), val_err.__str__())
        return None
    ssh_client_transport = ssh_client.get_transport()
    channel_sh = ssh_client_transport.open_channel(kind='session')
    try:
        channel_sh.invoke_shell()
    except paramiko.ssh_exception.SSHException as e:
        mod_log.warning("Exception raised by failures in SSH2 protocol negotiation or logic errors.")
        return None
    time.sleep(5)
    # Catching greetings
    if channel_sh.recv_ready():
        channel_sh.send('environment no more\n')
        time.sleep(2) # TODO: add speed_factor here
        channel_sh.in_buffer.empty()
    else:
        ssh_client.close()
        mod_log.warning("Unable to get catch initial greetings.")
        return None
    # Iterating over show command list
    seq = 0
    command_results = []
    for command in commands:
        if seq % speed_factor == 0:
            time.sleep(5)
            channel_sh.in_buffer.empty()
        try:
            channel_sh.send(command + '\n')
        except socket.timeout as e:
            if debug:
                print('Socket timout exception!')  # TODO: add node name when refactor to SROSNode
            return None
        # Waiting for output
        time.sleep(2)
        command_output = channel_sh.in_buffer.empty()
        command_results.append((command, bytearray(command_output).decode('ascii')))
        seq += 1
    ssh_client.close()
    return command_results


def sros_ssh_commander_prx(ip_address: ipaddress.IPv4Address, ip_address_prx: ipaddress.IPv4Address,
                           username: str, username_prx: str, password: str, password_prx: str,
                           commands: list, is_config_command: bool = True, stop_on_err: bool = True,
                           stop_on_warn: bool = False, host_key_policy_enforce: object = 0) -> (int, list):
    """Description... TBD
    :type host_key_policy_enforce: int
    :type commands: list
    :type username: str
    :type username_prx: str
    :type ip_address: ipaddress.IPv4Address
    :type ip_address_prx: ipaddress.IPv4Address
    :type password: str
    :type password_prx: str
    :type is_config_command: bool
    :type stop_on_err: bool
    :type stop_on_warn: bool
    """
    result = []
    status = 0
    ssh_client = paramiko.SSHClient()
    if host_key_policy_enforce == 0:
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    elif host_key_policy_enforce == 1:
        ssh_client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        ssh_client.connect(ip_address_prx.__str__(), username=username_prx, password=password_prx, timeout=30.0)
    except socket.timeout as val_err:
        print('Connection timeout for IP@:', ip_address_prx.__str__(), val_err.__str__())
        status = 1
        return status, result
    ssh_client_transport = ssh_client.get_transport()
    channel_sh = ssh_client_transport.open_channel(kind='session')
    channel_sh.invoke_shell()
    time.sleep(5)
    # Catching greetings and setting env no more
    if channel_sh.recv_ready():
        channel_sh.send('environment no more\n')
        time.sleep(5)
        channel_sh.in_buffer.empty()
    # Let's determine system name of proxy box
    channel_sh.send('show system information | match Name' + '\n')
    time.sleep(1)
    command_result = bytearray(channel_sh.in_buffer.empty()).decode('ascii')
    # Parsing result and determining is it ok or not
    try:
        system_name_prx = re.search('\n.*[ ]+:[ ]*([a-zA-Z0-9]+)[ ]*\r\n', command_result).group(1)
    except AttributeError as val_err:
        print('RegEx: Unable to determine system name of proxy box.', val_err)
        ssh_client.close()
        return 2, result
    channel_sh.send('ssh -l ' + username + ' ' + ip_address.__str__() + '\n')
    time.sleep(2)
    ssh_answer = bytearray(channel_sh.in_buffer.empty()).decode('ascii')
    if re.search('No route to destination', ssh_answer):
        print('No route to target box.')
        ssh_client.close()
        status = 3
        return status, result
    if re.search('Are you sure you want to continue connecting \(yes/no\)\?', ssh_answer):
        channel_sh.send('yes\n')
        time.sleep(5)
        ssh_answer = bytearray(channel_sh.in_buffer.empty()).decode('ascii')
    if re.search(username + r'@' + ip_address.__str__() + "'s password:", ssh_answer):
        channel_sh.send(password + '\n')
        time.sleep(10)
        ssh_answer = bytearray(channel_sh.in_buffer.empty()).decode('ascii')
        print(ssh_answer)
        if re.search(username + r'@' + ip_address.__str__() + "'s password:", ssh_answer):
            channel_sh.send(chr(3))
            ssh_client.close()
            status = 4
            return status, result
    else:
        print('No match or non password authentication type is not interactive/password!')
        ssh_client.close()
        status = 5
        return status, result
    channel_sh.send('environment no more\n')
    time.sleep(5)
    channel_sh.in_buffer.empty()
    # Let's determine system name of target box
    channel_sh.send('show system information | match Name' + '\n')
    time.sleep(1)
    ssh_answer = bytearray(channel_sh.in_buffer.empty()).decode('ascii')
    print('Target box system information: ', ssh_answer)
    # Parsing result and determining is it ok or not
    try:
        system_name = re.search('\n.*[ ]+:[ ]*([a-zA-Z0-9]+)[ ]*\r\n', ssh_answer).group(1)
    except AttributeError as val_err:
        print('RegEx: Unable to determine system name of target box.', val_err)
        channel_sh.send('logout\n')
        ssh_client.close()
        return 2, result
    # Target system name of target box
    print(system_name)
    if system_name == system_name_prx:
        print('System names of target box and proxy box match!\nSTOP!\n')
        ssh_client.close()
        return 2, result
    # Starting iteration over list of commands.
    number = 0
    for command in commands:
        if number == 10:
            channel_sh.send('sleep 5\n')
            number = 0
        else:
            channel_sh.send('sleep 1\n')
        time.sleep(1)
        command_result = bytearray(channel_sh.in_buffer.empty()).decode('ascii')
        if not re.search('\n\*(0,1)[AB]:' + system_name + '#[ ]+\r\n]', command_result) and re.search(
                '\n\*(0,1)[AB]:'
                + system_name_prx + '#[ ]+\r\n]', command_result):
            print('Connection to the target box lost. Exiting. Results of executed commands will be returned.\n')
            ssh_client.close()
            result.append((command, 'STOP!'))
            return 6, result
        channel_sh.send(command + '\n')
        time.sleep(5)
        command_result = bytearray(channel_sh.in_buffer.empty()).decode('ascii')
        if not re.search('\n\*(0,1)[AB]:' + system_name + '#[ ]+\r\n]', command_result) and re.search('\n\*(0,1)[AB]:'
                                                                                                      + system_name_prx + '#[ ]+\r\n]',
                                                                                                      command_result):
            print('Connection to the target box lost. Exiting. Results of executed commands will be returned.\n')
            ssh_client.close()
            result.append((command, 'STOP!'))
            return 6, result
        if is_config_command:
            if re.search(r"\nError: Invalid parameter\.", command_result) and stop_on_err:
                command_result = '!EXEC ERROR FOUND - STOP COMMAND EXECUTION! SROS output:\r\n' + command_result
                result.append((command, command_result))
                print(80 * '=')
                print(command_result)
                print(80 * '=')
                return 7, result
            elif re.search('\nINFO: .*\n\*(0,1)[AB]:' + system_name + '#[ ]+\r\n', command_result) and stop_on_warn:
                print('Attention! CLI warming:', command_result)
                result.append((command, command_result))
                print(80 * '=')
                print(command_result)
                print(80 * '=')
                return 7, result
            channel_sh.send('admin save\n')
        # Parsing result and determining is it ok or not
        # CODE
        result.append((command, command_result))
        number += 1
    channel_sh.send('logout\n')
    ssh_client.close()
    return 0, result
