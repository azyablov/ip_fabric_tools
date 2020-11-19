import re
import ipaddress
import paramiko
import time
import socket

# ==== Resource variables and matching patterns
IP_ADDR_SEARCH_PATTERN = r'[^0-9]*([0-9]{1,3})\.([0-9]+)\.([0-9]+)\.([0-9]{1,3})[^0-9]*'


# ==== Function definitions
def extract_ipaddr(ip_addr_str: str, ip_addr_list: list) -> int:
    """Function parses ip_addr_str and extract all possible IP@.
    Returns status of conversion;
                                0 = OK
                                1 = IP@ exists but not valid
                                2 = IP@ does not identified
    ip_addr_list contains list of IPv4Address objects.
    :type ip_addr_str: str, ip_addr_list: list
    """
    result = 2
    ip_addr_oct_list = ip_addr_str.split(sep='.')
    if ip_addr_oct_list.__len__() < 4:
        return False
    ip_addr_tuples = re.findall(IP_ADDR_SEARCH_PATTERN, ip_addr_str)
    print(ip_addr_tuples)
    if ip_addr_tuples is None:
        return result
    for ip_addr_tuple in ip_addr_tuples:
        print('IP@:', list(ip_addr_tuple))
        ip_str = '.'.join(ip_addr_tuple)
        try:
            ip_addr_obj = ipaddress.ip_address(ip_str)

        except ValueError as val_err:
            print('Provided string is not valid IP@:', ip_str, val_err.__str__())
            continue
        ip_addr_list.append(ip_addr_obj)
        print(ip_addr_list)
    if ip_addr_list.__len__() == 0:
        result = 1
        return result
    result = 0
    return result


def sros_show_ssh_commander(ip_address: ipaddress.IPv4Address, username: str,
                            password: str, commands: list, host_key_policy_enforce: int = 0) -> list:
    """Description...
    :type host_key_policy_enforce: int
    :type commands: list
    :type username: str
    :type ip_address: ipaddress.IPv4Address
    :type password: str
    """
    result = []
    ssh_client = paramiko.SSHClient()
    if host_key_policy_enforce == 0:
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    elif host_key_policy_enforce == 1:
        ssh_client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        ssh_client.connect(ip_address.__str__(), username=username, password=password, timeout=30.0)
    except socket.timeout as val_err:
        print('Connection timeout for IP@:', ip_address.__str__(), val_err.__str__())
        return result
    ssh_client_transport = ssh_client.get_transport()
    channel_sh = ssh_client_transport.open_channel(kind='session')
    channel_sh.invoke_shell()
    time.sleep(5)
    # Catching greetings
    if channel_sh.recv_ready():
        channel_sh.send('environment no more\n')
        print(channel_sh.in_buffer.empty())
    # Interating over show command list
    number = 0
    for command in commands:
        if number == 10:
            channel_sh.send('sleep 5\n')
            number = 0
        channel_sh.send(command + '\n')
        time.sleep(1)
        command_result = channel_sh.in_buffer.empty()
        # Parsing result and determining is it ok or not
        # CODE
        result.append((command, bytearray(command_result).decode('ascii')))
        number += 1
    ssh_client.close()
    return result

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
        if not re.search('\n\*(0,1)[AB]:' + system_name +'#[ ]+\r\n]', command_result) and re.search('\n\*(0,1)[AB]:'
                        + system_name_prx + '#[ ]+\r\n]', command_result):
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



def sros_get_inf_table(ip_address: ipaddress.IPv4Address, username: str, password: str,
                       host_key_policy_enforce: int = 0, commands: list = ['show router interface'],
                       search_pattern: str = r'^(.+?)[ ]+(Up|Down).+[ ](.+?)$') -> list:
    """Description... commands contain 'show router interface'
    :type host_key_policy_enforce: int
    :type commands: list
    :type username: str
    :type ip_address: ipaddress.IPv4Address
    :type password: str
    :type search_pattern: str
    """
    inf_table = []
    show_com_results = sros_show_ssh_commander(ip_address, username, password, commands,
                                                     host_key_policy_enforce)
    for (command, result) in show_com_results:
        # Check point 1
        print('Results of execution:', command, '\n', result)
        for line in result.splitlines():
            inf_name = re.search(search_pattern, line)
            if inf_name:
                inf_table.append(inf_name.groups(0))
    inf_table_orig = inf_table[:]
    try:
        inf_table.remove(('system', 'Up', 'system'))
    except ValueError as var_err:
        try:
            inf_table.remove(('system', 'Down', 'system'))
        except ValueError as var_err:
            print('No system interface found, please check SROS for changes in CLI or CLI output.\n', var_err)
            return []
    return [(inf_name, inf_state, inf_port) for (inf_name, inf_state, inf_port)
            in inf_table_orig if not inf_name == 'system']

def sros_get_inf_table_prx(ip_address: ipaddress.IPv4Address, ip_address_prx: ipaddress.IPv4Address,
                           username: str, username_prx: str, password: str, password_prx: str,
                           host_key_policy_enforce: int = 0, commands: list = ['show router interface'],
                           search_pattern: str = r'^(.+?)[ ]+(Up|Down).+[ ](.+?)$') -> list:


    """Description... commands contain 'show router interface'
    :type host_key_policy_enforce: int
    :type commands: list
    :type username: str
    :type ip_address: ipaddress.IPv4Address
    :type password: str
    :type search_pattern: str
    :type ip_address_prx: ipaddress.IPvAddress
    :type username_prx: str
    :type password_prx: str
    """
    inf_table = []
    show_com_results = sros_ssh_commander_prx(ip_address, ip_address_prx, username, username_prx,
                                              password, password_prx, commands, host_key_policy_enforce)
    show_com_results = show_com_results[1]
    for (command, result) in show_com_results:
        # Check point 1
        print('Results of execution:', command, '\n', result)
        for line in result.splitlines():
            inf_name = re.search(search_pattern, line)
            if inf_name:
                inf_table.append(inf_name.groups(0))
    inf_table_orig = inf_table[:]
    try:
        inf_table.remove(('system', 'Up', 'system'))
    except ValueError as var_err:
        print('System interface is down.', var_err)
        try:
            inf_table.remove(('system', 'Down', 'system'))
        except ValueError as var_err:
            print('No system interface found, please check SROS for changes in CLI or CLI output.\n', var_err)
            return []
    return [(inf_name, inf_state, inf_port) for (inf_name, inf_state, inf_port)
            in inf_table_orig if not inf_name == 'system']


def sros_show_config_commander(ip_address: ipaddress.IPv4Address, username: str,
                               password: str, commands: list, stop_on_warning: bool = True,
                               stop_on_err: bool = True, host_key_policy_enforce: int = 0) -> list:
    """Description...
    :type host_key_policy_enforce: int
    :type commands: list
    :type username: str
    :type ip_address: ipaddress.IPv4Address
    :type password: str
    :type stop_on_err: bool
    """
    result = []
    ssh_client = paramiko.SSHClient()
    if host_key_policy_enforce == 0:
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    elif host_key_policy_enforce == 1:
        ssh_client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        ssh_client.connect(ip_address.__str__(), username=username, password=password, timeout=30.0)
    except socket.timeout as val_err:
        print('Connection timeout for IP@:', ip_address.__str__(), val_err.__str__())
        return result
    ssh_client_transport = ssh_client.get_transport()
    channel_sh = ssh_client_transport.open_channel(kind='session')
    channel_sh.invoke_shell()
    time.sleep(3)
    # Catching greetings
    if channel_sh.recv_ready():
        time.sleep(3)
        channel_sh.in_buffer.empty()
    # Interating over configuration command list
    for command in commands:
        channel_sh.send(command + '\n')
        time.sleep(1)
        command_result = channel_sh.in_buffer.empty()
        # Parsing result and determining is it ok or not
        command_result = bytearray(command_result).decode('ascii')
        if re.search(r"\nError: Invalid parameter\.", command_result) and stop_on_err:
            command_result = '!EXEC ERROR FOUND - STOP COMMAND EXECUTION! SROS output:\r\n' + command_result
            result.append((command, command_result))
            print(80 * '=')
            print(command_result)
            print(80 * '=')
            return result
        elif re.search(r"\nError: Invalid parameter\.", command_result) and stop_on_warning:
            pass
        result.append((command, command_result))
    ssh_client.close()
    return result

