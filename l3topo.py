#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import ipaddress
import sroslib
from pprint import pprint
from helpers import load_json_data, load_j2_env, color_up_down, enable_logging, ALERT, NO_ALERT
import argparse
import pandas as pd
import numpy as np
import logging
import json


def main(debug: bool = False) -> int:
    """
    :param debug: Set to True to enable debug
    :return:
    """
    # Parsing arguments
    arg_desc = sys.argv[0] + ' script taking file in JSON as input and apply configuration'
    parser = argparse.ArgumentParser(description=arg_desc)
    parser.add_argument('-n', help='JSON formatted file with node connectivity params', action='store',
                        required=True)
    parser.add_argument('--log', help='set logging level', action='store', required=False)
    args = parser.parse_args()
    if args.log.upper() in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
        user_level = getattr(logging, args.log.upper())
    else:
        user_level = logging.WARNING
    pprint(user_level)
    # TODO: extend with capability to load several configuration params data files
    node_data = load_json_data(args.n)
    logger = enable_logging(name="l3topo", log_file="l3topo.log", level=user_level)
    logger.debug("%s", "=" * 20 + " Node connectivity data " + "=" * 20)
    logger.debug(msg=json.dumps(node_data))

    # Check for proxy object presence
    fabric_proxy = None
    if node_data.get('fabric_proxy'):
        fabric_proxy = node_data.pop('fabric_proxy')
        # TODO: add checking for proxy attrs
        fp_ip = sroslib.extract_ipaddr(fabric_proxy["ip_address"])
        if fp_ip:
            fabric_proxy["ip_address"] = sroslib.extract_ipaddr(fabric_proxy["ip_address"])
            logger.debug("Fabric proxy configuration set: %s", fabric_proxy)
        else:
            fabric_proxy = None

    sros_node_obj = {}
    for k, v in node_data.items():
        ip = sroslib.extract_ipaddr(node_data[k]["ip_address"])
        if ip:
            node_data[k]["ip_address"] = ip
            if node_data[k].get("proxy"):
                if not fabric_proxy:
                    msg = "Proxy enabled, but proxy object is not correct or not specified."
                    raise ValueError(msg)
                node_data[k].pop("proxy")
                node_data[k]["fabric_proxy"] = fabric_proxy
            sros_node_obj[k] = sroslib.SROSNode(k, **node_data[k])
        else:
            msg = f"Node {k} IP@ is not correct. Please provide correct one."
            raise ValueError(msg)

    sros_ordered_list = list(sros_node_obj.keys())

    # Availability checking common DataFrame creation
    ping_res = []
    for node in sros_ordered_list:
        print(f"Checking {node} availability ....")
        ping_res.append([sros_node_obj[node].ping_ones for i in range(3)])

    for n, ping in enumerate(ping_res):
        if any(ping):
            ping.append(NO_ALERT)
        else:
            ping.append(ALERT)
            # Removing not available elements for further processing
            sros_ordered_list.pop(n)
    data = np.array(ping_res)
    df_ping = pd.DataFrame(data, columns=["TRY#1", "TRY#2", "TRY#3", "IssueFound"], index=sros_ordered_list)
    st_ping = df_ping.style.applymap(color_up_down)
    exit(0)
    for node in sros_ordered_list:
        # Software version check
        print(f"Checking {node} software version ....")
        sw_version_control = sros_node_obj[node].check_expected_version

        # NTP status check
        print(f"Checking {node} NTP status ....")
        ntp_status = sros_node_obj[node].ntp_status()

        # Interface status check
        print(f"Fetching {node} interface status ....")
        sros_node_obj[node].fetch_infs()

        # Retrieving LLDP neighbors
        print(f"Fetching {node} LLDP neighbors ....")
        sros_node_obj[node].fetch_lldp()

        df_inf_state: pd.DataFrame = sros_node_obj[node].get_l3_infs_df_state
        st_inf_state = df_inf_state.style.applymap(color_up_down)

        # Template handling
        env = load_j2_env(path_to_templ='j2/')
        # TODO: l2 templates directory to be taken from params
        template = env.get_template('l3topo.html')
        html = template.render(node=node, ping_table=st_ping.render(), infs_table=st_inf_state.render(),
                               sw_version_control=sw_version_control, ntp_status=ntp_status)

        # Write the HTML file
        with open(f'reports/{node}.html', mode='w') as fh: # TODO: report directory to be provided as parameter
            fh.write(html)

    return 0


if __name__ == '__main__' and not main(True):
    """
    Script entry point.
    """
    exit(0)
