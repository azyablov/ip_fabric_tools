#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import os
import textfsm
import jinja2
import logging
from pprint import pprint
from typing import Union, Dict


# ==== Resource variables and matching patterns ====
ALERT = "Alert!"
NO_ALERT = "------"


def load_json_data(file_name: str) -> Dict:
    """
    The function facilitates parameters load from JSON file
    :param file_name:
    :return: dictionary
    """
    # Reading JSON file
    path_input_file: Union[bytes, str] = os.path.abspath(file_name)
    if os.path.exists(path_input_file) and os.access(path_input_file, os.R_OK):
        with open(path_input_file, mode='r', encoding='utf-8') as input_config_file:
            try:
                data = json.load(input_config_file)
            except json.JSONDecodeError as de:
                print(f'JSON format decode error.'
                      f'{de}')
                raise
        return data
    else:
        print("Can't access file {}".format(file_name))
        msg = "Please provide valid file name and/or path."
        raise ValueError(msg)


def apply_template(template: str, cli_output: str, debug: bool = False) -> Union[list, None]:
    path_to_template_file = os.path.abspath(template)
    if os.path.exists(path_to_template_file) and os.access(path_to_template_file, os.R_OK):
        with open(path_to_template_file, mode='r', encoding='utf-8') as tfh:
            re_table = textfsm.TextFSM(tfh)
            cli_data = re_table.ParseText(cli_output)
            if debug:
                print(cli_data)
            return cli_data
    else:
        msg = f"Incorrect template file name: {path_to_template_file}"
        raise ValueError(msg)
    return None


def load_j2_env(path_to_templ: str = './templates') -> jinja2.Environment:
    """
    The function is loading j2 env
    :type path_to_templ: str
    :param path_to_templ: directory with j2 templates
    :return: j2 environment
    """
    if os.path.exists(path_to_templ) and os.access(path_to_templ, os.R_OK):
        temp_env = jinja2.Environment(loader=jinja2.FileSystemLoader(path_to_templ, followlinks=True),
                                      undefined=jinja2.StrictUndefined)
        return temp_env


def color_up_down(val):
    if isinstance(val, bool):
        val = str(val)
    if not val:
        val = str(val)
    if val.strip() in ["Up", "True", NO_ALERT, "OK"]:
        color = 'green'
    elif val.strip() in ["Down", "False", ALERT, "NOK"]:
        color = 'red'
    elif val.strip() in ["Warn"]:
        color = 'orange'
    elif val in ["None"]:
        color = 'black'
    else:
        color = 'blue'
    return f'color: {color}'


def enable_logging(name: str, log_file: str, level=logging.WARNING) -> logging.Logger:
    log_fmt = "[{asctime} {levelname:<8} [{name}:{filename:<10}:{lineno}] {message}"
    date_fmt = "%d/%m/%Y %H:%M:%S"
    log: logging.Logger = logging.getLogger(name)
    log.setLevel(level)
    formatter = logging.Formatter(fmt=log_fmt, datefmt=date_fmt, style='{')
    fh = logging.FileHandler(filename=f"./log/{log_file}", encoding='utf-8')
    fh.setLevel(level=level)
    fh.setFormatter(formatter)
    log.addHandler(fh)
    return log
