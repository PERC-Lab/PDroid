"""Utility functions"""

import os
from os import path

import json

CWD = os.getcwd()

def get_ag_method_name_str():
    return

def get_reg_method_name():
    return

def get_ag_class_name():
    return

def get_reg_class_name():
    return

def get_api_methods():
    method_list = []

    method_to_pi = json.load(open(path.join(CWD, "pdrolyze", "api_methods.json"), 'r'))
    return [x.split(';')[-1] for x in method_to_pi.keys()]

def map_api_to_pi(method_name):
    method_to_pi = json.load(open(path.join(CWD, "pdrolyze", "method_to_pi.json"), 'r'))
    return method_to_pi[method_name]



