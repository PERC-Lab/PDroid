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
    api_list = []

    list_of_mappings = json.load(open(path.join(CWD, "pdrolyze", "api_methods.json"), 'r'))
    for each_class_to_pi_mapping in list_of_mappings:
        for each_api_to_pi_mapping in each_class_to_pi_mapping.keys():
            api_list.append(each_api_to_pi_mapping.split(';')[-1])
    
    return api_list

def map_api_to_pi(method_name):
    """Maps API method to the personal information being collected"""
    method_to_pi = json.load(open(path.join(CWD, "pdrolyze", "method_to_pi.json"), 'r'))
    return method_to_pi[method_name]



