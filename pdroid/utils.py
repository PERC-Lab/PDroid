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

    list_of_mappings = json.load(open(path.join(CWD, "pdroid", "api_methods.json"), 'r'))
    for each_class_to_pi_mapping in list_of_mappings:
        for each_api_to_pi_mapping in each_class_to_pi_mapping.keys():
            api_list.append(each_api_to_pi_mapping.split(';')[-1])
    
    return api_list

def map_api_to_pi(method_name):
    """Maps API method to the personal information being collected"""
    method_to_pi = json.load(open(path.join(CWD, "pdroid", "method_to_pi.json"), 'r'))
    return method_to_pi[method_name]

def print_src_code(src_code):
    src_code_split = src_code.split('\n')

    for each_part in src_code_split:
        print(each_part)

def get_api(id):
    """Given the id of the api, this method finds the API and returns as a dictionary"""
    json_path = path.join(CWD, "pdroid", "api_metadata_w_description.json")

    with open(json_path, 'r') as json_file:
        json_dict = json.load(json_file)
        try:
            return json_dict[id]
        except KeyError:
            return None
