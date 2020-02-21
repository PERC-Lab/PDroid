"""Module to analyze the  apk file"""

import os
from os import path

from androguard.misc import AnalyzeAPK
from androguard.cli.main import plot

import networkx as nx

import json

CWD = os.getcwd()

"""
1. Get Permission
2. From permission get the class
3. Convert class to Androguard class name
4. Get the list of methods that are being called
5. 

"""

def get_api_classes(list_of_permissions):
    """Returns class that require the given permission
    
    Parameters
    ----------
    list_of_permissions : list
        Android permissions listed in manifest.xml
    """
    clipped_permissions = [x.split(".")[-1] for x in list_of_permissions]

    permission_to_class = json.load(open(path.join(CWD, "pdrolyze", "permission_class_mapping.json"), "r"))
    api_classes = []
    
    for each_permission in clipped_permissions:
        try:
            api_classes.append(permission_to_class[each_permission])
        except KeyError:
            pass
    
    print("API Classes Used Are...")
    
    print(api_classes)

    api_classes = ["L" + x.replace(".", "/") + ";" for x in api_classes]
    return api_classes

def analyze(apk_file, analysis_loc):
    a, d, dx = AnalyzeAPK(apk_file)

    permission_list = a.get_permissions()

    list_of_classes = get_api_classes(permission_list)

    #Get the classes from Androguard.
    api_classes = []
    api_methods = [] #List of lists

    for each_api_class in list_of_classes:
        try:
            api_class = dx.classes[each_api_class]
            api_methods.append(api_class.get_methods())
            api_classes.append(api_class)

        except KeyError:
            pass
    

    num_classes = len(api_methods)
    flat_api_methods = [item for each_list in api_methods for item in each_list]

    # Calling classes
    calling_classes = []
    class_and_methods = []
    #(api_method, calling_class)


    for meth in flat_api_methods:
        for _, call, _ in meth.get_xref_from():
            calling_class = dx.classes[call.class_name]
            api_calling_class_pair = (meth.class_name, calling_class.name)
            api_cls_calling_meth_pair = (meth.name, calling_class.name)
            if api_calling_class_pair not in calling_classes:
                calling_classes.append(api_calling_class_pair)
            if api_cls_calling_meth_pair not in class_and_methods:
                class_and_methods.append(api_cls_calling_meth_pair)

    print("Following are the API and calling class pairs")
    print(calling_classes)

    for each_pair in class_and_methods:
        file_name = each_pair[0] + "_" + each_pair[1].split("/")[-1]
        call_graph = dx.get_call_graph(classname=each_pair[1], methodname=each_pair[0])
        filename = str(file_name + '.gml')
        file_path = path.join(str(analysis_loc), filename)
        nx.write_gml(call_graph, file_path)

    print("Following are the API class and methods calling pairs")
    print(class_and_methods)


def create_fs(location, name):
    """Takes in a pair and creates a folder for each pair in the given location"""
    
    os.makedirs(path.join(location, name))

    
    
PATH = path.join(CWD, "../TEST/")

print("Here")
file = "/home/vijayantajain/VJ/code/research/Phase 1/PDroLyze/ae.gov.dha.dha.dha-12.apk"   
analyze(file, PATH)


