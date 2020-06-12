"""Module for handling privacy-related data in APK and Android"""

import json
import os
from os import path

from androguard.misc import AnalyzeAPK

from pdroid.utils import (get_api, map_api_to_pi, print_src_code)

CWD = os.getcwd()
PDROID = path.join(CWD, "pdroid")
METADATA = path.join(PDROID, "api_metadata_w_description.json")

class APK():

    def __init__(self, apk, apk_analysis):
        self._package_name = apk.get_package()
        self._app_name = apk.get_app_name()
        self._permissions_in_xml = apk.get_permissions()
        self._api_methods = self._extract_api_methods(apk_analysis)
        self._picu = self._get_picu()
        self._api_callers = self._extract_callers(self._api_methods)
        self._api_caller_callers = self._extract_callers(self._api_callers)
    
    def get_permissions_in_xml(self):
        return self._permissions_in_xml

    def get_package_name(self):
        return self._package_name

    def get_app_name(self):
        return self._app_name
    
    def _extract_api_methods(self, apk_analysis):
        """Extract all the API methods declared in the apk"""

        api_methods = []
        get_method_id = lambda x: x.class_name[1:].replace("/", ".") + x.name
        assert path.exists(METADATA), f"The file {METADATA} does not exist"
        
        with open(METADATA, 'r') as metadata_file:
            metadata = json.load(metadata_file)

            for each_method in apk_analysis.methods.values():
                method_id = get_method_id(each_method)
                try:
                    api_metadata = metadata[method_id]
                    api_methods.append(PrivacyCode(each_method, is_android_api=True))
                except KeyError:
                    pass

        return api_methods
       
    def _extract_callers(self, list_of_methods):
        """Returns a list of methods that call methods in `list_of_methods`"""
        callers = {}

        for each_meth in list_of_methods:
            for _, call, _ in each_meth._method_analysis_object.get_xref_from():
                caller = PrivacyCode(call)
                if caller not in callers:
                    callers[caller] = ""
        
        return [x for x in callers.keys()]
    
    def _get_picu(self):
        """Return list of personal information collected/used (picu) by application"""
        picu = []

        for each_api_method in self._api_methods:
            personal_information = map_api_to_pi(each_api_method.get_method_name())
            if personal_information not in picu:
                picu.append(personal_information)

        return picu
    
    def export(self):
        attribute_dictionary = dict([
            ("app_id", str(self.get_package_name())),
            ("title", str(self.get_app_name())),
            ("permissions_in_xml", [str(x) for x in self.get_permissions_in_xml()]),
        ])

        api_callers = []
        for each_api_caller in self._api_callers:
            if not each_api_caller.is_method_analysis_object_external():
                api_callers.append(each_api_caller.export())
        attribute_dictionary["api_callers"] = api_callers

        api_caller_callers = []
        for each_api_double_caller in self._api_caller_callers:
            if not each_api_double_caller.is_method_analysis_object_external():
                api_caller_callers.append(each_api_double_caller.export())
        attribute_dictionary["api_double_callers"] = api_caller_callers

        return attribute_dictionary


    def __str__(self):
        return f"{self.get_package_name()};{self.get_app_name()}"

    def __repr__(self):
        return f"<pdroid.APK {self.__str__()}>"
        

class PrivacyCode:
    """A wrapper class for `androguard.core.analysis.MethodAnalysis`"""

    def __init__(self, method_analysis_object, is_android_api=False):
        self._method_analysis_object = method_analysis_object
        self._class_name = self._method_analysis_object.class_name.replace("/", ".")[1:]
        self._method_name = self._method_analysis_object.method.name
        self._id = self._class_name + self._method_name
        if is_android_api:
            api_metadata = get_api(self._id)
            if api_metadata is not None:
                self.permissions_required = api_metadata['permissions_required']
                self.personal_information_collected = api_metadata['personal_information_collected']
                self.is_android_api = True
                self.api_description = api_metadata['api_description']

    def get_method_name(self):
        return self._method_name
    
    def get_class_name(self):
        return self._class_name
    
    def get_id(self):
        return self._id

    def get_ag_class_name(self):
        return "L" + self.get_class_name().replace(".", "/") + ";"
    
    def is_method_analysis_object_external(self):
        return self._method_analysis_object.is_external()
    
    def get_caller_methods(self):
        """Returns a list of methods that call this method"""
        callers = []
        
        for _, call, _ in self._method_analysis_object.get_xref_from():
            caller = PrivacyCode(call)
            if caller not in callers:
                callers.append(caller)

        return callers
    
    def get_caller_method_src_codes(self, caller_method):
        """Returns the caller_method's source_code"""

        if not caller_method.is_method_analysis_object_external():
            src_code = caller_method.get_source_code()
        else:
            src_code = "N/A"
        
        return src_code

    def get_source_code(self):
        """Returns the source code of the method. It is 
        callers responsibility to ensure that the 
        `PrivacyMethod._method_analysis_object.method` is not 
        of type `androguard.analysis.analysis.External`"""
        self._source_code = self._method_analysis_object.get_method().get_source()
        return self._source_code

    def get_class_name(self):
        return self._class_name
    
    def export(self, include_src_code=True):
        json_obj = dict([
                        ("id", self.__str__()),
                        ("class_name", str(self.get_class_name())),
                        ("method_name", str(self.get_method_name()))
                        ])
        
        if include_src_code:
            try:
                json_obj["source_code"] = str(self.get_source_code())
            except Exception:
                json_obj["source_code"] = "N/A"

        return json_obj

    def __str__(self):
        return f"{self.get_class_name()}->{self.get_method_name()};{self._method_analysis_object.descriptor}"
    
    def __repr__(self):
        return f"<pdroid.PrivacyCode {self.__str__()}>"
