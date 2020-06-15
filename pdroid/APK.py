"""Module for handling privacy-related methods and data in Android APK"""

import json
import os
from os import path

from androguard.misc import AnalyzeAPK

CWD = os.getcwd()
METADATA_DIR = path.join(CWD, "metadata")
METADATA = path.join(METADATA_DIR, "api_metadata.json")

class APK():

    def __init__(self, apk, apk_analysis):
        self._package_name = apk.get_package()
        self._app_name = apk.get_app_name()
        self._permissions_in_xml = apk.get_permissions()
        self._api_methods = self._extract_api_methods(apk_analysis)
        self._picu = self.get_picu()
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
                    api_methods.append(PrivacyAPI(each_method, api_metadata))
                except KeyError:
                    pass

        return api_methods
       
    def _extract_callers(self, list_of_methods):
        """Returns a list of methods that call methods in `list_of_methods`"""
        callers = {}

        for each_meth in list_of_methods:
            for _, call, _ in each_meth._method_analysis_object.get_xref_from():
                caller = PrivacyMethod(call, each_meth)
                if caller not in callers:
                    callers[caller] = ""
        
        return [x for x in callers.keys()]

    def get_picu(self):
        """Return list of personal information collected/used (picu) by all methods"""
        picu = []

        for each_api_method in self._api_methods:
            picu.extend(each_api_method.get_personal_information_collected())

        return list(set(picu))
    
    def export(self):
        attribute_dictionary = dict([
            ("app_id", str(self.get_package_name())),
            ("title", str(self.get_app_name())),
            ("permissions_in_xml", [str(x) for x in self.get_permissions_in_xml()]),
            ("personal_information_processed", self.get_picu())
        ])

        # api_callers = []
        # for each_api_caller in self._api_callers:
        #     if not each_api_caller.is_method_analysis_object_external():
        #         api_callers.append(each_api_caller.export())
        # attribute_dictionary["api_callers"] = api_callers

        # api_caller_callers = []
        # for each_api_double_caller in self._api_caller_callers:
        #     if not each_api_double_caller.is_method_analysis_object_external():
        #         api_caller_callers.append(each_api_double_caller.export())
        # attribute_dictionary["api_double_callers"] = api_caller_callers

        return attribute_dictionary


    def __str__(self):
        return f"{self.get_package_name()};{self.get_app_name()}"

    def __repr__(self):
        return f"<pdroid.APK {self.__str__()}>"
        

class AbstractPrivacyMethod:

    def __init__(self, method_analysis_object):
        self._method_analysis_object = method_analysis_object
        self._class_name = self._method_analysis_object.class_name.replace("/", ".")[1:]
        self._method_name = self._method_analysis_object.method.name
        self._id = self._class_name + self._method_name
    
    def get_class_name(self):
        return self._class_name
    
    def get_method_name(self):
        return self._method_name
    
    def get_id(self):
        return self._id
    
    def is_method_analysis_object_external(self):
        return self._method_analysis_object.is_external()

    def export(self):
        attribute_dictionary = dict([
            ("id", self.get_id()),
            ("class_name", self.get_class_name()),
            ("method_name", self.get_method_name())
        ])
        return attribute_dictionary

class PrivacyAPI(AbstractPrivacyMethod):

    def __init__(self, method_analysis_object, json_object):
        super().__init__(method_analysis_object)
        self.permissions_required = json_object['permissions_required']
        self.personal_information_collected = json_object['personal_information_collected']
        self.api_description = json_object['api_description']
    
    def get_permissions_required(self):
        return self.permissions_required
    
    def get_personal_information_collected(self):
        return self.personal_information_collected
    
    def get_api_description(self):
        return self.api_description
    
    def export(self):
        attribute_dictionary = super().export()
        attr_dict = dict([
            ("personal_information_collected", self.get_personal_information_collected()),
            ("permissions_required", self.get_permissions_required()),
            ("api_description", self.get_api_description())
        ])
        attribute_dictionary.update(attr_dict)
    
        return attribute_dictionary
    
    def __str__(self):
        return f"{self.get_id()}"

    def __repr__(self):
        return f"<pdroid.APK.PrivacyAPI {self.__str__()}"

class PrivacyMethod(AbstractPrivacyMethod):

    def __init__(self, caller, api):
        super().__init__(caller)
        self._id = self._class_name + self._method_name + self._method_analysis_object.descriptor
        self._permissions_required = api.get_permissions_required()
        self._personal_information_collected = api.get_personal_information_collected()
        self._api_related_to = api
    
    def get_permissions_required(self):
        return self._permissions_required
    
    def get_personal_information_collected(self):
        return self._personal_information_collected
    
    def get_related_api(self):
        return self._api_related_to

    def get_caller_methods(self):
        """Returns a list of methods that call this method"""
        callers = []
        
        for _, call, _ in self._method_analysis_object.get_xref_from():
            caller = PrivacyMethod(call, self.get_related_api())
            if caller not in callers:
                callers.append(caller)

        return callers

    def get_source_code(self):
        """Returns the source code of the method. It is 
        callers responsibility to ensure that the 
        `PrivacyMethod._method_analysis_object.method` is not 
        of type `androguard.analysis.analysis.External`"""
        return self._method_analysis_object.get_method().get_source()
    
    def export(self, include_src_code=True):
        attribute_dictionary = super().__export()
        attr_dict = dict([
            ("id", self.get_id()),
            ("personal_information_collected", self.get_personal_information_collected()),
            ("permissions_required", self.get_permissions_required()),
        ])
        
        if include_src_code:
            try:
                attr_dict["source_code"] = str(self.get_source_code())
            except Exception:
                attr_dict["source_code"] = "N/A"
            
        attribute_dictionary.update(attr_dict)

        return attribute_dictionary

    def __str__(self):
        return f"{self.get_id()}"
    
    def __repr__(self):
        return f"<pdroid.APK.PrivacyCode {self.__str__()}>"
