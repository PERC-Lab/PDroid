"""Module for handling privacy-related data in APK and Android"""

# TODO - 
# 2. Create an object that maps the metadata about APIs, Classes, and their associated Information
# 3. Try not to import Androguard objects inside the APK attributes

from androguard.misc import AnalyzeAPK

from pdrolyze.utils import *

class APK():

    def __init__(self, apk, apk_analysis):
        self._a = apk # a
        self._dx = apk_analysis # dx
        self._package_name = apk.get_package()
        self._app_name = apk.get_app_name()
        self._permissions_in_xml = apk.get_permissions()
        self._api_methods = self._extract_api_methods()
        self._picu = self._get_picu()
        self._api_callers = self._extract_api_callers()
        self._api_caller_callers = self._extract_api_caller_callers()
    
    def get_permissions_in_xml(self):
        return self._permissions_in_xml

    def get_package_name(self):
        return self._package_name

    def get_app_name(self):
        return self._app_name
    
    def _extract_api_methods(self):
        """Extract all the API methods declared in the apk"""

        api_methods = []
        all_methods = dict([(x.method.name, x) for x in self._dx.methods.values() ]) # TODO Optimize this
        for each_method in get_api_methods():
            try:
                method_analysis_object = PrivacyCode(all_methods[each_method])
                api_methods.append(method_analysis_object)
            except KeyError:
                pass
        
        return api_methods
    
    def _extract_api_callers(self):
        """Extract methods that call the API methos in the apk"""
        api_callers = {}

        for privacy_meth in self._api_methods:
            for _, call, _ in privacy_meth._method_analysis_object.get_xref_from():
                caller = PrivacyCode(call)
                if caller not in api_callers:
                    api_callers[caller] = ""

        return [x for x in api_callers.keys()]
    
    def _extract_api_caller_callers(self):
        """Extract methods that call API Callers"""
        api_caller_callers = {}

        for each_meth in self._api_callers:
            for _, call, _ in each_meth._method_analysis_object.get_xref_from():
                caller = PrivacyCode(call)
                if caller not in api_caller_callers:
                    api_caller_callers[caller] = ""
                
                
        return [x for x in api_caller_callers.keys()]
    
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
        print(len(api_callers))

        return attribute_dictionary


    def __str__(self):
        return f"{self.get_package_name()};{self.get_app_name()}"

    def __repr__(self):
        return f"<prdolyze.APK {self.__str__()}>"
        

class PrivacyCode:
    """A wrapper class for `androguard.core.analysis.MethodAnalysis`"""

    def __init__(self, method_analysis_object):
        self._method_analysis_object = method_analysis_object
        self._method_name = self._method_analysis_object.method.name
        self._class_name = self._method_analysis_object.class_name.replace("L", "").replace(";", "")


    def get_ag_method_name(self):
        return
    
    def get_method_name(self):
        return self._method_name

    def get_ag_class_name(self):
        return "L" + self.get_class_name() + ";"
    
    def is_method_analysis_object_external(self):
        return self._method_analysis_object.is_external()

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
            json_obj["source_code"] = str(self.get_source_code())
        
        return json_obj

    def __str__(self):
        return f"{self.get_class_name()}->{self.get_method_name()};{self._method_analysis_object.descriptor}"
    
    def __repr__(self):
        return f"<pdrolyze.PrivacyCode {self.__str__()}"
