"""Module to represent privacy attributes of an Android APK"""

# TODO - 
# 1. Create an object that helps translating the name conventions
# 2. Create an object that maps the metadata about APIs, Classes, and their associated Information
# 3. Try not to import Androguard objects insie the APK attributes
# 4. 
from androguard.misc import AnalyzeAPK

from pdrolyze.utils import *

class APK():

    def __init__(self, apk, apk_analysis):
        self._a = apk # a
        self._dx = apk_analysis # dx
        self._name = self._get_package_name()
        self._permission_in_xml = self._get_permissions()
        self._api_methods = self._get_api_methods()
        self._picu = self._get_picu()
    
    def _get_permissions(self):
        return self._a.get_permissions()

    def _get_package_name(self):
        return self._a.get_package()

    def _get_app_name(self):
        return self._a.get_app_name()
    
    def _get_api_methods(self):

        api_methods = []
        all_methods = dict([(x.method.name, "") for x in self._dx.methods.values() ]) # TODO Optimize this
        for each_method in get_api_methods():
            try:
                all_methods[each_method]
                api_methods.append(each_method)
            except KeyError:
                pass
        
        return api_methods
    
    def _get_picu(self):
        """Return list of personal information collected/used (picu) by application"""
        picu = []

        for each_api_method in self._api_methods:
            personal_information = map_api_to_pi(each_api_method)
            if personal_information not in picu:
                picu.append(personal_information)

        return picu

    def __str__(self):
        return "{};{}".format(self._get_package_name(), self._get_app_name())

    def __repr__(self):
        return "<prdolyze.APK {}>".format(self.__str__())
        
