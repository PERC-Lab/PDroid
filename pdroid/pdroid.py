"""Module for handling privacy-related methods and data in Android APK"""

import json
import re
import os
from os import path

from androguard.misc import AnalyzeAPK

from androguard.core.mutf8 import MUTF8String

CWD = os.getcwd()
METADATA_DIR = path.join(CWD, "metadata")
METADATA = path.join(METADATA_DIR, "api_metadata.json")


class APK:
    def __init__(self, apk, apk_analysis):
        self._package_name = apk.get_package()
        self._app_name = apk.get_app_name()
        self._permissions_in_xml = apk.get_permissions()
        self._api_methods = self._extract_api_methods(apk_analysis)
        self._personal_information_used = self.get_piu()
        self.prcs = self.get_prcs(self._api_methods)

    def get_permissions_in_xml(self):
        return self._permissions_in_xml

    def get_package_name(self):
        return self._package_name

    def get_app_name(self):
        return self._app_name

    def _get_method_id(self, x):
        method_strings = x.split("->")
        class_name = method_strings[0][1:].replace("/", ".")
        method_desc = method_strings[1]
        method_name = method_desc[: method_desc.find("(")].strip("<>")
        return class_name + method_name

    def _extract_api_methods(self, apk_analysis):
        """Extract all the API methods declared in the apk"""

        api_methods = []

        assert path.exists(METADATA), f"The file {METADATA} does not exist"

        with open(METADATA, "r") as metadata_file:
            metadata = json.load(metadata_file)

            for each_method in apk_analysis.methods.values():
                method_id = self._get_method_id(str(each_method.method))
                try:
                    api_metadata = metadata[method_id]
                    api_methods.append(PrivacyAPI(each_method, api_metadata))
                except KeyError:
                    pass

        return api_methods

    def _extract_callers(self, api_called):
        """Returns a JSON object of callers. The key is the caller's `id`
        and the value is another JSON object defined as
        {'caller': caller, apis_called = [api_1, api_2, ... api_n]}"""

        callers = {}

        for each_meth in api_called:
            for _, call, _ in each_meth._method_analysis_object.get_xref_from():
                caller = PrivacyMethod(call, [each_meth])
                try:
                    if each_meth not in callers[caller.get_id()]["apis_called"]:
                        callers[caller.get_id()]["apis_called"].append(each_meth)
                        callers[caller.get_id()]["caller"].add_related_apis(each_meth)
                except KeyError:
                    callers[caller.get_id()] = {
                        "caller": caller,
                        "apis_called": [each_meth],
                    }
        return callers

    def get_piu(self):
        """Return list of personal information used (piu) by all methods"""
        piu = []

        for each_api_method in self._api_methods:
            piu.extend(each_api_method.get_personal_information_collected())

        return list(set(piu))

    def get_prcs(self, api_methods):
        """Returns a list of tuples representing
        permission-requiring code segments (PRCS).
        PRCS is defined as a code segment that calls
        permission-requiring Android API to process
        personal information. Currently, PRCS includes
        upto 3 hops of methods.
        """
        prcs_list = []

        first_hop_dict = self._extract_callers(api_methods)
        first_hop_list = [f["caller"] for f in first_hop_dict.values()]

        #
        for each_first_hop in first_hop_list:
            second_hop_list = each_first_hop.get_caller_methods()
            if len(second_hop_list) == 0:
                prcs_list.append((each_first_hop))
            else:
                for each_second_hop in second_hop_list:
                    third_hop_list = each_second_hop.get_caller_methods()
                    if len(third_hop_list) == 0:
                        prcs_list.append((each_first_hop, each_second_hop))
                    else:
                        for each_third_hop in third_hop_list:
                            prcs_list.append(
                                (each_first_hop, each_second_hop, each_third_hop)
                            )

        return prcs_list

    def export(self):
        attribute_dictionary = dict(
            [
                ("app_id", str(self.get_package_name())),
                ("title", str(self.get_app_name())),
                ("permissions_in_xml", [str(x) for x in self.get_permissions_in_xml()]),
                ("personal_information_processed", self.get_picu()),
            ]
        )

        return attribute_dictionary

    def __str__(self):
        return f"{self.get_package_name()};{self.get_app_name()}"

    def __repr__(self):
        return f"<pdroid.APK {self.__str__()}>"


class AbstractPrivacyMethod:
    def __init__(self, method_analysis_object):
        self._method_analysis_object = method_analysis_object
        self._class_name = self.refine_class_name(
            self._method_analysis_object.class_name
        )
        self._method_name = self._method_analysis_object.method.name
        self._id = self._class_name + self._method_name

    @staticmethod
    def refine_class_name(method_name):
        """Remove the first 'L', replace '/' with '.', and
        remove '$<int>' instances"""
        refined_method_name = str(method_name).replace("/", ".")[1:]
        # print(f"Type of str = {type(refined_method_name)}")
        regex_match = re.search("\$.*;", refined_method_name)

        if regex_match is not None:
            start, end = regex_match.span()
            refined_method_name = (
                refined_method_name[:start] + refined_method_name[end - 1]
            )

        return MUTF8String.from_str(refined_method_name)
        # return refined_method_name

    def get_class_name(self):
        return self._class_name

    def get_method_name(self):
        return self._method_name

    def get_id(self):
        return self._id

    def is_method_analysis_object_external(self):
        return self._method_analysis_object.is_external()

    def export(self):
        attribute_dictionary = dict(
            [
                ("id", self.get_id()),
                ("class_name", self.get_class_name()),
                ("method_name", self.get_method_name()),
            ]
        )
        return attribute_dictionary


class PrivacyAPI(AbstractPrivacyMethod):
    def __init__(self, method_analysis_object, json_object):
        super().__init__(method_analysis_object)
        self.permissions_required = json_object["permissions_required"]
        self.personal_information_collected = json_object[
            "personal_information_collected"
        ]
        self.api_description = json_object["api_description"]

    def get_permissions_required(self):
        return self.permissions_required

    def get_personal_information_collected(self):
        return self.personal_information_collected

    def get_api_description(self):
        return self.api_description

    def export(self):
        attribute_dictionary = super().export()
        attr_dict = dict(
            [
                (
                    "personal_information_collected",
                    self.get_personal_information_collected(),
                ),
                ("permissions_required", self.get_permissions_required()),
                ("api_description", self.get_api_description()),
            ]
        )
        attribute_dictionary.update(attr_dict)

        return attribute_dictionary

    def __str__(self):
        return f"{self.get_id()}"

    def __repr__(self):
        return f"<pdroid.APK.PrivacyAPI {self.__str__()}>"


class PrivacyMethod(AbstractPrivacyMethod):
    def __init__(self, caller, apis: list):
        super().__init__(caller)
        self._id = (
            self._class_name
            + self._method_name
            + self._method_analysis_object.descriptor
        )
        self._permissions_required = [f.get_permissions_required() for f in apis]
        self._personal_information_collected = [
            f.get_personal_information_collected() for f in apis
        ]
        self._apis_related_to = apis

    def get_permissions_required(self):
        return self._permissions_required

    def get_personal_information_collected(self):
        return self._personal_information_collected

    def get_related_apis(self):
        return self._apis_related_to

    def add_related_apis(self, api):
        self._apis_related_to.append(api)

    def get_caller_methods(self):
        """Returns a list of methods that call this method"""
        callers = []

        for _, call, _ in self._method_analysis_object.get_xref_from():
            caller = PrivacyMethod(call, self.get_related_apis())
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
        attr_dict = dict(
            [
                ("id", self.get_id()),
                (
                    "personal_information_collected",
                    self.get_personal_information_collected(),
                ),
                ("permissions_required", self.get_permissions_required()),
            ]
        )

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
        return f"<pdroid.APK.PrivacyMethod {self.__str__()}>"
