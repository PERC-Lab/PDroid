"""Module for testing pdroid"""

import unittest

from pdroid.pdroid import APK, PrivacyAPI, PrivacyMethod

from pathlib import Path

from androguard.misc import AnalyzeAPK

CWD = Path.cwd()
METADATA = CWD.joinpath("metadata/api_metadata.json")
APK_PATH = CWD.joinpath("apk/pedometer.apk")


class TestAPK(unittest.TestCase):
    def setUp(self) -> None:
        apk, _, apk_analysis = AnalyzeAPK(APK_PATH)
        self.apk = APK(apk, apk_analysis)
        return super().setUp()

    def test_package_name(self):
        package_name = "pedometer.stepcounter.calorieburner.pedometerforwalking"
        self.assertEqual(self.apk.package_name, package_name)

    def test_app_name(self):
        app_name = "Pedometer - Step Counter"
        self.assertEqual(self.apk.app_name, app_name)

    def test_get_method_id(self):
        method_strings = [
            "Lcom/google/android/gms/ads;->initialize(Landroid/content/Context; Laqd; Ljava/util/List;)V [access_flags=public abstract] @ 0x0",
            "Laad;->b(Ljava/util/Map;)Z [access_flags=public static] @ 0x116e9c",
            "La$1;-><init>()V [access_flags=constructor] @ 0x116ac4",
        ]
        method_ids = ["com.google.android.gms.ads;initialize", "aad;b", "a$1;init"]
        for i, each_method_id in enumerate(method_ids):
            encoded_method_string = method_strings[i]
            self.assertEqual(
                self.apk._get_method_id(encoded_method_string), each_method_id
            )
