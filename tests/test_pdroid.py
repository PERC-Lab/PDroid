"""Module for testing pdroid"""

from pathlib import Path

import pytest
from androguard.misc import AnalyzeAPK

from pdroid.pdroid import APK

CWD = Path.cwd()
METADATA = CWD.joinpath("metadata/api_metadata.json")
APK_PATH = CWD.joinpath("apk/pedometer.apk")


@pytest.fixture
def apk():
    """Return APK object"""
    app, _, apk_analysis = AnalyzeAPK(APK_PATH)
    return APK(app, apk_analysis)


def test_package_name(apk):
    """Test package name"""
    package_name = "pedometer.stepcounter.calorieburner.pedometerforwalking"
    assert apk.package_name == package_name, "Package names do not match"


def test_app_name(apk):
    """Test app name"""
    app_name = "Pedometer - Step Counter"
    assert apk.app_name == app_name, "App names do not match"


def test_get_method_id(apk):
    """test get_method_id"""
    method_strings = [
        "Lcom/google/android/gms/ads;->initialize(Landroid/content/Context; Laqd; Ljava/util/List;)V [access_flags=public abstract] @ 0x0",
        "Laad;->b(Ljava/util/Map;)Z [access_flags=public static] @ 0x116e9c",
        "La$1;-><init>()V [access_flags=constructor] @ 0x116ac4",
    ]
    method_ids = ["com.google.android.gms.ads;initialize", "aad;b", "a$1;init"]
    for i, each_method_id in enumerate(method_ids):
        encoded_method_string = method_strings[i]
        assert apk._get_method_id(encoded_method_string) == each_method_id
