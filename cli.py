"""Module to handle commandline arguments for analyzing Android applications"""

import logging
import os
from pathlib import Path

import click

from pdroid import APK
from androguard.misc import AnalyzeAPK

CWD = os.getcwd()
logger = logging.getLogger(__name__)


@click.command()
@click.option('--apk', type=click.Path(exists=True), required=True, help='Path to the apk file')
def extract_prcs(apk):
    """Analyzes the apk and extracts permission-requiring code segments"""

    a, _, dx = AnalyzeAPK(apk)
    app = APK(a, dx)
    prcs_list = app.prcs

    path_to_apk = Path(apk)
    dir_to_apk = path_to_apk.parent
    app_name = app.get_app_name()

    app_dir = dir_to_apk / app_name
    os.makedirs(app_dir)

    for i, el in enumerate(prcs_list):
        filepath = app_dir / f"PRCS_{str(i)}.java"

        with open(filepath, 'w') as f:
            header =  f"class PRCS_{str(i)} {{\n"
            footer = "\n}"
            try:
                f.write(header)
                if type(el) == tuple:
                    for each_hop in el:
                        src_code = each_hop.get_source_code()
                        f.write(src_code)
                else:
                    src_code = el.get_source_code()
                    f.write(src_code)
                f.write(footer)
            except Exception as e:
                print(f"Exception {e} occurred at index {i}")

if __name__ == "__main__":
    extract_prcs()
