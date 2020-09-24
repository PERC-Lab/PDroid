"""Module to handle commandline arguments for analyzing Android applications"""

import logging
import os

import click

from pdroid import APK
from androguard.misc import AnalyzeAPK

CWD = os.getcwd()
logger = logging.getLogger(__name__)


@click.group()
def main():
    pass

@main.command()
@click.option('--apk', type=click.Path(exists=True), required=True, help='Path to the apk file')

def get_sensitive_methods(apk):
    a, _, dx = AnalyzeAPK(apk)
    app = APK(a, dx)

    api_callers = app._api_callers
    print(f"Following are the sensitive methods in {apk}")
    for each_method in api_callers:
        print(f"\tMethod Name: {each_method}")

if __name__ == "__main__":
    main()
