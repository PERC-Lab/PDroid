"""Module to handle commandline arguments for analyzing Android applications"""

import os
from os.path import exists, split
import argparse

from androguard.misc import AnalyzeAPK

CWD = os.getcwd()

def parse_arguments():
    """Argument Parser

    Returns
    -------
    arguments: argparse.Namespace
        Returns arguments parsed from commandline
    """

    parser = argparse.ArgumentParser(description="Analyze privacy aspects of Android applications")

    parser.add_argument('--path_to_apk', type=str,
                        dest='path_to_apk',
                        help='Path to the apk file to be analyzed')

    parser.add_argument('--path_to_folder', type=str,
                        dest='path_to_folder',
                        help='Path to the directory containing apk files',
                        required=False)


    arguments = parser.parse_args()
    return arguments

def check_args(arguments):
    """Validate correctness of CMD args
    
    Parameters
    ----------
    arguments : dict
        Dictionary of cmd args and values
    
    Returns
    -------
    arguments : dict
        Dictionary of cmd args
    """
    if arguments.path_to_apk is not None:
        assert exists(arguments.path_to_apk), "Path to apk file does not exist!"
    if arguments.path_to_folder is not None:
        assert exists(arguments.path_to_folder), "Path to apk folder does not exist!"
    
    if (arguments.path_to_apk is None) and (arguments.path_to_folder is None):
        assert False, "Either provide path to an apk file or path to a folder of apk file(s)!"

    return arguments

def main():

    arguments = parse_arguments()
    print("Checking for arguments...")
    check_args(arguments)
    print("Arguments Validated!")

    print("Analyzing Android application")
    a, d, dx = AnalyzeAPK(arguments.path_to_apk)
    print("Printing Android application permissions")
    print(a.get_permissions())

if __name__ == '__main__':
    main()