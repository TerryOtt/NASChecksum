import argparse
import os
import os.path
import sys
import pprint
import json


def _main():
    args = _parse_cli_args()
    files_to_checksum = _enumerate_files_to_checksum(args)

def _parse_cli_args():
    arg_parser = argparse.ArgumentParser(description="Checksum directory trees off the NAS")
    arg_parser.add_argument("checksum_json_file", help="file to store checksums from all the given directories")
    arg_parser.add_argument("source_rootdir_to_checksum", nargs="+",
                            help="Path to directory that all files under it should be added to checksum file")
    return arg_parser.parse_args()


def _enumerate_files_to_checksum(args):
    # Find all rootdirs
    for curr_source_rootdir in args.source_rootdir_to_checksum:
        if os.path.isdir(curr_source_rootdir) is False:
            sys.exit(f"Rootdir {curr_source_rootdir} does not exist")
        print(f"Found valid source rootdir: {curr_source_rootdir}")

    # We now know all roots are valid, so create a dictionary with all the roots listed
    checksum_dict = {
        "source_rootdirs": {
        }
    }

    # Walk over each root and recursively find all files under it
    for curr_source_rootdir in args.source_rootdir_to_checksum:
        checksum_dict['source_rootdirs'][curr_source_rootdir.lower()] = {}

        source_rootdir_result = [os.path.join(dp, f) for dp, dn, filenames in os.walk(curr_source_rootdir)
                                 for f in filenames]

        for curr_result in source_rootdir_result:
            # Remove the rootdir prefix
            relative_path_to_add = curr_result[len(curr_source_rootdir):].lower()

            # Trim off leading file system dir/file separator character(s)
            while relative_path_to_add[0] == os.sep:
                relative_path_to_add = relative_path_to_add[1:]

            checksum_dict['source_rootdirs'][curr_source_rootdir.lower()][relative_path_to_add] = {}

        print(f"Found {len(source_rootdir_result)} files under {curr_source_rootdir}")

    print("Files we found:\n" + json.dumps(checksum_dict, indent=4, sort_keys=True))

    return checksum_dict


if __name__ == "__main__":
    _main()
