import argparse
import os
import os.path
import queue
import sys
# import pprint
import json
import multiprocessing
import hashlib


def _main():
    args = _parse_cli_args()

    checksum_file_dict = _enumerate_files_to_checksum(args)
    existing_checksums = _read_existing_checksums(args)

    if args.force_checksums is False:
        number_merged_checksums = _merge_in_existing_checksums(checksum_file_dict, existing_checksums)
    else:
        number_merged_checksums = 0

    total_files_in_sourcedirs = _count_files_in_hash_dictionary(checksum_file_dict)
    if total_files_in_sourcedirs - number_merged_checksums > 0:
        work_to_do = True
    else:
        work_to_do = False

    if work_to_do:
        _compute_checksums(args, checksum_file_dict, total_files_in_sourcedirs - number_merged_checksums)
        #print("Computed checksums:\n" + json.dumps(checksum_file_dict, indent=4, sort_keys=True))

        _merge_checksums_not_in_sourcedirs(checksum_file_dict, existing_checksums)

        _write_checksum_to_file(args, checksum_file_dict)
    else:
        print("\nSkipped all checksum computations -- no new checksums to compute!")


def _parse_cli_args():
    arg_parser = argparse.ArgumentParser(description="Checksum directory trees off the NAS")

    # Determined experimentally -- ran values from 1 to 32 and then binary searched to best CPU
    #       utilization
    default_child_worker_processes = 16  # multiprocessing.cpu_count() - 1
    arg_parser.add_argument("--workers", type=int, default=default_child_worker_processes,
                            help="Optional number of child worker processes "
                            f"(default {default_child_worker_processes} due to CPU supporting "
                            f"{multiprocessing.cpu_count()} threads)")

    default_queue_depth = 4096
    arg_parser.add_argument("--queuedepth", type=int, default=default_queue_depth,
                            help="Optional queue depth "
                            f"(default {default_queue_depth} to limit memory usage)")

    default_skip_existing_files = True
    arg_parser.add_argument("--force-checksums", action='store_true',
                            help="Force computing all checksums in root dirs, "
                            "even if found in existing checksum JSON file")

    arg_parser.add_argument("checksum_json_file", help="file to store checksums from all the given directories")
    arg_parser.add_argument("source_rootdir_to_checksum", nargs="+",
                            help="Path to directory that all files under it should be added to checksum file")

    return arg_parser.parse_args()


def _enumerate_files_to_checksum(args):
    # Find all rootdirs
    for curr_source_rootdir in args.source_rootdir_to_checksum:
        if os.path.isdir(curr_source_rootdir) is False:
            sys.exit(f"Rootdir {curr_source_rootdir} does not exist")
        # print(f"Found valid source rootdir: {curr_source_rootdir}")

    # We now know all roots are valid, so create a dictionary with all the roots listed
    checksum_dict = {
        "source_rootdirs": {
        }
    }

    # Walk over each root and recursively find all files under it
    print("Enumerating files to checksum")
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

        print(f"\t- Source rootdir \"{curr_source_rootdir}\": {len(source_rootdir_result):6,} files")

    # print("Files we found:\n" + json.dumps(checksum_dict, indent=4, sort_keys=True))
    print("File enumeration complete!")

    return checksum_dict


def _read_existing_checksums(args):
    existing_checksums = None
    if os.path.isfile(args.checksum_json_file):
        print("\nReading existing checksums")
        print(f"\t- Reading pre-existing checksums from \"{args.checksum_json_file}\"")

        with open(args.checksum_json_file, "r") as existing_checksum_file:
            existing_checksums = json.load(existing_checksum_file)

        number_of_files_already_checksummed = _count_files_in_hash_dictionary(existing_checksums)
        print(f"\t- Total existing checksums found: {number_of_files_already_checksummed:6,}")

        print("Reading existing checksums complete!")
    else:
        existing_checksums = {
            'source_rootdirs': {}
        }

    return existing_checksums


def _merge_in_existing_checksums(checksum_file_dict, existing_checksums):
    print("\nDetermining checksums we can skip due to having previously computed them")
    checksums_skipped = 0
    for curr_sourcedir in checksum_file_dict['source_rootdirs']:
        for curr_relative_path in checksum_file_dict['source_rootdirs'][curr_sourcedir]:
            if curr_sourcedir in existing_checksums['source_rootdirs']:
                if curr_relative_path in existing_checksums['source_rootdirs'][curr_sourcedir]:
                    checksums_skipped += 1
                    checksum_file_dict['source_rootdirs'][curr_sourcedir][curr_relative_path] = \
                        existing_checksums['source_rootdirs'][curr_sourcedir][curr_relative_path]

    print(f"\t- Number of checksums skipped: {checksums_skipped:,}")

    print("Work reduction complete!")

    return checksums_skipped


def _compute_checksums(args, checksum_file_dict, number_of_files_awaiting_checksum):

    print("\nComputing file checksums")

    # Quickly determine how many files we're going to checksum, so we know when all the checksum work is done
    print(f"\t- Total number of files to compute checksums for: {number_of_files_awaiting_checksum:6,}")

    # Create multi-process Queues for sending files to be checksummed, and then once checksum is computed
    queue_for_files_awaiting_checksumming = multiprocessing.Queue(args.queuedepth)
    queue_of_checksummed_files = multiprocessing.Queue(args.queuedepth)

    # Event where parent process indicates all work is now completed
    all_checksum_work_completed = multiprocessing.Event()

    child_process_handles = _launch_checksum_worker_processes(args, queue_for_files_awaiting_checksumming,
                                                               queue_of_checksummed_files,
                                                               all_checksum_work_completed)

    for curr_source_rootdir in checksum_file_dict['source_rootdirs']:
        for curr_relative_path_to_checksum in checksum_file_dict['source_rootdirs'][curr_source_rootdir]:

            # See if there's any work here to do -- if it already has hashes, we merged in from existing,
            #       no work to do!
            if 'hashes' in checksum_file_dict['source_rootdirs'][curr_source_rootdir][curr_relative_path_to_checksum]:
                continue

            checksum_queue_entry = {
                'source_rootdir'    : curr_source_rootdir,
                'relative_path'     : curr_relative_path_to_checksum
            }

            #print("Going to push this entry into checksumming queue: " + pprint.pformat(checksum_queue_entry))
            queue_for_files_awaiting_checksumming.put(checksum_queue_entry)

            # Now read all the entries we can out of the computed checksum queue to keep all processes busy
            while True:
                try:
                    #print("Parent awaiting a write to the checksummed file queue")
                    checksummed_file_entry = queue_of_checksummed_files.get_nowait()
                    # print("Got entry:\n" + json.dumps(checksummed_file_entry, indent=4, sort_keys=True))

                    checksum_file_dict['source_rootdirs'][ checksummed_file_entry['source_rootdir'] ][
                        checksummed_file_entry['relative_path']]['hashes'] = checksummed_file_entry['hashes']

                    number_of_files_awaiting_checksum -= 1

                    # print("Parent got a checksum back, number of files awaiting checksum: "
                    #      f"{number_of_files_awaiting_checksum}")
                except queue.Empty as e:
                    # totally expected, not actually exceptional, break out of our read loop
                    break
    # Wrote all entries in the queue for checksumming, get all remaining entries from child queue
    while number_of_files_awaiting_checksum > 0:
        #print("Parent awaiting a write to the checksummed file queue")
        checksummed_file_entry = queue_of_checksummed_files.get()
        # print("Got entry:\n" + json.dumps(checksummed_file_entry, indent=4, sort_keys=True))
        checksum_file_dict['source_rootdirs'][checksummed_file_entry['source_rootdir']][
            checksummed_file_entry['relative_path']]['hashes'] = checksummed_file_entry['hashes']

        number_of_files_awaiting_checksum -= 1

        # print("Parent got a checksum back, number of files awaiting checksum: "
        #      f"{number_of_files_awaiting_checksum}")

    all_checksum_work_completed.set()
    # print("Parent signaled that all expected checksums were received")

    _wait_for_all_child_worker_processes_to_rejoin(child_process_handles)

    print("File checksum computations complete!")


def _count_files_in_hash_dictionary(hash_dictionary):
    # Quickly determine how many files we're going to checksum, so we know when all the checksum work is done
    number_of_files_awaiting_checksum = 0
    for curr_source_rootdir in hash_dictionary['source_rootdirs']:
        for curr_relative_path_to_checksum in hash_dictionary['source_rootdirs'][curr_source_rootdir]:
            number_of_files_awaiting_checksum += 1

    return number_of_files_awaiting_checksum


def _launch_checksum_worker_processes(args, queue_for_files_awaiting_checksum, queue_of_checksummed_files,
                                      all_checksum_work_completed):

    child_process_handles = []
    print(f"\t- Launching {args.workers} child process(es) to compute file checksums")
    for i in range(args.workers):
        child_process = multiprocessing.Process(target=_checksum_worker,
                                                args=(i + 1, queue_for_files_awaiting_checksum,
                                                      queue_of_checksummed_files,
                                                      all_checksum_work_completed))
        child_process.start()
        child_process_handles.append(child_process)

    return child_process_handles


def _checksum_worker(worker_index, queue_for_files_awaiting_checksum, queue_of_checksummed_files,
                     all_checksum_work_completed):

    queue_read_timeout_seconds = 0.1
    blocking_read = True

    while all_checksum_work_completed.is_set() is False:
        # Try a blocking read off the incoming queue
        try:
            item_to_checksum = queue_for_files_awaiting_checksum.get(block=blocking_read,
                                                                     timeout=queue_read_timeout_seconds)
            # print("Worker got item to checksum: " + pprint.pformat(item_to_checksum))

            full_path_to_file = os.path.join(
                item_to_checksum['source_rootdir'],
                item_to_checksum['relative_path'])

            with open(full_path_to_file, "rb") as f:
                try:
                    file_contents = f.read()
                except Exception as e:
                    print("Something blew up in IO")
                    continue

            computed_hash = hashlib.sha3_512(file_contents).hexdigest()

            checksummed_item = {
                "hashes": {
                    "sha3_512": computed_hash
                }
            }
            # Merge in the contents of the incomingfile info so we have complete context about WHICH file got
            #       checksummed
            checksummed_item.update(item_to_checksum)
            #print("Child worker going to put something in checksum queue")
            queue_of_checksummed_files.put(checksummed_item)
            #print("Child worker successfully added to checksum queue")
        except queue.Empty as e:
            continue


def _wait_for_all_child_worker_processes_to_rejoin(child_worker_handles):
    while child_worker_handles:
        curr_handle = child_worker_handles.pop()
        curr_handle.join()

    # print("All child worker processes rejoined cleanly!")


def _merge_checksums_not_in_sourcedirs(checksum_file_dict, existing_checksums):
    print("\nMerging in sourcedirs from checksum JSON but not included in this run")
    checksums_merged_in = 0
    for curr_existing_sourcedir in existing_checksums['source_rootdirs']:
        # If we didn't know anything about this sourcedir, fold the whole tree in and be done here
        if curr_existing_sourcedir not in checksum_file_dict['source_rootdirs']:
            checksums_merged_in += len(existing_checksums['source_rootdirs'][curr_existing_sourcedir])
            checksum_file_dict['source_rootdirs'][curr_existing_sourcedir] = \
                existing_checksums['source_rootdirs'][curr_existing_sourcedir]
    print(f"\t- Checksums merged in: {checksums_merged_in:,}")
    print("Checksum merging complete!")


def _write_checksum_to_file(args, checksum_file_dict):
    print("\nWriting file checksums to disk")
    print(f"\t- Writing {_count_files_in_hash_dictionary(checksum_file_dict):,} checksums")
    print(f"\t- Writing to file \"{args.checksum_json_file}\"")
    with open(args.checksum_json_file, "w") as output_json:
        json.dump(checksum_file_dict, output_json, indent=4, sort_keys=True)
    print("Checksums written to disk")


if __name__ == "__main__":
    _main()
