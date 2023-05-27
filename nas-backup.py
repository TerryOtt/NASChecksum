import argparse
import os
import os.path
import queue
import sys
import pprint
import json
import multiprocessing

def _main():
    args = _parse_cli_args()
    checksum_file_dict = _enumerate_files_to_checksum(args)
    _compute_checksums(args, checksum_file_dict)


def _parse_cli_args():
    arg_parser = argparse.ArgumentParser(description="Checksum directory trees off the NAS")
    default_child_worker_processes = multiprocessing.cpu_count() - 1
    arg_parser.add_argument("--workers", type=int, default=default_child_worker_processes,
                            help="Optional number of child worker processes "
                            f"(default {default_child_worker_processes} due to CPU supporting "
                            f"{multiprocessing.cpu_count()} threads)")
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

        print(f"Found {len(source_rootdir_result)} files under \"{curr_source_rootdir}\"")

    # print("Files we found:\n" + json.dumps(checksum_dict, indent=4, sort_keys=True))

    return checksum_dict


def _compute_checksums(args, checksum_file_dict):
    # Create multi-process Queues for sending files to be checksummed, and then once checksum is computed
    queue_for_files_awaiting_checksumming = multiprocessing.Queue()
    queue_of_checksummed_files = multiprocessing.Queue()

    # Event where parent process indicates all work is now completed
    all_checksum_work_completed = multiprocessing.Event()

    child_process_handles = _launch_checksum_worker_processes(args, queue_for_files_awaiting_checksumming,
                                                              queue_of_checksummed_files,
                                                              all_checksum_work_completed)

    # Quickly determine how many files we're going to checksum, so we know when all the checksum work is done
    number_of_files_awaiting_checksum = 0
    for curr_source_rootdir in checksum_file_dict['source_rootdirs']:
        for curr_relative_path_to_checksum in checksum_file_dict['source_rootdirs'][curr_source_rootdir]:
            number_of_files_awaiting_checksum += 1

    print(f"Total number of files needing checksumming: {number_of_files_awaiting_checksum}")

    for curr_source_rootdir in checksum_file_dict['source_rootdirs']:
        for curr_relative_path_to_checksum in checksum_file_dict['source_rootdirs'][curr_source_rootdir]:
            checksum_queue_entry = ( curr_source_rootdir, curr_relative_path_to_checksum )

            #print("Going to push this entry into checksumming queue: " + pprint.pformat(checksum_queue_entry))
            queue_for_files_awaiting_checksumming.put(checksum_queue_entry)

            # Now read all the entries we can out of the computed checksum queue to keep all processes busy
            while True:
                try:
                    print("Parent awaiting a write to the checksummed file queue")
                    checksummed_file_entry = queue_of_checksummed_files.get_nowait()
                    number_of_files_awaiting_checksum -= 1

                    print("Parent got a checksum back, number of files awaiting checksum: "
                          f"{number_of_files_awaiting_checksum}")
                except queue.Empty as e:
                    # totally expected, not actually exceptional, break out of our read loop
                    break
    # Wrote all entries in the queue for checksumming, get all remaining entries from child queue
    while number_of_files_awaiting_checksum > 0:
        print("Parent awaiting a write to the checksummed file queue")
        checksummed_file_entry = queue_of_checksummed_files.get()
        number_of_files_awaiting_checksum -= 1

        print("Parent got a checksum back, number of files awaiting checksum: "
              f"{number_of_files_awaiting_checksum}")

    all_checksum_work_completed.set()
    print("Parent signaled that all expected checksums were received")

    _wait_for_all_child_worker_processes_to_rejoin(child_process_handles)


def _launch_checksum_worker_processes(args, queue_for_files_awaiting_checksum, queue_of_checksummed_files,
                                      all_checksum_work_completed):

    child_process_handles = []
    print(f"Launching {args.workers} child process(es) to compute file checksums")
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
            #print("Worker got item to checksum: " + pprint.pformat(item_to_checksum))
            # Fake out a checksum was completed
            checksummed_item = ("foo", "bar", "01234567890abcdef")
            print("Child worker going to put something in checksum queue")
            queue_of_checksummed_files.put(checksummed_item)
            print("Child worker successfully added to checksum queue")
        except queue.Empty as e:
            continue


def _wait_for_all_child_worker_processes_to_rejoin(child_worker_handles):
    while child_worker_handles:
        curr_handle = child_worker_handles.pop()
        curr_handle.join()

    print("All child worker processes rejoined cleanly!")


if __name__ == "__main__":
    _main()
