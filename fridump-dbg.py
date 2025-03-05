#Edited by Abhijith on 05/03/2025
import textwrap
import frida
import os
import sys
import argparse
import logging
import dumper
import utils

def setup_logger(verbose):
    logging_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(format='%(levelname)s: %(message)s', level=logging_level)

def get_arguments():
    parser = argparse.ArgumentParser(
        prog='fridump',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Frida-based memory dumper")
    parser.add_argument('-o', '--out', type=str, metavar="dir", help='Output directory path (default: dump)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('-r', '--read-only', action='store_true', help='Dump read-only memory')
    parser.add_argument('-s', '--strings', action='store_true', help='Run strings on all dump files')
    parser.add_argument('--max-size', type=int, metavar="bytes", default=20971520,
                        help='Maximum dump file size (default: 20971520 bytes)')
    parser.add_argument('-l', '--listprocess', action='store_true', help='List all running processes')
    return parser.parse_args()

def get_device():
    try:
        return frida.get_usb_device(timeout=5)
    except Exception as e:
        logging.error("Failed to get USB device. Ensure the device is connected and Frida server is running.")
        sys.exit(1)

def list_processes(device):
    try:
        running_processes = device.enumerate_processes()  # Get all running processes
        installed_apps = {app.pid: app.identifier for app in device.enumerate_applications()}  # Map PIDs to package names

        user_apps = []
        system_prefixes = ("com.android.", "android.", "com.google.android.", "com.miui.", "com.samsung.", "com.huawei.", "com.apple.")

        for process in running_processes:
            package_name = installed_apps.get(process.pid, "Unknown")  # Get package name if available
            if process.pid > 0 and package_name != "Unknown" and not package_name.startswith(system_prefixes):
                user_apps.append((process.pid, process.name, package_name))

        # Display only user-installed running applications with valid PIDs
        if user_apps:
            print("\n----------- Running User Installed Applications -----------\n")
            print("{:<8} {:<30} {:<40}".format("PID", "Process Name", "Package Identifier"))
            print("=" * 80)
            for pid, name, identifier in user_apps:
                print("{:<8} {:<30} {:<40}".format(pid, name, identifier))
        else:
            print("\nNo user-installed applications are currently running.")

    except Exception as e:
        logging.error("Failed to list processes: %s", e)
        sys.exit(1)

def attach_to_process(device, process_name):
    try:
        return device.attach(process_name)
    except Exception as e:
        logging.error("Cannot attach to process %s. Ensure the app is running and debuggable.", process_name)
        sys.exit(1)

def setup_output_directory(directory):
    if directory:
        if not os.path.isdir(directory):
            logging.error("Output directory does not exist: %s", directory)
            sys.exit(1)
    else:
        directory = os.path.join(os.getcwd(), "dump")
        if not os.path.exists(directory):
            os.makedirs(directory)
    logging.info("Output directory set to: %s", directory)
    return directory

def start_memory_dump(session, perms, max_size, directory):
    logging.info("Starting memory dump...")
    script = session.create_script(
        """'use strict';
        rpc.exports = {
          enumerateRanges: function (prot) {
            return Process.enumerateRangesSync(prot);
          },
          readMemory: function (address, size) {
            return Memory.readByteArray(ptr(address), size);
          }
        };""")
    script.on("message", utils.on_message)
    script.load()
    agent = script.exports_sync
    ranges = agent.enumerate_ranges(perms)

    for i, range in enumerate(ranges):
        base, size = range["base"], range["size"]
        logging.debug("Dumping memory: Base=%s, Size=%d", base, size)
        if size > max_size:
            dumper.splitter(agent, base, size, max_size, "", directory)
        else:
            dumper.dump_to_file(agent, base, size, "", directory)
        utils.printProgress(i + 1, len(ranges), prefix='Progress:', suffix='Complete', bar=50)

def main():
    args = get_arguments()
    setup_logger(args.verbose)
    device = get_device()

    print("\n\n-----------Device Details----------\n")
    print(device,"\n")

    if args.listprocess:
        list_processes(device)
        sys.exit(0)

    list_processes(device)
    app_name = input("\nEnter the process name to dump memory: ")
    session = attach_to_process(device, app_name)

    directory = setup_output_directory(args.out)
    perms = 'r--' if args.read_only else 'rw-'

    start_memory_dump(session, perms, args.max_size, directory)

    if args.strings:
        files = os.listdir(directory)
        for i, file in enumerate(files):
            utils.strings(file, directory)
            utils.printProgress(i + 1, len(files), prefix='Processing:', suffix='Complete', bar=50)

    logging.info("Memory dump complete!")

if __name__ == "__main__":
    main()
