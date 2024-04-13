import datetime
import functools
import json
import logging
import os
import platform
import socket
import sys
import time
import traceback
import wmi


def set_up_logging():
    """
    Configures logging to output errors to a specified JSON log file.
    If the logs directory doesn't exist, it creates one.

    Returns:
        logging.Logger: Logger object for logging errors.
    """
    global logger  # Declare logger as global variable

    # Define the path for the log file
    log_file_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "logs", "error.json"
    )

    # Create logs directory if it doesn't exist
    os.makedirs(os.path.dirname(log_file_path), exist_ok=True)

    # Configure logging
    logging.basicConfig(
        level=logging.ERROR,
        filename=log_file_path,
        filemode="a",
        format="%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Get the logger object
    logger = logging.getLogger(__name__)

    return logger


# Initialize logger
logger = set_up_logging()


def log_errors(func):
    """
    Decorator that logs specific errors and shuts down the logging system after execution.

    Args:
        func (callable): The function to decorate.

    Returns:
        callable: The decorated function.
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (
            ValueError,
            TypeError,
            KeyError,
            IndexError,
            FileNotFoundError,
            IOError,
            Exception,
        ) as e:
            # Log the error using the log_error function
            log_error(func, e, type(e).__name__.lower())
        finally:
            # Closing the logger
            logging.shutdown()

    return wrapper


def log_error(func, error, error_type):
    """
    Logs an error with relevant information.

    This function extracts the traceback information (if available) and creates a dictionary
    containing the current time, function name, error type, error message, line number,
    file name, and function name where the error occurred. It then logs this dictionary as
    a JSON string using the provided logger.

    Args:
        func (callable): The function where the error occurred.
        error (Exception): The exception object representing the error.
        error_type (str): The type of the error.

    Returns:
        None
    """
    # Extract traceback information
    tb = traceback.extract_tb(error.__traceback__)
    if tb:
        error_line, error_file, error_function = tb[-1][1], tb[-1][0], tb[-1][2]
    else:
        error_line, error_file, error_function = None, None, None

    # Create a dictionary containing error information
    error_data = {
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "function": func.__name__,
        "type": error_type,
        "error": str(error),
        "line": error_line,
        "file": error_file,
        "function_name": error_function,
    }

    # Log the error data as a JSON string
    logger.error(json.dumps(error_data))


@log_errors
def example_function(x, y):
    return x / y


# Example usage
print(example_function(1, 0))


@log_errors
def clear_terminal():
    """
    Clears the terminal screen.

    Uses the 'cls' command for Windows systems and the 'clear' command for Unix/Linux systems
    to clear the terminal screen.

    Note:
        This function uses os.system, which is not recommended for security reasons
        when executing shell commands. Consider using alternative methods for
        clearing the terminal screen in production code.

    Returns:
        None
    """
    if os.name == "nt":  # Check if the operating system is Windows
        os.system("cls")  # Clear the screen using 'cls' command
    else:
        os.system("clear")  # Clear the screen using 'clear' command


@log_errors
def host_detection(wmi_service):
    """
    Detects host information using the provided WMI service.

    Args:
        wmi_service: The WMI service object for querying host information.

    Returns:
        dict: A dictionary containing the hostname, username and domain.
    """
    host_info = {}
    for computer in wmi_service.Win32_ComputerSystem():
        # Extract host information
        host_info = {
            "hostname": computer.Caption or "N/A",
            "username": computer.UserName or "N/A",
            "domain": computer.Domain or "N/A",
        }
    return host_info


@log_errors
def os_detection(wmi_service):
    """
    Detects operating system information using the provided WMI service and platform module.

    Args:
        wmi_service: The WMI service object for querying operating system information.

    Returns:
        dict: A dictionary containing the install date, name, architecture,
              version, and version info of the operating system.
    """
    os_info = {}

    # Extract install date and calculate days since install
    install_date_str = wmi_service.Win32_OperatingSystem()[0].InstallDate[:8]
    install_date = datetime.datetime.strptime(install_date_str, "%Y%m%d")
    days_since_install = (datetime.datetime.now() - install_date).days
    os_info["install_date"] = (
        f"{install_date_str} ({days_since_install} days ago)" or "N/A"
    )

    # Get OS information using platform module
    os_info["name"] = platform.system() or "N/A"
    os_info["architecture"] = platform.architecture()[0] or "N/A"
    os_info["version"] = platform.win32_ver()[0] or "N/A"
    os_info["version_info"] = platform.win32_ver()[1] or "N/A"

    return os_info


@log_errors
def account_detection(wmi_service):
    """
    Detects user account information using the provided WMI service.

    Args:
        wmi_service: The WMI service object for querying user account information.

    Returns:
        dict: A dictionary containing information about user accounts, excluding specified accounts.
    """
    excluded_accounts = {"defaultaccount", "wdagutilityaccount", "guest"}

    # Filter out excluded accounts
    user_accounts = [
        account
        for account in wmi_service.Win32_UserAccount()
        if account.Name.lower() not in excluded_accounts
    ]

    account_info = {}
    for idx, account in enumerate(user_accounts, start=1):
        # Extract account information
        account_info[idx] = {
            "username": account.Name or "N/A",
            "domain": account.Domain or "N/A",
            "sid": account.SID or "N/A",
            "disabled": "Yes" if account.Disabled else "No",
        }
    return account_info


@log_errors
def motherboard_detection(wmi_service):
    """
    Detects motherboard information using the provided WMI service.

    Args:
        wmi_service: The WMI service object for querying motherboard information.

    Returns:
        dict: A dictionary containing information about the motherboard.
    """
    motherboard_info = {}
    for idx, board in enumerate(wmi_service.Win32_BaseBoard(), start=1):
        # Extract motherboard information
        motherboard_info[idx] = {
            "manufacturer": board.Manufacturer or "N/A",
            "model": board.Product or "N/A",
            "serial_number": board.SerialNumber or "N/A",
        }
    return motherboard_info


@log_errors
def cpu_detection(wmi_service):
    """
    Detects CPU information using the provided WMI service.

    Args:
        wmi_service: The WMI service object for querying CPU information.

    Returns:
        dict: A dictionary containing information about the CPU.
    """
    cpu_info = {}
    for idx, cpu in enumerate(wmi_service.Win32_Processor(), start=1):
        # Extract CPU information
        cpu_info[idx] = {
            "name": cpu.Name or "N/A",
            "max_clock_speed": f"{cpu.MaxClockSpeed} MHz" or "N/A",
            "cores": cpu.NumberOfCores or "N/A",
            "threads": cpu.NumberOfLogicalProcessors or "N/A",
        }
    return cpu_info


@log_errors
def ram_detection(wmi_service):
    """
    Detects RAM information using the provided WMI service.

    Args:
        wmi_service: The WMI service object for querying RAM information.

    Returns:
        dict: A dictionary containing information about the RAM.
    """
    ram_info = {}
    for idx, ram in enumerate(wmi_service.Win32_PhysicalMemory(), start=1):
        # Extract RAM information
        ram_info[idx] = {
            "capacity": round(
                int(ram.Capacity) / (1024**3), 2
            ),  # Convert bytes to gigabytes
            "manufacturer": ram.Manufacturer or "N/A",
            "speed": ram.Speed or "N/A",
        }
    return ram_info


@log_errors
def gpu_detection(wmi_service):
    """
    Detects GPU information using the provided WMI service.

    Args:
        wmi_service: The WMI service object for querying GPU information.

    Returns:
        dict: A dictionary containing information about the GPU.
    """
    gpu_info = {}
    for idx, gpu in enumerate(wmi_service.Win32_VideoController(), start=1):
        # Extract GPU information
        gpu_info[idx] = {"name": gpu.Name or "N/A"}
    return gpu_info


@log_errors
def storage_detection(wmi_service):
    """
    Detects storage information using the provided WMI service.

    Args:
        wmi_service: The WMI service object for querying storage information.

    Returns:
        dict: A dictionary containing information about the storage devices and their partitions.
    """
    storage_info = {}
    for idx, disk in enumerate(wmi_service.Win32_DiskDrive(), start=1):
        # Extract disk information
        storage_info[idx] = {
            "name": disk.Caption or "N/A",
            "size": (
                round(int(disk.Size) / (1024**3), 2) if disk.Size is not None else "N/A"
            ),
            "type": (
                "SSD"
                if "SSD" in (disk.MediaType or "") or "SSD" in (disk.Caption or "")
                else "HDD"
            ),
            "partitions": [],
        }
        for partition in disk.associators("Win32_DiskDriveToDiskPartition"):
            for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                # Extract partition information
                partition_info = {}
                partition_info["name"] = logical_disk.Caption
                partition_info["total_size"] = (
                    round(int(logical_disk.Size) / (1024**3), 0)
                    if logical_disk.Size is not None
                    else "N/A"
                )
                partition_info["free_size"] = (
                    round(int(logical_disk.FreeSpace) / (1024**3), 0)
                    if logical_disk.FreeSpace is not None
                    else "N/A"
                )
                storage_info[idx]["partitions"].append(partition_info)
    return storage_info


@log_errors
def nic_detection(wmi_service):
    """
    Detects network interface card (NIC) information using the provided WMI service.

    Args:
        wmi_service: The WMI service object for querying NIC information.

    Returns:
        dict: A dictionary containing information about the NICs.
    """
    nic_info = {}
    for idx, nic in enumerate(
        wmi_service.Win32_NetworkAdapterConfiguration(IPEnabled=True), start=1
    ):
        # Extract NIC information
        nic_info[idx] = {
            "description": nic.Description or "N/A",
            "ip_address": nic.IPAddress[0] if nic.IPAddress else "N/A",
            "subnet_mask": nic.IPSubnet[0] if nic.IPSubnet else "N/A",
            "default_gateway": (
                nic.DefaultIPGateway[0] if nic.DefaultIPGateway else "N/A"
            ),
            "dns_servers": (
                nic.DNSServerSearchOrder if nic.DNSServerSearchOrder else "N/A"
            ),
            "dhcp_enabled": nic.DHCPEnabled,
        }
    return nic_info


@log_errors
def print_info(system_info):
    """
    Prints the system information to the console.

    Args:
        system_info (dict): A dictionary containing system information.

    Returns:
        None
    """
    space = "\t  "

    host_info = system_info["host_info"]
    os_info = system_info["os_info"]
    account_info = system_info["account_info"]
    motherboard_info = system_info["motherboard_info"]
    cpu_info = system_info["cpu_info"]
    ram_info = system_info["ram_info"]
    storage_info = system_info["storage_info"]
    gpu_info = system_info["gpu_info"]
    nic_info = system_info["nic_info"]

    # Print Host information
    print(f"\nHost:", end="")
    print(f"{space*2}Hostname ....... : {host_info['hostname']}")
    print(f"{space*2}Username ....... : {host_info['username']}")
    print(f"{space*2}Domain ......... : {host_info['domain']}")

    # Print Operating System information
    print(f"\nOperation System: ", end="")
    print(
        f"Description .... : {os_info['name']} {os_info['version']} {os_info['architecture']} ({os_info['version_info']})"
    )
    print(f"{space*2}install_date ... : {os_info['install_date']}")

    # Print Account information
    for idx, info in account_info.items():
        print(f"\nAccount{idx}:", end="")
        print(f"{space}Username ....... : {info['username']}")
        print(f"{space*2}Domain ......... : {info['domain']}")
        print(f"{space*2}SID Number ..... : {info['sid']}")
        print(f"{space*2}Disabled ....... : {info['disabled']}")

    # Print Motherboard information
    for idx, info in motherboard_info.items():
        print(f"\nMotherboard{idx}:", end="")
        print(f"{space}Manufacturer ... : {info['manufacturer']}")
        print(f"{space*2}Product ........ : {info['model']}")
        print(f"{space*2}SerialNumber  .. : {info['serial_number']}")

    # Print CPU information
    for idx, info in cpu_info.items():
        print(f"\nCPU{idx}:", end="")
        print(f"{space*2}Description .... : {info['name']}")
        print(f"{space*2}Clock Speed .... : {info['max_clock_speed']}")
        print(f"{space*2}Cores .......... : {info['cores']}")
        print(f"{space*2}Threads ........ : {info['threads']}")

    # Print RAM information
    for idx, info in ram_info.items():
        print(f"\nRAM{idx}:", end="")
        print(f"{space*2}Capacity ....... : {info['capacity']} GB")
        print(f"{space*2}Manufacturer ... : {info['manufacturer']}")
        print(f"{space*2}Speed .......... : {info['speed']} MHz")

    # Print Storage information
    for idx, info in storage_info.items():
        print(f"\n{info['type']}{idx}:", end="")
        print(f"{space*2}Description .... : {info['name']}")
        print(f"{space*2}Size ........... : {info['size']} GB")
        for partition_idx, partition in enumerate(info["partitions"], start=1):
            print(f"{space*2}Partition #{partition_idx} ... : ", end="")
            print(f"Letter: {partition['name']}", end="")
            print(f" (Size: {partition['free_size']}/{partition['total_size']} GB)")

    # Print GPU information
    for idx, info in gpu_info.items():
        print(f"\nGPU{idx}:   ", end="")
        print(f"{space}Description .... : {info['name']}")

    # Print NIC information
    for idx, info in nic_info.items():
        print(f"\nNIC{idx}:", end="")
        print(f"{space*2}Description .... : {info['description']}")
        print(f"{space*2}IP Address ..... : {info['ip_address']}")
        print(f"{space*2}Subnet Mask .... : {info['subnet_mask']}")
        print(f"{space*2}DefaultGateway . : {info['default_gateway']}")
        print(f"{space*2}DNS Servers .... : {', '.join(info['dns_servers'])}")
        print(f"{space*2}DHCP Enabled ... : {'Yes' if info['dhcp_enabled'] else 'No'}")


@log_errors
def generate_output(system_info):
    """
    Generates an output file containing system information.

    This function creates a text file containing system information such as hostname, current date, and time,
    and saves it in the 'current_dir > info' directory. The output file is named with the hostname and
    current date-time stamp. The system information is printed to this file.

    Args:
        system_info (str): System information to be printed into the output file.

    Returns:
        None
    """

    # Get the current directory of the script
    current_dir = os.path.dirname(os.path.realpath(__file__))
    info_dir = os.path.join(current_dir, "info")

    # Create 'info' directory if it does not exist
    if not os.path.exists(info_dir):
        os.makedirs(info_dir)

    # Get the hostname
    hostname = socket.gethostname()

    # Get the current date and time
    now = datetime.datetime.now()
    date_time_string = now.strftime("%Y-%m-%d_%H-%M-%S")

    # Construct the output file path
    output_file_path = os.path.join(info_dir, f"{hostname}_{date_time_string}.txt")

    # Open the output file in write mode and redirect print output to the file
    with open(output_file_path, "w") as f:
        sys.stdout = f
        print_info(system_info)
        sys.stdout = sys.__stdout__

    print(
        f"\n\033[92mExported system information successfully to: {output_file_path}\033[0m\n"
    )


@log_errors
def run_detection():
    """
    Runs the system information detection process.

    This function initializes the WMI service and performs various detections for host, account, OS, motherboard,
    CPU, RAM, GPU, storage, and NIC information. It prints status messages for each detection step and
    generates an output file containing the system information.

    Returns:
        None
    """
    system_info = {}
    wmi_service = wmi.WMI()

    def perform_detection(index, total, info_key, detection_func):
        system_info[info_key] = detection_func(wmi_service)
        message = f"[\033[92m     OK     \033[0m] \033[93m{index}/{total}\033[0m > \033[93m{datetime.datetime.now().time().strftime('%H:%M:%S')}\033[0m > {detection_func.__name__.replace('_', ' ')}"
        print(message, end="\r")
        print()

    detections = [
        ("host_info", host_detection),
        ("account_info", account_detection),
        ("os_info", os_detection),
        ("motherboard_info", motherboard_detection),
        ("cpu_info", cpu_detection),
        ("ram_info", ram_detection),
        ("gpu_info", gpu_detection),
        ("storage_info", storage_detection),
        ("nic_info", nic_detection),
    ]

    total_detections = len(detections)
    for idx, (info_key, detection_func) in enumerate(detections, start=1):
        message = f"[\033[93mINITIALIZING\033[0m] \033[93m{idx}/{total_detections}\033[0m > \033[93m{datetime.datetime.now().time().strftime('%H:%M:%S')}\033[0m > {detection_func.__name__.replace('_', ' ')}"
        print(message, end="\r")
        time.sleep(0.02)
        perform_detection(idx, total_detections, info_key, detection_func)

    # Clear the terminal
    clear_terminal()

    # Print the system info to the console
    print_info(system_info)
    generate_output(system_info)


@log_errors
def main():
    """
    Main function to run the system information detection script.

    This function clears the terminal and checks if the operating system is Windows.
    If it is, it calls the run_detection function to start the detection process.
    If it is not, it prints a message indicating that the script is only compatible
    with Windows Operating System.

    Returns:
        None
    """
    clear_terminal()
    if os.name == "nt":
        run_detection()
    else:
        print("This script is only compatible with Windows Operating System.")


if __name__ == "__main__":
    main()
