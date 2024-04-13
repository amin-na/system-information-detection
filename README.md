# System Information Detection Script

This Python script utilizes Windows Management Instrumentation (WMI) to detect various system information and logs any errors encountered during the detection process.

## Features

- Detects host information such as hostname, username, and domain.
- Retrieves operating system details including install date, name, architecture, version, and version info.
- Identifies user account information, excluding specified accounts.
- Retrieves motherboard information such as manufacturer, model, and serial number.
- Detects CPU information including name, max clock speed, cores, and threads.
- Retrieves RAM information including capacity, manufacturer, and speed.
- Identifies GPU information including name.
- Detects storage information including device name, size, type, and partitions.
- Retrieves network interface card (NIC) information including description, IP address, subnet mask, default gateway, DNS servers, and DHCP status.

## Requirements

- Python 3.x
- Windows Operating System

## Installation

1. Clone the repository to your local machine:
   ```
   git clone https://github.com/amin-na/system-information-detection.git
   ```

2. Navigate to the project directory:
   ```
   cd system-information-detection
   ```

3. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

- To use the script, run the following command:
   ```
   python system_info_detection.py
   ```
- The script will detect the system information and output the results to the console.

## Contributing

- Contributions are welcome! If you'd like to contribute to this project, please fork the repository, make your changes, and submit a pull request.

## License

- This project is licensed under the MIT License.

## Author

- Amin Nazeri <amin.nazeri@hotmail.com>
