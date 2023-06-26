# Process Memory Scanner

The Process Memory Scanner is a Python script that scans the memory of running processes on a Linux system using YARA rules. It helps identify processes that match specific patterns defined by the YARA rules, making it useful for security analysis and research purposes. I have created the linux/x64/meterpreter/reverse_tcp payload, dumped its data on memory and created a yara rule (thanx to yarGen project) for that so its also obfuscation resistant.

## Prerequisites

Before using the Process Memory Scanner, ensure you have the following prerequisites installed:

- Python 3.x
- `psutil` library: Install using `pip install psutil`
- `yara-python` library: Install using `pip install yara-python`

## Usage

To use the Process Memory Scanner, follow these steps:

1. If you have yara rules for memory, copy them under ./rules.
2. If you dont, just create and return to first step.
3. Run the script with root rights.

```shell
sudo python3 process_memory_scanner.py
```

4. The script will iterate over the running processes and scan their memory using the provided YARA rules.
5. If there are matches, the script will print the rule name, process ID, process name, and process path.

## Configuration

The Process Memory Scanner uses YARA rules for scanning process memory. You can customize the scanning behavior by modifying the YARA rules in the `rules/meterpreter_reverse_tcp.yar` file. Add, modify, or remove rules based on your specific requirements or just create your rules.

## Contributing

Contributions to the Process Memory Scanner project are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

There is no license.

## Acknowledgments

- The Process Memory Scanner utilizes the `psutil` and `yara-python` libraries.
- Bad hackers (you bad bois) can obfuscate their codes to escape from static scans.
- We know that every command and string must be unobfuscated when running ( "s.connect(("gyugyjg==",3141))" doesnt have a meaning). 
- Scanning memory is much more powerful way than scanning the file itself.

Feel free to customize the above template to include more details or sections based on the specific requirements and features of your project.
