![Screenshot](https://i.imgur.com/E4xrpDo.png)

# Web Technology Detection Tool

## Overview

This tool leverages the Wappalyzer library to analyze the underlying technologies used on a specific website or a list of domains. It's designed to assist in reconnaissance and provides insights into what technologies are powering a website, including content management systems (CMS), JavaScript frameworks, web servers, analytics tools, and more.

## Dependencies

- Python 3
- concurrent.futures
- Wappalyzer
- urllib3
- argparse

To install these dependencies, run:

```bash
pip install futures python-Wappalyzer
```

## Usage

Analyze a single domain:
```
python your_script.py -d <domain> [-t <threads>] [-i] [-o <output_file>]
```

Analyze a list of domains from a file:
```
python your_script.py -f <file_path> [-t <threads>] [-i] [-o <output_file>]
```

## Parameters
```
-d, --domain: Single domain to analyze.
-f, --file: File containing list of domains to analyze.
-t, --thread: Number of threads to use (default is 1).
-i, --ignore: Ignore any errors during execution.
-o, --output: Save the results to a specified file.
```
## Example

Single domain:
```
python your_script.py -d example.com -t 5 -o results.txt
```

List of domains:
```
python your_script.py -f domains.txt -t 5 -o results.txt
```

## Output
The script prints the detected technologies for the given domain and, if specified, saves them to a file.

## Disclaimer
Ensure that you have the necessary permissions to analyze the domain. Usage of this tool should be compliant with all applicable laws.
