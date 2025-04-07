# XSS Scanner

A powerful Cross-Site Scripting (XSS) vulnerability scanner written in Python.

## Features

- Scan single URLs or multiple targets from a file
- Colorized output
- JSON report generation
- Smart payload reflection detection

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/xss-scanner.git
cd xss-scanner

# Install requirements
pip install -r requirements.txt
```

## Usage

```bash
# Scan a single URL
python scanner.py -t "http://example.com/?param=test"

# Scan multiple URLs from a file
python scanner.py --target-list urls.txt

# Save results to a file
python scanner.py -t "http://example.com/?param=test" --output results.json
```

## Author

Silent-Xploit
