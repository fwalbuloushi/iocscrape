# iocscrape
[![PyPI version](https://img.shields.io/pypi/v/iocscrape.svg)](https://pypi.org/project/iocscrape/)
![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Category](https://img.shields.io/badge/Category-CTI-orange)

**CTI tool to extract IOCs from CTI reports (URLs or files)**  
IOC extraction is **best-effort** and may produce **false positives** - always review before ingestion.



## Links

- GitHub: https://github.com/fwalbuloushi/iocscrape
- PyPI: https://pypi.org/project/iocscrape/



## Features

- Extract IOCs from:
  - **URLs** (CTI articles / reports)
  - **Files**: `txt`, `html`, `pdf`, `docx`, `xlsx`
- Uses **trafilatura** to convert web pages into clean text (reduces noise from hidden links / menus / assets).
- Groups suspicious/noisy matches into **Low-Confidence (Review)** using:
  - **Public Suffix List (PSL)** validation
  - **MISP warninglists** (vendored snapshot + optional `--update`)
  - filename-like domain detection (e.g. `something.png`)
  - static asset URL detection (e.g. `.png`, `.css`, `.woff2`)
- Output formats:
  - Default: **TXT** (pixhash-like run log style)
  - Optional: **JSON**
- `--update` updates **both**: **warninglists + PSL**



## Installation

### Option 1: pipx (recommended)
```bash
python3 -m pip install --user pipx
python3 -m pipx ensurepath
pipx install iocscrape
```

### Option 2:
```bash
pip install iocscrape
```



## Usage

### Extract from URL
```bash
iocscrape --url "https://example.com/report" --out output.txt
```

### Extract from File
```bash
iocscrape --file "/path/report.pdf" --out output.txt
```

### JSON Output
```bash
iocscrape --url "https://example.com/report" --out output.json --format json
```



## Updating datasets (Warninglists + PSL)
By default, iocscrape ships with a vendored snapshot of:
* MISP warninglists, and
* Public Suffix List (PSL).

To update them:
```bash
iocscrape --update
```

To update + run extraction in one command:
```bash
iocscrape --update --url "https://example.com/report" --out output.txt
```

Cache location:
`~/.cache/iocscrape`



## Supported IOC Types
* URL
* Domain
* IPv4
* IPv6
* Email
* MD5
* SHA1
* SHA256
* CVE



## Output

### 1. TXT (Default)
The output file is a run log:
* **Results** section contains "high-confidence" IOCs
* **Low-Condidence (Review)** section contains items flagged by:
    * Warninglists match
    * PSL invalid suffix
    * Filename-like "domain"
    * Static asset URL

Example structure:
```markdown
iocscrape Run Log
=================

[#] Target:       ...
[#] Date:         ...
[#] Time:         ...
[#] User-Agent:   ...
[#] Output File:  ...

-------
Results
-------

[#] URL (..)
...

-----------------------
Low-Confidence (Review)
-----------------------

[#] DOMAIN (..)
value >> reason
```

### 2. JSON
Contains:
* Counts per IOC type
* IOC by type
* Low-confidence array with reasons



## Notes on False Positives

This tool uses regex-based extraction. It can still pick up:
* File names that look like domains
* Configuration keys
* Benign public infrastructure (flagged via warninglists / PSL into low-confidence)

**Always review the output before operational ingestion** (SIEM/Blocklists/EDR/Firewall... etc.).



## License

MIT License. See `LICENSE`.



## Contributing

Issues/PRs are welcomed:
* [https://github.com/fwalbuloushi/iocscrape/issues](https://github.com/fwalbuloushi/iocscrape/issues)
