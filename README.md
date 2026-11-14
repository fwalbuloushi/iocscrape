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
  - **MISP warninglists** (downloaded via `--update`, not bundled)
  - filename-like domain detection (e.g. `something.png`)
  - static asset URL detection (e.g. `.png`, `.css`, `.woff2`)
- Output formats:
  - Default: **TXT** (pixhash-like run log style)
  - Optional: **JSON**
- Bundled **PSL** snapshot; `--update` refreshes **both** warninglists + PSL



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

### First run
Download the MISP warninglists (required once, ~65 MB):
```bash
iocscrape --update
```
Without them, iocscrape still works but prints a warning and only applies
PSL, filename-like, static-asset and private-IP checks.



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
iocscrape ships with a bundled snapshot of the Public Suffix List (PSL).
MISP warninglists are **not bundled** due to their size (~65 MB) and must be
downloaded into the cache. Re-run periodically to keep both up to date:
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
* **Context** section annotates Results IOCs that sit on notable infrastructure
  (cloud/VPS hosting, Tor/VPN, dynamic DNS, URL shorteners, personal/disposable email).
  These stay in Results, the note is for the analyst.
* **Low-Confidence (Review)** section contains items flagged by:
    * Warninglists match
    * Known benign / false-positive hash (empty file, EICAR, Windows binaries...)
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

-------
Context
-------

[#] IPV4 (..)
value >> note

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
* Context array with notes



## Notes on False Positives

This tool uses regex-based extraction. It can still pick up:
* File names that look like domains
* Configuration keys
* Benign public infrastructure (flagged via warninglists / PSL into low-confidence)

**Always review the output before operational ingestion** (SIEM/Blocklists/EDR/Firewall... etc.).



## Development Notes

iocscrape has been developed with the help of AI tools, used for code review,
bug fixing and test writing. All changes are reviewed, tested and approved by
the maintainer before each release.



## License

MIT License. See `LICENSE`.



## Contributing

Issues/PRs are welcomed:
* [https://github.com/fwalbuloushi/iocscrape/issues](https://github.com/fwalbuloushi/iocscrape/issues)
