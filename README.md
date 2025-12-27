# iocscrape

Extract IOCs (URLs, domains, IPs, hashes, CVEs) from a URL or a file.

## Install

### Recommended (pipx)
pipx install iocscrape

### pip
python3 -m pip install iocscrape

## Usage

iocscrape --url https://example.com/article --out output.txt
iocscrape --file /path/report.pdf --out output.txt
iocscrape --url https://example.com/article --out output.json --format json

## Notes

- Output may include false positives. Review before ingesting.
- Non-public IPs are excluded by default and listed in the output with reasons.
