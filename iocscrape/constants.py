import os

APP_NAME = "iocscrape"
APP_VERSION = "0.3.0"
PROJECT_URL = "https://github.com/fwalbuloushi/iocscrape"
APP_DESC = (
    "CTI tool to extract IOCs from CTI reports (URLs or files), "
    "and write them to an output file. Low-confidence items are grouped at the end."
)

DEFAULT_TIMEOUT_SEC = 15
DEFAULT_MAX_BYTES = 20 * 1024 * 1024  # 20MB
DEFAULT_REDIRECT_LIMIT = 5

IOC_TYPES_ORDER = ["url", "domain", "ipv4", "ipv6", "email", "md5", "sha1", "sha256", "cve"]

FILENAME_LIKE_EXTS = {
    "exe", "dll", "js", "vbs", "ps1", "bat", "cmd", "zip", "rar", "7z",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "png", "jpg", "jpeg", "gif", "svg", "css", "woff", "woff2", "ico",
    "conf", "cfg", "rule", "dit", "vmx",
    "py", "sh", "pl", "rs", "md", "so",     # ccTLDs that look like file extensions
}

STATIC_ASSET_EXTS = {
    "css",
    "png", "jpg", "jpeg", "gif", "svg", "webp", "bmp",   # images
    "woff", "woff2", "ttf", "eot", "otf",                 # fonts
    "ico",
}

# Cache paths
def _cache_dir() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, APP_NAME)

CACHE_DIR = _cache_dir()
CACHE_META_FILE = os.path.join(CACHE_DIR, "meta.json")
CACHE_PSL_FILE = os.path.join(CACHE_DIR, "public_suffix_list.dat")
CACHE_WARNINGLISTS_DIR = os.path.join(CACHE_DIR, "warninglists")

# Bundled data paths
PACKAGE_DIR = os.path.dirname(__file__)
BUNDLED_DATA_DIR = os.path.join(PACKAGE_DIR, "data")
BUNDLED_PSL_FILE = os.path.join(BUNDLED_DATA_DIR, "public_suffix_list.dat")
BUNDLED_WARNINGLISTS_DIR = os.path.join(BUNDLED_DATA_DIR, "warninglists")

# Remote URLs
MISP_WARNINGLISTS_ZIP = "https://github.com/MISP/misp-warninglists/archive/refs/heads/main.zip"
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
