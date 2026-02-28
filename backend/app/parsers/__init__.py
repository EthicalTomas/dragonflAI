from backend.app.parsers.subfinder_parser import parse_subfinder_output
from backend.app.parsers.httpx_parser import parse_httpx_output
from backend.app.parsers.nmap_parser import parse_nmap_output
from backend.app.parsers.burp_parser import parse_burp_xml
from backend.app.parsers.zap_parser import parse_zap_json, parse_zap_xml

PARSER_REGISTRY = {
    "subfinder": parse_subfinder_output,
    "httpx": parse_httpx_output,
    "nmap": parse_nmap_output,
    "burp": parse_burp_xml,
    "zap_json": parse_zap_json,
    "zap_xml": parse_zap_xml,
}
