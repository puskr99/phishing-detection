import time
from urllib.parse import urlparse
import socket
import whois
import dns.resolver
from datetime import datetime

EXPECTED_FEATURES = [
    'qty_slash_url', 'length_url', 'qty_dot_directory', 'qty_hyphen_directory',
    'qty_underline_directory', 'qty_questionmark_directory', 'directory_length',
    'qty_hyphen_file', 'file_length', 'qty_dot_params', 'qty_underline_params',
    'asn_ip', 'time_domain_activation', 'time_domain_expiration', 'ttl_hostname',
]


def extract_url_features(url, callback=None):
    """
    Extract features from the given URL. Ensures features match EXPECTED_FEATURES.
    """
    parsed_url = urlparse(url)
    path = parsed_url.path
    params = parsed_url.query
    features = {}

        # Define feature extraction steps
    steps = [
        ("Extracting slash count...", lambda: url.count("/"), 'qty_slash_url'),
        ("Calculating URL length...", lambda: len(url), 'length_url'),
        ("Counting dots in directory...", lambda: path.count("."), 'qty_dot_directory'),
        ("Counting hyphens in directory...", lambda: path.count("-"), 'qty_hyphen_directory'),
        ("Counting underscores in directory...", lambda: path.count("_"), 'qty_underline_directory'),
        ("Counting question marks in directory...", lambda: path.count("?"), 'qty_questionmark_directory'),
        ("Calculating directory length...", lambda: len(path), 'directory_length'),
        ("Counting hyphens in file name...", lambda: parsed_url.path.split("/")[-1].count("-"), 'qty_hyphen_file'),
        ("Calculating file name length...", lambda: len(parsed_url.path.split("/")[-1]), 'file_length'),
        ("Counting dots in parameters...", lambda: params.count("."), 'qty_dot_params'),
        ("Counting underline in parameters...", lambda: params.count("_"), 'qty_underline_params'),
        ("Fetching TTL...", lambda: get_ttl(url, callback), 'ttl_hostname'),
        ("Fetching ASN...", lambda: get_asn(url, callback), 'asn_ip'),
        ("Fetching domain activation time...", lambda: get_domain_activation(url), 'time_domain_activation'),
        ("Fetching domain expiration time...", lambda: get_domain_expiration(url), 'time_domain_expiration'),
    ]


    for message, func, feature_name in steps:
        if callback:
            callback(message)
        time.sleep(0.2)  # Simulate delay
        try:
            features[feature_name] = func()
        except Exception as e:
            features[feature_name] = -1  # Default value for missing features
            if callback:
                callback(f"Error in {feature_name}: {e}")

    # Ensure all features match the EXPECTED_FEATURES order
    ordered_features = {key: features.get(key, -1) for key in EXPECTED_FEATURES}
    print("Ordered", ordered_features)
    return ordered_features


from ipwhois import IPWhois
def get_asn(url, callback=None):
    """
    Resolve the domain to fetch the ASN (Autonomous System Number).
    """
    try:
        # Parse the URL to extract the domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Remove 'www.' if present
        if domain.startswith("www."):
            domain = domain[4:]

        if callback:
            callback(f"Resolving domain: {domain}")

        # Resolve domain to IP address
        ip_address = socket.gethostbyname(domain)
        if callback:
            callback(f"Resolved IP address: {ip_address}")

        # Perform IP Whois lookup
        obj = IPWhois(ip_address)
        results = obj.lookup_rdap()
        asn = results.get("asn", -1)

        if callback:
            callback(f"ASN fetched: {asn}")
        return asn
    except Exception as e:
        if callback:
            callback(f"Error fetching ASN: {e}")
        return -1

def get_ttl(url, callback=None):
    """
    Fetch the TTL (Time-To-Live) value from DNS records.
    """
    try:
        domain = urlparse(url).netloc
        if callback:
            callback("Fetching TTL from DNS records...")
        answers = dns.resolver.resolve(domain, "A")
        return answers.rrset.ttl
    except Exception as e:
        if callback:
            callback(f"Error fetching TTL: {e}")
        return -1


def get_domain_activation(url):
    """
    Fetch the domain activation time using WHOIS.
    """
    try:
        # Parse the URL to extract the domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Remove 'www.' if present
        if domain.startswith("www."):
            domain = domain[4:]

        print(f"Extracted domain: {domain}")

        # Fetch WHOIS information
        domain_info = whois.whois(domain)
        print("Domain info:", domain_info)

        # Get creation date
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]  # Handle case with multiple entries

        if creation_date:
            return (datetime.now() - creation_date).days
        else:
            return -1
    except Exception as e:
        print(f"Error in get_domain_activation: {e}")
        return -1


def get_domain_expiration(url):
    """
    Fetch the domain expiration time using WHOIS.
    """
    try:
        # Parse the URL to extract the domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Remove 'www.' if present
        if domain.startswith("www."):
            domain = domain[4:]

        print(f"Extracted domain: {domain}")

        # Fetch WHOIS information
        domain_info = whois.whois(domain)
        print("Domain info:", domain_info)

        # Get creation date
        expiration_date = domain_info.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]  # Handle case with multiple entries

        if expiration_date:
            return (expiration_date - datetime.now()).days
        else:
            return -1
    except Exception as e:
        print(f"Error in get_domain_activation: {e}")
        return -1
