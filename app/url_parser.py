import socket
import whois
import dns.resolver
import requests

from urllib.parse import urlparse
from ipwhois import IPWhois


def extract_url_features(url):
    parsed_url = urlparse(url)
    
    # Path and parameters
    path = parsed_url.path
    params = parsed_url.query
    
    return {
        "qty_slash_url": url.count("/"),
        "length_url": len(url),
        "qty_dot_directory": path.count("."),
        "qty_hyphen_directory": path.count("-"),
        "qty_underline_directory": path.count("_"),
        "qty_questionmark_directory": path.count("?"),
        "directory_length": len(path),
        "qty_hyphen_file": parsed_url.path.split("/")[-1].count("-"),
        "file_length": len(parsed_url.path.split("/")[-1]),
        "qty_dot_params": params.count("."),
        "qty_underline_params": params.count("_"),
        "qty_questionmark_params": params.count("?"),
    }


def get_asn_and_ttl(url):
    try:
        # Get domain name
        domain = urlparse(url).netloc

        # Get IP address of domain
        ip_address = socket.gethostbyname(domain)

        # Get ASN using IP Whois lookup
        obj = IPWhois(ip_address)
        results = obj.lookup_rdap()
        asn = results.get("asn", -1)  # ASN number

        # Get TTL value
        answers = dns.resolver.resolve(domain, "A")
        ttl = answers.rrset.ttl

        return {"asn_ip": asn, "ttl_hostname": ttl}
    except Exception as e:
        return {"asn_ip": -1, "ttl_hostname": -1}  # Return default values in case of failure




from datetime import datetime

def get_domain_age(url):
    try:
        domain = urlparse(url).netloc
        domain_info = whois.whois(domain)

        # Get creation date
        if isinstance(domain_info.creation_date, list):
            creation_date = domain_info.creation_date[0]
        else:
            creation_date = domain_info.creation_date

        if creation_date:
            days_since_creation = (datetime.now() - creation_date).days
        else:
            days_since_creation = -1  # Unknown domain age

        return {"time_domain_activation": days_since_creation}
    except Exception as e:
        return {"time_domain_activation": -1}  # Default in case of failure



def extract_features_from_url(url):
    url_features = extract_url_features(url)
    asn_ttl_features = get_asn_and_ttl(url)
    domain_age_feature = get_domain_age(url)
    
    # Merge all extracted features into a single dictionary
    all_features = {**url_features, **asn_ttl_features, **domain_age_feature}
    
    return all_features

