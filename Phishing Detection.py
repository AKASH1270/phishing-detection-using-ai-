from urllib.parse import urlparse
import ipaddress
import re
from bs4 import BeautifulSoup
import whois
import urllib
import requests
from datetime import datetime

def getDomain(url):
    domain = urlparse(url).netloc
    if domain.startswith("www."):
        domain = domain.replace("www.", "")
    return domain

def havingIP(url):
    try:
        ipaddress.ip_address(url)
        return 1
    except:
        return 0

def haveAtSign(url):
    return 1 if "@" in url else 0

def getLength(url):
    return 0 if len(url) < 54 else 1

def getDepth(url):
    path_segments = urlparse(url).path.split('/')
    depth = sum(1 for segment in path_segments if segment)
    return depth

def redirection(url):
    return 1 if url.rfind('//') > 7 else 0

def httpDomain(url):
    domain = urlparse(url).netloc
    return 1 if 'https' in domain else 0

shortening_services = (
    "bit.ly|goo.gl|shorte.st|ow.ly|t.co|tinyurl|adf.ly|..."
)  # Truncated for brevity

def tinyURL(url):
    return 1 if re.search(shortening_services, url) else 0

def prefixSuffix(url):
    return 1 if '-' in urlparse(url).netloc else 0

def web_traffic(url):
    try:
        url = urllib.parse.quote(url)
        rank = BeautifulSoup(
            urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml"
        ).find("REACH")["RANK"]
        rank = int(rank)
        return 1 if rank < 100000 else 0
    except:
        return 1

def domainAge(domain_name):
    try:
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date
        if isinstance(creation_date, str):
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
        if isinstance(expiration_date, str):
            expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')
        if not creation_date or not expiration_date:
            return 1
        domain_age = abs((expiration_date - creation_date).days)
        return 1 if (domain_age / 30) < 6 else 0
    except:
        return 1

def domainEnd(domain_name):
    try:
        expiration_date = domain_name.expiration_date
        if isinstance(expiration_date, str):
            expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')
        if not expiration_date:
            return 1
        today = datetime.now()
        remaining_days = abs((expiration_date - today).days)
        return 1 if (remaining_days / 30) < 6 else 0
    except:
        return 1

def iframe(response):
    return 1 if response == "" or not re.findall(r"[<iframe>|<frameBorder>]", response.text) else 0

def mouseOver(response):
    return 1 if response == "" or re.findall("<script>.+onmouseover.+</script>", response.text) else 0

def rightClick(response):
    return 1 if response == "" or not re.findall(r"event.button ?== ?2", response.text) else 0

def forwarding(response):
    return 1 if response == "" or len(response.history) > 2 else 0

def featureExtractions(url):
    features = [
        getDomain(url),
        havingIP(url),
        haveAtSign(url),
        getLength(url),
        getDepth(url),
        redirection(url),
        httpDomain(url),
        prefixSuffix(url),
        tinyURL(url)
    ]

    dns = 0
    try:
        domain_name = whois.whois(urlparse(url).netloc)
    except:
        dns = 1

    features.append(dns)
    features.append(web_traffic(url))
    features.append(1 if dns == 1 else domainAge(domain_name))
    features.append(1 if dns == 1 else domainEnd(domain_name))

    try:
        response = requests.get(url)
    except:
        response = ""

    features.append(iframe(response))
    features.append(mouseOver(response))
    features.append(rightClick(response))
    features.append(forwarding(response))

    return features


# Example usage
#url = "http://www.bowen.edu.ng/degree-programme/"
#bob = featureExtractions(url)
#print(bob)
