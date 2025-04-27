import validators
import logging
from urllib.parse import urlparse
import ipaddress
import re
from bs4 import BeautifulSoup
import whois
import requests
from datetime import datetime

logger = logging.getLogger(__name__)

class DETECTION:
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                          r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                          r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                          r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                          r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                          r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                          r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                          r"tr\.im|link\.zip\.net"

    def __init__(self):
        # Initialization code (if needed)
        pass

    def getDomain(self, url):
        domain = urlparse(url).netloc
        if re.match(r"^www.", domain):
            domain = domain.replace("www.", "")
        return domain

    def havingIP(self, url):
        try:
            ipaddress.ip_address(url)
            return 1
        except:
            return 0

    def haveAtSign(self, url):
        return 1 if "@" in url else 0

    def getLength(self, url):
        return 0 if len(url) < 54 else 1

    def getDepth(self, url):
        return len([part for part in urlparse(url).path.split('/') if part])

    def redirection(self, url):
        return 1 if url.rfind('//') > 7 else 0

    def httpDomain(self, url):
        return 0 if 'https' in url else 1

    def tinyURL(self, url):
        return 1 if re.search(self.shortening_services, url) else 0

    def prefixSuffix(self, url):
        return 1 if '-' in url else 0

    def web_traffic(self, url):
        try:
            url = urllib.parse.quote(url)
            rank = BeautifulSoup(urllib.request.urlopen(f"http://data.alexa.com/data?cli=10&dat=s&url={url}").read(), "xml").find("REACH")['RANK']
            return 1 if int(rank) < 100000 else 0
        except TypeError:
            return 1

    def domainAge(self, domain_name):
        try:
            creation_date = domain_name.creation_date
            expiration_date = domain_name.expiration_date
            if isinstance(creation_date, str) or isinstance(expiration_date, str):
                creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
            age = abs((expiration_date - creation_date).days) if creation_date and expiration_date else 1
            return 1 if age / 30 < 6 else 0
        except Exception as e:
            logger.error(f"Error in domainAge: {str(e)}")
            return 1

    def domainEnd(self, domain_name):
        expiration_date = domain_name.expiration_date
        try:
            if isinstance(expiration_date, str):
                expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
            end = abs((expiration_date - datetime.now()).days) if expiration_date else 1
            return 0 if end / 30 < 6 else 1
        except Exception as e:
            logger.error(f"Error in domainEnd: {str(e)}")
            return 1

    def iframe(self, response):
        return 0 if re.findall(r"[<iframe>|<frameBorder>]", response.text) else 1

    def mouseOver(self, response):
        return 1 if re.findall("<script>.+onmouseover.+</script>", response.text) else 0

    def rightClick(self, response):
        return 0 if re.findall(r"event.button ?== ?2", response.text) else 1

    def forwarding(self, response):
        return 1 if len(response.history) > 2 else 0

    def featureExtractions(self, url):
        features = [
            self.getDomain(url), self.havingIP(url), self.haveAtSign(url),
            self.getLength(url), self.getDepth(url), self.redirection(url),
            self.httpDomain(url), self.prefixSuffix(url), self.tinyURL(url)
        ]
        try:
            domain_name = whois.whois(urlparse(url).netloc)
            features.append(0)
            features.append(self.web_traffic(url))
            features.append(self.domainAge(domain_name))
            features.append(self.domainEnd(domain_name))
        except:
            features.extend([1, 0, 1, 1])
        
        try:
            response = requests.get(url)
            features.append(self.iframe(response))
            features.append(self.mouseOver(response))
            features.append(self.rightClick(response))
            features.append(self.forwarding(response))
        except:
            features.extend([1, 0, 1, 1])

        return features
#url = "https://chatgpt.com/c/67988780-41b0-8007-b51c-699fe3bb6574"
#detection = DETECTION()
#print(detection.featureExtractions(url))