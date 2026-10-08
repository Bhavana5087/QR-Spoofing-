import ipaddress
import re
import socket
import urllib.request
import warnings
from datetime import date, datetime
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from googlesearch import search
import whois

# Suppress warnings
warnings.filterwarnings('ignore')

# The exact ordered 30 features matching the schema of phishing.csv
FEATURE_NAMES = [
    "UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting//", 
    "PrefixSuffix-", "SubDomains", "HTTPS", "DomainRegLen", "Favicon", 
    "NonStdPort", "HTTPSDomainURL", "RequestURL", "AnchorURL", "LinksInScriptTags", 
    "ServerFormHandler", "InfoEmail", "AbnormalURL", "WebsiteForwarding", "StatusBarCust", 
    "DisableRightClick", "UsingPopupWindow", "IframeRedirection", "AgeofDomain", "DNSRecording", 
    "WebsiteTraffic", "PageRank", "GoogleIndex", "LinksPointingToPage", "StatsReport"
]

class FeatureExtraction:
    def __init__(self, url):
        self.features = []
        self.url = url.strip()
        self.domain = ""
        self.whois_response = None
        self.urlparse = None
        self.response = None
        self.soup = None
        self.is_non_url = False

        # ✅ Detect if it's NOT a normal web URL (UPI, plain text, etc.)
        # Non-URLs will bypass the classifier
        if not re.match(r'^(https?|ftp)://', self.url, re.IGNORECASE):
            self.is_non_url = True
            self.features = [0] * 30
            return

        # Parse URL structure safely
        try:
            self.urlparse = urlparse(self.url)
            self.domain = self.urlparse.hostname or self.urlparse.netloc or ""
            # Strip port if present in domain
            if ":" in self.domain:
                self.domain = self.domain.split(":")[0]
        except Exception:
            self.domain = ""

        # Fetch webpage source with timeout to prevent server hangs
        try:
            self.response = requests.get(self.url, timeout=3, headers={"User-Agent": "AegisShield-Threat-Scanner/1.0"})
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except Exception:
            self.response = None
            self.soup = None

        # Fetch WHOIS response safely
        if self.domain:
            try:
                self.whois_response = whois.whois(self.domain)
            except Exception:
                self.whois_response = None

        # Build feature mapping methods
        feature_methods = {
            "UsingIP": self.UsingIp,
            "LongURL": self.longUrl,
            "ShortURL": self.shortUrl,
            "Symbol@": self.symbol,
            "Redirecting//": self.redirecting,
            "PrefixSuffix-": self.prefixSuffix,
            "SubDomains": self.SubDomains,
            "HTTPS": self.Hppts,
            "DomainRegLen": self.DomainRegLen,
            "Favicon": self.Favicon,
            "NonStdPort": self.NonStdPort,
            "HTTPSDomainURL": self.HTTPSDomainURL,
            "RequestURL": self.RequestURL,
            "AnchorURL": self.AnchorURL,
            "LinksInScriptTags": self.LinksInScriptTags,
            "ServerFormHandler": self.ServerFormHandler,
            "InfoEmail": self.InfoEmail,
            "AbnormalURL": self.AbnormalURL,
            "WebsiteForwarding": self.WebsiteForwarding,
            "StatusBarCust": self.StatusBarCust,
            "DisableRightClick": self.DisableRightClick,
            "UsingPopupWindow": self.UsingPopupWindow,
            "IframeRedirection": self.IframeRedirection,
            "AgeofDomain": self.AgeofDomain,
            "DNSRecording": self.DNSRecording,
            "WebsiteTraffic": self.WebsiteTraffic,
            "PageRank": self.PageRank,
            "GoogleIndex": self.GoogleIndex,
            "LinksPointingToPage": self.LinksPointingToPage,
            "StatsReport": self.StatsReport
        }

        # Extract features ensuring exact order and bounds
        self.features = []
        for name in FEATURE_NAMES:
            method = feature_methods[name]
            try:
                val = method()
                # Enforce valid category range: -1 (phishing), 0 (suspicious), 1 (legitimate)
                if val not in [-1, 0, 1]:
                    val = 1
                self.features.append(val)
            except Exception:
                self.features.append(-1)  # Fallback to suspicious/phishing on failure

        # Strict validation
        assert len(self.features) == 30, f"Expected 30 features, got {len(self.features)}"

    # === 1. Using IP ===
    def UsingIp(self):
        try:
            # Safely parse hostname from domain or urlparse
            hostname = self.domain
            if not hostname and self.urlparse:
                hostname = self.urlparse.hostname or self.urlparse.netloc
            if not hostname:
                return 1
            # Strip brackets from IPv6 hostnames if present (e.g. [2001:db8::1])
            if hostname.startswith('[') and hostname.endswith(']'):
                hostname = hostname[1:-1]
            
            ipaddress.ip_address(hostname)
            return -1  # Phishing if URL contains an IP address
        except Exception:
            return 1   # Legitimate

    # === 2. Long URL ===
    def longUrl(self):
        if len(self.url) < 54:
            return 1
        elif len(self.url) <= 75:
            return 0
        return -1

    # === 3. Short URL ===
    def shortUrl(self):
        match = re.search(
            r'bit\.ly|goo\.gl|tinyurl|t\.co|ow\.ly|is\.gd|bit\.do|lnkd\.in|db\.tt|qr\.ae|adf\.ly|tinyurl\.com|bitly\.com',
            self.url, re.I)
        return -1 if match else 1

    # === 4. Symbol @ ===
    def symbol(self):
        return -1 if "@" in self.url else 1

    # === 5. Redirecting (//) ===
    def redirecting(self):
        # Checks if last occurrence of '//' is after the protocol prefix
        return -1 if self.url.rfind('//') > 7 else 1

    # === 6. Prefix/Suffix (- in domain) ===
    def prefixSuffix(self):
        return -1 if "-" in self.domain else 1

    # === 7. SubDomains ===
    def SubDomains(self):
        try:
            domain = self.domain
            if domain.startswith("www."):
                domain = domain[4:]
            dots = domain.count('.')
            if dots <= 1:
                return 1
            elif dots == 2:
                return 0
            else:
                return -1
        except Exception:
            return -1

    # === 8. HTTPS ===
    def Hppts(self):
        try:
            if self.urlparse and self.urlparse.scheme == 'https':
                return 1
            return -1
        except Exception:
            return -1

    # === 9. DomainRegLen ===
    def DomainRegLen(self):
        try:
            if not self.whois_response:
                return -1
            exp = self.whois_response.expiration_date
            cre = self.whois_response.creation_date
            if not exp or not cre:
                return -1
            if isinstance(exp, list): exp = exp[0]
            if isinstance(cre, list): cre = cre[0]
            
            diff_days = (exp - cre).days
            return 1 if diff_days >= 365 else -1
        except Exception:
            return -1

    # === 10. Favicon ===
    def Favicon(self):
        try:
            if not self.soup:
                return -1
            for link in self.soup.find_all('link', rel=re.compile(r'icon', re.I)):
                href = link.get('href', '')
                if not href:
                    continue
                parsed_href = urlparse(href)
                if parsed_href.netloc and parsed_href.netloc != self.domain:
                    return -1
            return 1
        except Exception:
            return -1

    # === 11. NonStdPort ===
    def NonStdPort(self):
        try:
            if self.urlparse:
                port = self.urlparse.port
                if port is None or port in [80, 443]:
                    return 1
            return -1
        except Exception:
            return -1

    # === 12. HTTPSDomainURL ===
    def HTTPSDomainURL(self):
        return -1 if 'https' in self.domain.lower() else 1

    # === 13. RequestURL ===
    def RequestURL(self):
        try:
            if not self.soup:
                return -1
            i, success = 0, 0
            for tag in ['img', 'audio', 'embed', 'iframe']:
                for element in self.soup.find_all(tag, src=True):
                    src = element['src']
                    parsed_src = urlparse(src)
                    if not parsed_src.netloc or parsed_src.netloc == self.domain:
                        success += 1
                    i += 1
            if i == 0:
                return 1
            external_pct = (1.0 - (success / float(i))) * 100.0
            if external_pct < 22.0:
                return 1
            elif external_pct < 61.0:
                return 0
            else:
                return -1
        except Exception:
            return -1

    # === 14. AnchorURL ===
    def AnchorURL(self):
        try:
            if not self.soup:
                return -1
            i, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                href = a['href'].strip()
                if href.startswith('#') or href.startswith('javascript:') or href.startswith('mailto:') or not (self.domain in href or href.startswith('/') or href.startswith('.')):
                    unsafe += 1
                i += 1
            if i == 0:
                return 1
            unsafe_pct = (unsafe / float(i)) * 100.0
            if unsafe_pct < 31.0:
                return 1
            elif unsafe_pct < 67.0:
                return 0
            else:
                return -1
        except Exception:
            return -1

    # === 15. LinksInScriptTags ===
    def LinksInScriptTags(self):
        try:
            if not self.soup:
                return -1
            i, external = 0, 0
            for tag in ['meta', 'script', 'link']:
                for element in self.soup.find_all(tag):
                    href = element.get('href') or element.get('src')
                    if href:
                         i += 1
                         parsed_href = urlparse(href)
                         if parsed_href.netloc and parsed_href.netloc != self.domain:
                              external += 1
            if i == 0:
                return 1
            pct = (external / float(i)) * 100.0
            if pct < 17.0:
                return 1
            elif pct <= 81.0:
                return 0
            else:
                return -1
        except Exception:
            return -1

    # === 16. ServerFormHandler ===
    def ServerFormHandler(self):
        try:
            if not self.soup:
                return -1
            forms = self.soup.find_all('form', action=True)
            if not forms:
                return 1
            for form in forms:
                action = form['action'].strip()
                if action == "" or action.lower() == "about:blank":
                    return -1
                parsed_action = urlparse(action)
                if parsed_action.netloc and parsed_action.netloc != self.domain:
                    return 0
            return 1
        except Exception:
            return -1

    # === 17. InfoEmail ===
    def InfoEmail(self):
        try:
            if "mailto:" in self.url.lower():
                return -1
            if self.response and "mailto:" in self.response.text.lower():
                return -1
            return 1
        except Exception:
            return -1

    # === 18. AbnormalURL ===
    def AbnormalURL(self):
        try:
            if not self.whois_response:
                return -1
            whois_domain = self.whois_response.domain_name
            if isinstance(whois_domain, list):
                whois_domains = [d.lower() for d in whois_domain]
            elif isinstance(whois_domain, str):
                whois_domains = [whois_domain.lower()]
            else:
                whois_domains = []
            
            if self.domain.lower() in whois_domains or any(self.domain.lower() in d for d in whois_domains):
                return 1
            return -1
        except Exception:
            return -1

    # === 19. WebsiteForwarding ===
    def WebsiteForwarding(self):
        try:
            if not self.response:
                return 0
            redirects = len(self.response.history)
            if redirects <= 1:
                return 1
            elif redirects <= 3:
                return 0
            else:
                return -1
        except Exception:
            return -1

    # === 20. StatusBarCust ===
    def StatusBarCust(self):
        try:
            if not self.response:
                return -1
            if "window.status" in self.response.text:
                return -1
            if self.soup:
                for element in self.soup.find_all(onmouseover=True):
                    if "window.status" in element['onmouseover'] or "status" in element['onmouseover']:
                        return -1
            return 1
        except Exception:
            return -1

    # === 21. DisableRightClick ===
    def DisableRightClick(self):
        try:
            if not self.response:
                return -1
            text = self.response.text.lower()
            if "event.button==2" in text or "event.button == 2" in text or "contextmenu" in text:
                if "preventdefault" in text:
                    return -1
            return 1
        except Exception:
            return -1

    # === 22. UsingPopupWindow ===
    def UsingPopupWindow(self):
        try:
            if not self.response:
                return -1
            text = self.response.text.lower()
            if "prompt(" in text or "window.open(" in text:
                return -1
            return 1
        except Exception:
            return -1

    # === 23. IframeRedirection ===
    def IframeRedirection(self):
        try:
            if not self.soup:
                return -1
            if self.soup.find('iframe'):
                return -1
            return 1
        except Exception:
            return -1

    # === 24. AgeofDomain ===
    def AgeofDomain(self):
        try:
            if not self.whois_response:
                return -1
            cre = self.whois_response.creation_date
            if not cre:
                return -1
            if isinstance(cre, list): cre = cre[0]
            if isinstance(cre, datetime):
                cre = cre.date()
            
            age_days = (date.today() - cre).days
            return 1 if age_days >= 180 else -1
        except Exception:
            return -1

    # === 25. DNSRecording ===
    def DNSRecording(self):
        try:
            if not self.domain:
                return -1
            socket.gethostbyname(self.domain)
            return 1
        except Exception:
            return -1

    # === 26. WebsiteTraffic ===
    def WebsiteTraffic(self):
        try:
            # Fallback heuristic: Common legitimate domains
            common_domains = {'google.com', 'youtube.com', 'facebook.com', 'baidu.com', 'wikipedia.org', 'yahoo.com', 'amazon.com', 'twitter.com', 'instagram.com'}
            if any(self.domain.endswith(d) for d in common_domains):
                return 1
            return -1
        except Exception:
            return -1

    # === 27. PageRank ===
    def PageRank(self):
        try:
            common_domains = {'google.com', 'youtube.com', 'facebook.com', 'wikipedia.org', 'yahoo.com', 'amazon.com', 'twitter.com'}
            if any(self.domain.endswith(d) for d in common_domains):
                return 1
            return -1
        except Exception:
            return -1

    # === 28. GoogleIndex ===
    def GoogleIndex(self):
        try:
            res = search(self.domain, num_results=1)
            if list(res):
                return 1
            return -1
        except Exception:
            return -1

    # === 29. LinksPointingToPage ===
    def LinksPointingToPage(self):
        try:
            if not self.soup:
                return -1
            links = len(self.soup.find_all('a', href=True))
            if links == 0:
                return -1
            elif links <= 2:
                return 0
            else:
                return 1
        except Exception:
            return -1

    # === 30. StatsReport ===
    def StatsReport(self):
        try:
            # Check if domain/url contains common phishing indicators
            indicators = ['secure', 'login', 'verify', 'update', 'banking', 'signin', 'account']
            if any(ind in self.url.lower() for ind in indicators):
                return -1
            return 1
        except Exception:
            return -1

    # === Get Feature List ===
    def getFeaturesList(self):
        return self.features
