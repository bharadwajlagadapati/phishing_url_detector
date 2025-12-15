from urllib.parse import urlparse
from rapidfuzz import fuzz
import pandas as pd
import tldextract
import ipaddress
import re


brand_list= {"Microsoft", "Google", "Apple", "Amazon", "PayPal", "Facebook", "WhatsApp", "LinkedIn", "Adobe", "DHL", "Spotify", "Mastercard", "Alibaba", "OneDrive", "Okta", "SharePoint", "Telegram", "pCloud", "FedEx", "Ebay", "Netflix", "Instagram", "Wells Fargo", "Airbnb", "Steam", "Dropbox", "DocuSign", "Visa", "Outlook", "Yahoo", "Chase Bank", "Bank of America", "HSBC", "ING", "Sparkasse", "Credit Agricole", "American Express", "Rakuten", "SoftBank", "Orange", "Comcast", "UPS", "USPS", "JCB", "Banco Bradesco", "Caixa Economica Federal", "MUFG", "SMBC", "Nubank", "Bank Millennium", "Allegro", "InPost", "Correos", "DPD", "SFR", "Santander", "Credit Saison", "ANZ Bank", "PayU", "Itau Unibanco", "Walmart", "Best Buy", "Nike", "Disney", "Office 365", "Google Workspace", "Google Drive", "YouTube", "Slack", "GitHub", "GitLab", "Bitbucket", "Stripe", "Coinbase", "Crypto.com", "Binance", "Paytm", "Zimbra", "IBM", "Salesforce", "Oracle", "Zoom", "Microsoft Teams", "T-Mobile", "AT&T", "Verizon", "Singtel", "Optus", "Naver", "WeTransfer", "Reddit", "TikTok", "Pinterest", "Snapchat", "Mailchimp", "OVH", "DigitalOcean", "Linode", "GoDaddy", "Shopify", "AliExpress", "Booking.com", "Expedia"}


shortening_services = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "buff.ly", "ow.ly",
    "rebrand.ly", "cutt.ly", "tiny.cc", "bit.do", "v.gd", "t.ly", "shorte.st",
    "bl.ink", "soo.gd", "shorturl.at", "adf.ly", "lc.chat", "clk.im",
    "ulvis.net", "chilp.it", "x.co", "rb.gy", "yourls.org", "qr.ae",
    "s.id", "hyperurl.co", "lnkd.in", "fur.ly", "tr.im", "lnkfi.re",
    "snip.ly", "ht.ly", "short.cm", "shrtcode.org", "po.st", "bc.vc",
    "ity.im", "2.gp", "v.ht", "t2m.io", "u.to", "kutt.it", "gg.gg",
    "urlzs.com", "tny.im", "hid.li", "b.link"
}

free_hosts = {
    "000webhost",      # 000webhost.com
    "pages.dev",       # GitHub Pages (pages.dev)
    "github.io",       # GitHub Pages
    "netlify.app",     # Netlify free hosting
    "herokuapp.com",   # Heroku free tier
    "glitch.me",       # Glitch free hosting
    "vercel.app",      # Vercel free tier
    "wixsite.com",     # Wix free plan
    "weebly.com",      # Weebly free plan
    "wordpress.com",   # WordPress free hosting
    "blogspot.com",    # Blogger free hosting
    "tumblr.com",      # Tumblr blogs
    "neocities.org",   # Neocities free hosting
    "surge.sh",        # Surge static hosting
    "gitlab.io",       # GitLab Pages
    "freesite.host",   # Generic free hosting service
    "0000free.com",    # Another free host
    "awardspace.com",  # Free hosting plan
    "byethost.com",    # Free hosting
    "altervista.org"   # Free hosting in Europe
}

suspicious_tlds = {
    "xyz", "top", "club", "online", "site",
    "shop", "fun", "cyou", "info", "rest",
    "link", "click", "work", "fit", "tokyo",
    "gq", "ml", "tk", "cf", "buzz"
    }


def clean_url(url):
    url = str(url).strip()  # remove leading/trailing spaces
    # Remove malformed brackets that break urlparse
    url = re.sub(r"\[.*?\]", "", url)
    # Add scheme if missing (urlparse fails without scheme)
    if not re.match(r"^https?://", url):
        url = "http://" + url
    return url
# print(clean_url("webmailadmin0.myfreesites.net/	  "))

def has_gibberish_token(host):
    tokens = re.split(r"[.\-]", host)
    return 1 if any(len(t) >= 10 and not t.isalpha() for t in tokens) else 0

def safe_parse_url(url):
    try:
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        domain = ext.domain or ""
        subdomain = ext.subdomain or ""
        suffix = ext.suffix or ""
        return hostname, path, query, domain, subdomain, suffix
    except Exception:
        # Return empty strings if parsing fails
        return "", "", "", "", "", ""



def has_ip(url):
    host = urlparse(url).hostname
    if not host:
        return 0

    # Remove brackets for IPv6 addresses
    host = host.strip('[]')

    try:
        ipaddress.ip_address(host)
        return 1
    except ValueError:
        return 0





### ---------- Helper Functions ---------- ###


def clean_text(x):
    if x is None:
        return ""
    return x.lower()
def match_score(brand,part):
    return 85<=fuzz.ratio(brand,part)<=100

### ---------- D1 – D6 Feature Extraction ---------- ###

def extract_bad_domain_features(url, brand_list):
    
    hostname, path, query, domain, subdomain, suffix = safe_parse_url(url)

    # Convert everything to lowercase
    path = clean_text(path)
    query = clean_text(query)
    domain = clean_text(domain)
    subdomain = clean_text(subdomain)
    suffix = clean_text(suffix)

    ### ---------------------------------------------------------
    ### D1: Brand in Path or Query (1 if brand appears here)
    ### ---------------------------------------------------------
    D1 = 0
    for brand in brand_list:
        b = brand.lower()
        if b in path or b in query:
            D1 = 1
            break

    ### ---------------------------------------------------------
    ### D2: Brand in Subdomain
    ### Detect exact brand OR brand substring OR misspellings
    ### ---------------------------------------------------------
    D2 = 0
    sub_parts = re.split(r"[.-]", subdomain)
    for brand in brand_list:
        b = brand.lower()

        # exact match or substring in subdomain
        if b in subdomain:
            D2 = 1
            break

        # fuzzy match on each token to catch typos
        for part in sub_parts:
            score = fuzz.ratio(part, b)
            if 85 <= score <= 100:
                D2 = 1
                break
        if D2 == 1:
            break


    ### ---------------------------------------------------------
    ### D3: Brand as Substring in Primary Domain
    ### ---------------------------------------------------------
    D3 = 0
    tokens = re.split(r"[-0-9]+", domain)

    for brand in brand_list:
        b = brand.lower()

        # A) Exact brand match → legitimate, so skip
        if domain == b:
            D3 = 0
            break  # exact match, not phishing

        # B) Brand as token in domain → suspicious
        if b in tokens:
            D3 = 1
            break

        # C) Brand substring inside domain → suspicious
        if b in domain and domain != b:
            D3 = 1

        # D) Typosquatting similarity → suspicious
        for part in tokens:
            if match_score(b,part):
                D3 = 1
                break
        sim = fuzz.ratio(domain, b)
        if 85 <= sim <= 100:
            D3 = 1



    ### ---------------------------------------------------------
    ### D4: Brand Typo in Domain
    ### e.g., amaz0nn, pay-pal-secure, fac3book-shop, etc.
    ### fuzzy threshold = >=85 but NOT equal 100
    ### ---------------------------------------------------------
    D4 = 0
    for brand in brand_list:
        b = brand.lower()

        # fuzzy typo detection
        score = fuzz.ratio(domain, b)
        if score >= 85 and score != 100:
            D4 = 1
            break

    ### ---------------------------------------------------------
    ### D5: Fake TLD
    ### suspicious TLD used for brandlike domain
    ### e.g., brand.cyou, brand.top, brand.xyz, brand.shop
    ### ---------------------------------------------------------


    D5 = 1 if (suffix in suspicious_tlds) else 0

    ### ---------------------------------------------------------
    ### D6: IP Address Usage
    ### ---------------------------------------------------------
    D6 = has_ip(url)

    ### Return all features
    return {
        "D1": D1,
        "D2": D2,
        "D3": D3,
        "D4": D4,
        "D5": D5,
        "D6": D6
    }



# Remove www for consistency
from urllib.parse import urlparse

def remove_www_prefix(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc

        if domain.startswith("www."):
            domain = domain[4:]

        return parsed._replace(netloc=domain).geturl()
    except:
        return url


mean_url_len = 32.84
mean_domain_len = 17.45

def extract_features(url):
    url=clean_url(url)
    url=remove_www_prefix(url)
    hostname, path, query, domain, subdomain, suffix = safe_parse_url(url)

    # Now you can safely compute D1-D5 and L1-L19
    # For example:
    D1,D2,D3,D4,D5,D6=extract_bad_domain_features(url, brand_list).values()
    L1 = 1 if re.search(r'//', urlparse(url).path) else 0
    L2 = has_ip(url)
    L3 = path.count(".")
    L4 = path.count("/")
    L5 = 1 if len(url) > mean_url_len else 0
    L6 = 1 if 'http' in hostname else 0
    L7 = 1 if '-' in domain or '_' in domain else 0
    L8 = 1 if any(c.isdigit() for c in hostname) else 0
    L9 = hostname.count(".")
    tokens = re.split(r"[.\-]", hostname)
    L10 = max(len(t) for t in tokens) if tokens else 0
    L11 = 1 if any(s in url for s in shortening_services) else 0
    L12 = 1 if len(domain) > mean_domain_len else 0
    L13 = 1 if '#' in url else 0
    L14 = 1 if "xn--" in hostname else 0
    L15 = 1 if '@' in url else 0
    L16 = has_gibberish_token(hostname)
    L17 = 1 if any(fh in url for fh in free_hosts) else 0
    L18 = sum(1 for c in url if not c.isalnum() and c not in ['.', '/', '#', '@'])
    L19 = 1 if urlparse(url).scheme == 'http' else 0

    return {
  'D1': D1, 'D2': D2, 'D3': D3, 'D4': D4, 'D5': D5, 'D6': D6,
  'L1': L1, 'L2': L2, 'L3': L3, 'L4': L4, 'L5': L5, 'L6': L6,
  'L7': L7, 'L8': L8, 'L9': L9, 'L10': L10, 'L11': L11, 'L12': L12,
  'L13': L13, 'L14': L14, 'L15': L15, 'L16': L16, 'L17': L17, 'L18': L18, 'L19': L19
}


