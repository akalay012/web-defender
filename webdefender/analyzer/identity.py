"""Identity and URL-context knowledge.

Context only. Brand/domain metadata cannot override hard threat evidence.
"""
import re

BRAND_KEYWORDS = [
    "google", "gmail", "youtube", "microsoft", "outlook", "office", "live",
    "apple", "icloud", "facebook", "instagram", "whatsapp", "meta",
    "paypal", "amazon", "aws", "netflix", "twitter", "linkedin",
    "dropbox", "github", "adobe", "steam", "ebay", "bankofamerica",
    "wellsfargo", "chase", "citibank", "garanti", "akbank", "isbank",
    "ziraatbank", "vakifbank", "halkbank", "yapikredi", "dhl",
    "fedex", "ups", "shopee", "trendyol", "hepsiburada", "aliexpress", "temu", "binance", "coinbase", "discord", "telegram", "turkiye", "saglik", "edevlet", "turknet",
    "turkcell", "vodafone", "turktelekom", "btk", "ing",
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".online",
    ".site", ".store", ".info", ".biz", ".link", ".click", ".work",
    ".loan", ".win", ".racing", ".download", ".stream", ".gdn", ".icu",
}

LEGITIMATE_BRAND_DOMAINS = {
    "google.com", "gmail.com", "youtube.com", "googleapis.com",
    "microsoft.com", "outlook.com", "office.com", "live.com", "bing.com",
    "apple.com", "icloud.com", "facebook.com", "instagram.com",
    "whatsapp.com", "meta.com", "paypal.com", "amazon.com", "amazon.com.tr", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it", "amazon.es", "amazon.co.jp", "amazon.ca", "amazon.com.au", "amazon.in", "amazon.com.br", "amazon.com.mx", "amazonaws.com",
    "netflix.com", "twitter.com", "x.com", "linkedin.com", "dropbox.com",
    "github.com", "adobe.com", "steampowered.com", "ebay.com", "shopee.com", "shopee.co.id", "shopee.com.my", "shopee.sg", "shopee.ph", "shopee.co.th", "shopee.vn", "trendyol.com", "hepsiburada.com", "aliexpress.com", "temu.com", "binance.com", "coinbase.com", "discord.com", "telegram.org",
    "garanti.com.tr", "garantibbva.com.tr", "akbank.com", "isbank.com.tr",
    "ziraatbank.com.tr", "vakifbank.com.tr", "halkbank.com.tr",
    "yapikredi.com.tr", "turkcell.com.tr", "vodafone.com.tr",
    "turktelekom.com.tr", "turkiye.gov.tr",
    "ing.com", "ing.com.tr", "ing.de", "ing.nl", "ing.be", "ing.pl", "ing.es",
}


def brand_present(brand, text):
    """Kısa marka adlarında substring false-positive üretmeden marka görünürlüğünü kontrol eder."""
    b=(brand or "").lower().strip(); t=(text or "").lower()
    if not b: return False
    if len(b) <= 3:
        return bool(re.search(r"(?<![a-z0-9])" + re.escape(b) + r"(?![a-z0-9])", t, re.I))
    return b in t

def legitimate_brand_root(brand, root):
    b=(brand or "").lower(); r=(root or "").lower()
    if b == "ing":
        return r in {"ing.com","ing.com.tr","ing.de","ing.nl","ing.be","ing.pl","ing.es"}
    return any(r == d or r.endswith("."+d) for d in LEGITIMATE_BRAND_DOMAINS if b in d)

DANGEROUS_EXTENSIONS = {
    ".exe", ".msi", ".msp", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs",
    ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".jar", ".apk", ".dll",
    ".iso", ".img", ".lnk", ".reg", ".chm", ".xll", ".appinstaller", ".msix"
}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"}
SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy"
}
