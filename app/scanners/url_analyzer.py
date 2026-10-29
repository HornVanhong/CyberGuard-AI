"""CyberGuard AI - URL & Phishing Threat Analyzer.

Extracts URLs from user messages, evaluates deterministic heuristics (IP addresses,
suspicious TLDs, URL shorteners, punycode/homograph attacks, brand impersonation),
correlates with VirusTotal Threat Intelligence, and assigns a normalized Verdict.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from app.services.virustotal_service import VirusTotalService, VTResult, VTStatus
from app.utils.logger import logger

# Regex to match URLs in arbitrary text
URL_REGEX = re.compile(
    r"(?:https?://|www\.)[^\s<>'\"{}|\\^`]+[^\s<>'\"{}|\\^`.,;:?!]",
    re.IGNORECASE,
)

# Known URL shorteners concealing destination
KNOWN_SHORTENERS: Set[str] = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "cutt.ly",
    "is.gd",
    "rb.gy",
    "shorturl.at",
    "ow.ly",
    "rebrand.ly",
    "bl.ink",
    "v.gd",
    "t.ly",
    "s.id",
    "soo.gd",
}

# High-risk Top-Level Domains heavily abused in phishing & malware campaigns
HIGH_RISK_TLDS: Set[str] = {
    "xyz",
    "top",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "buzz",
    "fit",
    "work",
    "click",
    "rest",
    "icu",
    "cam",
    "live",
    "vip",
    "monster",
    "quest",
    "surf",
    "fun",
    "casa",
    "cfd",
    "sbs",
}

# Targeted brands and sensitive terms
SENSITIVE_KEYWORDS: List[str] = [
    "telegram",
    "whatsapp",
    "facebook",
    "meta",
    "google",
    "apple",
    "microsoft",
    "paypal",
    "binance",
    "coinbase",
    "trustwallet",
    "metamask",
    "aba",
    "acleda",
    "wing",
    "canadia",
    "login",
    "signin",
    "verify",
    "verification",
    "security",
    "account-update",
    "airdrop",
    "claim",
    "bonus",
    "free-gift",
    "customer-service",
    "support-team",
    "password-reset",
]

# Official domains of heavily targeted brands
OFFICIAL_DOMAINS: Dict[str, List[str]] = {
    "telegram": ["telegram.org", "t.me", "telegram.me"],
    "google": ["google.com", "google.com.kh", "accounts.google.com"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com"],
    "paypal": ["paypal.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "aba": ["ababank.com", "payway.com.kh"],
    "acleda": ["acledabank.com.kh"],
    "wing": ["wingbank.com.kh", "wingmoney.com"],
    "canadia": ["canadiabank.com.kh"],
    "binance": ["binance.com"],
}

# Regex for IPv4 address
IP_REGEX = re.compile(r"^https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/.*)?$", re.IGNORECASE)


@dataclass
class UrlAnalysisResult:
    """Outcome of URL threat inspection."""

    url: str
    domain: str
    verdict: str  # "MALICIOUS", "SUSPICIOUS", "CLEAN"
    risk_score: int  # 0 to 100
    is_shortened: bool = False
    is_ip_address: bool = False
    is_punycode: bool = False
    vt_malicious: int = 0
    vt_total: int = 0
    red_flags: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class MessageAnalysisResult:
    """Outcome of phishing/scam message text inspection."""

    text: str
    urls_found: List[str] = field(default_factory=list)
    url_results: List[UrlAnalysisResult] = field(default_factory=list)
    verdict: str = "CLEAN"  # "MALICIOUS", "SUSPICIOUS", "CLEAN"
    risk_score: int = 0
    red_flags: List[str] = field(default_factory=list)
    social_engineering_tactics: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class UrlAnalyzer:
    """Multi-layer URL and Phishing Message Analyzer."""

    def __init__(self, vt_service: Optional[VirusTotalService] = None) -> None:
        self.vt = vt_service

    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extracts unique URLs from text."""
        if not text:
            return []
        matches = URL_REGEX.findall(text)
        urls = []
        for u in matches:
            clean = u.strip()
            if not clean.startswith(("http://", "https://")):
                clean = "http://" + clean
            if clean not in urls:
                urls.append(clean)
        return urls

    async def analyze_url(self, target_url: str) -> UrlAnalysisResult:
        """Evaluates heuristics and Threat Intelligence for a single URL."""
        clean_url = target_url.strip()
        if not clean_url.startswith(("http://", "https://")):
            clean_url = "http://" + clean_url

        try:
            parsed = urllib.parse.urlparse(clean_url)
            domain = parsed.hostname or clean_url
        except Exception:
            domain = clean_url

        domain_lower = domain.lower()
        path_lower = (parsed.path or "").lower()

        red_flags: List[str] = []
        score = 0
        is_ip = bool(IP_REGEX.match(clean_url))
        is_shortened = domain_lower in KNOWN_SHORTENERS
        is_punycode = "xn--" in domain_lower

        # 1. Bare IP address check
        if is_ip:
            score += 45
            red_flags.append("Bare IP address used instead of domain name (common in phishing & C2 nodes)")

        # 2. Punycode / Homograph check
        if is_punycode:
            score += 40
            red_flags.append(f"Punycode characters detected in domain '{domain}' (potential spoofing of trusted brand)")

        # 3. URL shortener check
        if is_shortened:
            score += 20
            red_flags.append(f"URL shortener '{domain_lower}' conceals the true target destination")

        # 4. High-risk TLD check
        tld = domain_lower.split(".")[-1] if "." in domain_lower else ""
        if tld in HIGH_RISK_TLDS:
            score += 30
            red_flags.append(f"Suspicious top-level domain '.{tld}' frequently linked to phishing infrastructure")

        # 5. Brand Impersonation in domain or path
        for brand, official_list in OFFICIAL_DOMAINS.items():
            if brand in domain_lower:
                # Check if it matches an authentic official domain
                is_official = any(domain_lower == off or domain_lower.endswith("." + off) for off in official_list)
                if not is_official:
                    score += 65
                    red_flags.append(f"Impersonation detected: Contains '{brand}' but is NOT on official domain ({', '.join(official_list)})")

        # 6. Sensitive keywords in path or subdomain
        subdomains = domain_lower.split(".")[:-2] if len(domain_lower.split(".")) > 2 else []
        for kw in SENSITIVE_KEYWORDS:
            if kw in subdomains or kw in path_lower:
                if not any(brand in domain_lower for brand in OFFICIAL_DOMAINS):
                    score += 15
                    red_flags.append(f"Security/Credential keyword '{kw}' present in unverified domain structure")
                    break

        # 7. VirusTotal Threat Intelligence check
        vt_malicious = 0
        vt_total = 0
        if self.vt and self.vt.enabled:
            vt_res = await self.vt.lookup_url(clean_url)
            if vt_res.status == VTStatus.FOUND:
                vt_malicious = vt_res.malicious + vt_res.suspicious
                vt_total = vt_res.total_engines
                if vt_malicious > 0:
                    score += min(vt_malicious * 30, 85)
                    red_flags.append(f"VirusTotal alert: {vt_malicious}/{vt_total} security engines flagged this URL as malicious")

        # 8. Calculate Verdict
        score = min(score, 100)
        if score >= 60 or vt_malicious >= 2:
            verdict = "MALICIOUS"
        elif score >= 25 or vt_malicious == 1 or is_shortened:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        recommendations = []
        if verdict == "MALICIOUS":
            recommendations.append("Do NOT open or click this link under any circumstances.")
            recommendations.append("Never enter passwords, banking details, or OTP codes on this site.")
            recommendations.append("Block and report the sender immediately.")
        elif verdict == "SUSPICIOUS":
            recommendations.append("Exercise extreme caution before navigating to this destination.")
            recommendations.append("Verify through the service's official app or bookmarked website instead.")
        else:
            recommendations.append("No immediate threats flagged by heuristic checks or intelligence databases.")
            recommendations.append("Standard zero-trust browsing vigilance is always advised.")

        return UrlAnalysisResult(
            url=clean_url,
            domain=domain,
            verdict=verdict,
            risk_score=score,
            is_shortened=is_shortened,
            is_ip_address=is_ip,
            is_punycode=is_punycode,
            vt_malicious=vt_malicious,
            vt_total=vt_total,
            red_flags=red_flags,
            recommendations=recommendations,
        )

    async def analyze_message(self, message_text: str) -> MessageAnalysisResult:
        """Analyzes a suspicious text message and any embedded URLs."""
        text = message_text.strip()
        lower = text.lower()
        urls = self.extract_urls(text)

        url_results = []
        for u in urls[:5]:  # Analyze up to 5 URLs
            res = await self.analyze_url(u)
            url_results.append(res)

        red_flags: List[str] = []
        tactics: List[str] = []
        score = 0

        # Social Engineering Pattern 1: Urgency & Fear
        urgency_terms = [
            "immediately", "within 24 hours", "account will be deleted", "suspended",
            "urgent", "police", "arrest", "security breach", "frozen", "blocked",
            "បន្ទាន់", "ជាបន្ទាន់", "បិទគណនី", "ផ្អាកដំណើរការ", "បង្កក", "គំរាម"
        ]
        if any(term in lower for term in urgency_terms):
            score += 25
            tactics.append("Urgency & Fear Tactics (Pressuring victim to act without thinking)")
            red_flags.append("Message creates artificial panic or urgent deadline")

        # Social Engineering Pattern 2: Greed & Fake Prizes
        greed_terms = [
            "you won", "lottery", "cash prize", "free money", "claim your reward",
            "airdrop", "giveaway", "free telegram premium", "crypto giveaway", "bonus",
            "ឈ្នះរង្វាន់", "ឥតគិតថ្លៃ", "លុយហ្វ្រី", "ទទួលបានរង្វាន់"
        ]
        if any(term in lower for term in greed_terms):
            score += 30
            tactics.append("Lure & False Reward (Promising free money, prizes, or bonuses)")
            red_flags.append("Offers unrealistic financial reward or unrequested giveaway")

        # Social Engineering Pattern 3: Credential & OTP Solicitation
        cred_terms = [
            "send me your password", "otp", "verification code", "secret code",
            "seed phrase", "private key", "confirm your identity",
            "ផ្ញើលេខកូដ otp", "លេខសម្ងាត់", "password", "កូដសម្ងាត់"
        ]
        if any(term in lower for term in cred_terms):
            score += 45
            tactics.append("Credential Harvesting (Attempting to steal passwords or OTP tokens)")
            red_flags.append("Explicit request for confidential security codes or login credentials")

        # Incorporate URL scores
        for ur in url_results:
            if ur.verdict == "MALICIOUS":
                score = max(score, 85)
                red_flags.extend(ur.red_flags)
            elif ur.verdict == "SUSPICIOUS":
                score = max(score, 50)
                red_flags.extend(ur.red_flags)

        score = min(score, 100)
        verdict = "MALICIOUS" if score >= 65 else ("SUSPICIOUS" if score >= 30 else "CLEAN")

        recommendations = []
        if verdict == "MALICIOUS":
            recommendations.append("This message is an active phishing or scam attempt.")
            recommendations.append("Do NOT share OTP codes, passwords, or personal identity information.")
            recommendations.append("Do NOT click any links inside the message.")
            recommendations.append("Block the sender and report as spam.")
        elif verdict == "SUSPICIOUS":
            recommendations.append("Message contains typical signs of social engineering.")
            recommendations.append("Contact the organization directly through their verified phone number.")
        else:
            recommendations.append("No obvious phishing patterns detected.")
            recommendations.append("Never share sensitive credentials or financial pins.")

        return MessageAnalysisResult(
            text=text,
            urls_found=urls,
            url_results=url_results,
            verdict=verdict,
            risk_score=score,
            red_flags=list(dict.fromkeys(red_flags)),  # Deduplicate
            social_engineering_tactics=tactics,
            recommendations=recommendations,
        )
