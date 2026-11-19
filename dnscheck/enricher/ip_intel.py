"""
IP Intelligence & GeoIP/ASN Enrichment Engine.
Combines built-in CIDR classification (Fake-IP, RFC1918, well-known DNS providers, CDN ranges)
with multi-source online GeoIP lookup (ip-api.com batch/single, ipwho.is, ipinfo.io) and thread-safe caching.
"""

from __future__ import annotations

import ipaddress
import json
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple


@dataclass
class IPIntel:
    """Enriched metadata for an IPv4 or IPv6 address."""
    ip: str
    country_code: str = "UNKNOWN"
    country_name: str = "未知"
    region: str = ""
    city: str = ""
    asn: str = ""
    isp: str = "Unknown"
    org: str = ""
    is_private: bool = False
    is_loopback: bool = False
    is_fake_ip: bool = False
    is_cn: bool = False
    is_anycast_dns: bool = False
    provider_tag: str = ""

    @property
    def display_location(self) -> str:
        parts = [p for p in (self.country_name, self.region, self.city) if p and p != "未知"]
        # Deduplicate adjacent identical strings (e.g., ["新加坡", "新加坡"])
        deduped: List[str] = []
        for p in parts:
            if not deduped or deduped[-1] != p:
                deduped.append(p)
        return " · ".join(deduped) if deduped else self.country_name

    @property
    def display_isp(self) -> str:
        if self.provider_tag:
            return f"{self.provider_tag} ({self.asn})" if self.asn else self.provider_tag
        base = self.org or self.isp or "Unknown"
        if self.asn and self.asn not in base:
            return f"{base} ({self.asn})"
        return base

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "region": self.region,
            "city": self.city,
            "location": self.display_location,
            "asn": self.asn,
            "isp": self.isp,
            "org": self.org,
            "display_isp": self.display_isp,
            "is_private": self.is_private,
            "is_loopback": self.is_loopback,
            "is_fake_ip": self.is_fake_ip,
            "is_cn": self.is_cn,
            "is_anycast_dns": self.is_anycast_dns,
            "provider_tag": self.provider_tag,
        }


# Fake-IP networks commonly used by Clash / Sing-box / Surge / Tun2socks
FAKE_IP_NETWORKS = [
    ipaddress.ip_network("198.18.0.0/15"),   # Standard RFC 2544 benchmark range used for Fake-IP
    ipaddress.ip_network("28.0.0.0/8"),      # Alternate Fake-IP range in some clients
    ipaddress.ip_network("fc00::/18"),       # IPv6 Fake-IP range used by Sing-box / Clash.Meta
]

# Known public DNS & CDN networks for instant offline recognition
KNOWN_NETWORKS: List[Tuple[ipaddress._BaseNetwork, dict]] = [
    # Domestic Public DNS
    (ipaddress.ip_network("223.5.5.0/24"), {"cc": "CN", "cn": "中国", "asn": "AS37963", "isp": "阿里云 AliDNS", "tag": "阿里公共 DNS", "anycast": True}),
    (ipaddress.ip_network("223.6.6.0/24"), {"cc": "CN", "cn": "中国", "asn": "AS37963", "isp": "阿里云 AliDNS", "tag": "阿里公共 DNS", "anycast": True}),
    (ipaddress.ip_network("2400:3200::/32"), {"cc": "CN", "cn": "中国", "asn": "AS37963", "isp": "阿里云 AliDNS", "tag": "阿里公共 DNS IPv6", "anycast": True}),
    (ipaddress.ip_network("119.29.29.0/24"), {"cc": "CN", "cn": "中国", "asn": "AS45090", "isp": "腾讯云 DNSPod", "tag": "腾讯 DNSPod Public DNS", "anycast": True}),
    (ipaddress.ip_network("119.28.28.0/24"), {"cc": "CN", "cn": "中国", "asn": "AS45090", "isp": "腾讯云 DNSPod", "tag": "腾讯 DNSPod Public DNS", "anycast": True}),
    (ipaddress.ip_network("1.12.12.0/24"), {"cc": "CN", "cn": "中国", "asn": "AS45090", "isp": "腾讯云 DNSPod", "tag": "腾讯 DNSPod Public DNS", "anycast": True}),
    (ipaddress.ip_network("114.114.114.0/24"), {"cc": "CN", "cn": "中国", "asn": "AS4134", "isp": "南京信风 114DNS", "tag": "114 公共 DNS", "anycast": True}),
    (ipaddress.ip_network("114.114.115.0/24"), {"cc": "CN", "cn": "中国", "asn": "AS4134", "isp": "南京信风 114DNS", "tag": "114 公共 DNS", "anycast": True}),
    (ipaddress.ip_network("180.76.76.0/24"), {"cc": "CN", "cn": "中国", "asn": "AS38365", "isp": "百度 BaiduDNS", "tag": "百度公共 DNS", "anycast": True}),
    (ipaddress.ip_network("1.2.4.0/24"), {"cc": "CN", "cn": "中国", "asn": "AS7497", "isp": "CNNIC SDNS", "tag": "CNNIC 公共 DNS", "anycast": True}),
    # Global Public DNS & Anycast
    (ipaddress.ip_network("1.1.1.0/24"), {"cc": "GLOBAL", "cn": "全球 Anycast", "asn": "AS13335", "isp": "Cloudflare, Inc.", "tag": "Cloudflare 1.1.1.1", "anycast": True}),
    (ipaddress.ip_network("1.0.0.0/24"), {"cc": "GLOBAL", "cn": "全球 Anycast", "asn": "AS13335", "isp": "Cloudflare, Inc.", "tag": "Cloudflare 1.0.0.1", "anycast": True}),
    (ipaddress.ip_network("2606:4700:4700::/48"), {"cc": "GLOBAL", "cn": "全球 Anycast", "asn": "AS13335", "isp": "Cloudflare, Inc.", "tag": "Cloudflare DNS IPv6", "anycast": True}),
    (ipaddress.ip_network("8.8.8.0/24"), {"cc": "GLOBAL", "cn": "全球 Anycast", "asn": "AS15169", "isp": "Google LLC", "tag": "Google Public DNS", "anycast": True}),
    (ipaddress.ip_network("8.8.4.0/24"), {"cc": "GLOBAL", "cn": "全球 Anycast", "asn": "AS15169", "isp": "Google LLC", "tag": "Google Public DNS", "anycast": True}),
    (ipaddress.ip_network("2001:4860:4860::/48"), {"cc": "GLOBAL", "cn": "全球 Anycast", "asn": "AS15169", "isp": "Google LLC", "tag": "Google Public DNS IPv6", "anycast": True}),
    (ipaddress.ip_network("9.9.9.0/24"), {"cc": "GLOBAL", "cn": "全球 Anycast", "asn": "AS19281", "isp": "Quad9", "tag": "Quad9 Security DNS", "anycast": True}),
    (ipaddress.ip_network("149.112.112.0/24"), {"cc": "GLOBAL", "cn": "全球 Anycast", "asn": "AS19281", "isp": "Quad9", "tag": "Quad9 Security DNS", "anycast": True}),
    (ipaddress.ip_network("208.67.222.0/24"), {"cc": "US", "cn": "美国", "asn": "AS36692", "isp": "Cisco OpenDNS", "tag": "Cisco OpenDNS", "anycast": True}),
    (ipaddress.ip_network("208.67.220.0/24"), {"cc": "US", "cn": "美国", "asn": "AS36692", "isp": "Cisco OpenDNS", "tag": "Cisco OpenDNS", "anycast": True}),
]

COUNTRY_CN_MAP: Dict[str, str] = {
    "CN": "中国内地",
    "HK": "中国香港",
    "TW": "中国台湾",
    "MO": "中国澳门",
    "US": "美国",
    "JP": "日本",
    "SG": "新加坡",
    "KR": "韩国",
    "DE": "德国",
    "GB": "英国",
    "UK": "英国",
    "NL": "荷兰",
    "FR": "法国",
    "CA": "加拿大",
    "AU": "澳大利亚",
    "RU": "俄罗斯",
    "IN": "印度",
    "MY": "马来西亚",
    "TH": "泰国",
    "VN": "越南",
    "ID": "印尼",
    "PH": "菲律宾",
    "CH": "瑞士",
    "SE": "瑞典",
    "IE": "爱尔兰",
}

DOMESTIC_ASN_KEYWORDS = {
    "AS4134": "中国电信 (China Telecom 163)",
    "AS4809": "中国电信 CN2 (China Telecom Next Carrier)",
    "AS4812": "中国电信 (上海电信)",
    "AS4837": "中国联通 (China Unicom 169)",
    "AS9929": "中国联通 A网 (CUII)",
    "AS17621": "中国联通 (上海联通)",
    "AS9808": "中国移动 (China Mobile)",
    "AS56040": "中国移动 (广东移动)",
    "AS56046": "中国移动 (江苏移动)",
    "AS56048": "中国移动 (北京移动)",
    "AS24400": "中国移动 (上海移动)",
    "AS4538": "中国教育网 (CERNET)",
    "AS37963": "阿里云 (Alibaba Cloud)",
    "AS45090": "腾讯云 (Tencent Cloud)",
    "AS132203": "腾讯云 (Tencent Cloud)",
    "AS55990": "华为云 (Huawei Cloud)",
    "AS38365": "百度云 (Baidu)",
}

_CACHE_LOCK = threading.Lock()
_IP_CACHE: Dict[str, IPIntel] = {}


def is_fake_ip(ip_str: str) -> bool:
    """Return True if the IP belongs to a Fake-IP virtual pool (e.g., 198.18.0.0/15)."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in FAKE_IP_NETWORKS)
    except ValueError:
        return False


def classify_local_or_known_ip(ip_str: str) -> Optional[IPIntel]:
    """Check if IP is loopback, private, Fake-IP, or in a known public DNS subnet."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None

    if is_fake_ip(ip_str):
        return IPIntel(
            ip=ip_str,
            country_code="FAKE-IP",
            country_name="本地虚拟网段 (Fake-IP)",
            isp="代理客户端 Fake-IP 映射池 (Clash / Sing-box / Surge)",
            org="RFC 2544 Fake-IP Pool",
            is_private=True,
            is_fake_ip=True,
            provider_tag="Fake-IP 虚拟地址",
        )

    if addr.is_loopback:
        return IPIntel(
            ip=ip_str,
            country_code="LOCAL",
            country_name="本机回环 (Loopback)",
            isp="本机 DNS 服务 / 代理监听 (127.0.0.1 / ::1)",
            is_private=True,
            is_loopback=True,
            provider_tag="本机回环地址",
        )

    if addr.is_private or addr.is_link_local:
        return IPIntel(
            ip=ip_str,
            country_code="LAN",
            country_name="局域网 / 虚拟网卡 (LAN/TUN)",
            isp="本地路由器网关或 TUN 虚拟网关",
            is_private=True,
            provider_tag="局域网/虚拟网关",
        )

    for net, meta in KNOWN_NETWORKS:
        if addr in net:
            return IPIntel(
                ip=ip_str,
                country_code=meta["cc"],
                country_name=meta["cn"],
                asn=meta["asn"],
                isp=meta["isp"],
                org=meta["isp"],
                is_cn=(meta["cc"] == "CN"),
                is_anycast_dns=meta.get("anycast", False),
                provider_tag=meta["tag"],
            )

    return None


def _parse_asn_org(as_str: str, isp_str: str, org_str: str) -> Tuple[str, str]:
    """Normalize ASN number and friendly ISP label."""
    asn = ""
    if as_str:
        parts = as_str.strip().split(" ", 1)
        if parts[0].upper().startswith("AS"):
            asn = parts[0].upper()
    if asn in DOMESTIC_ASN_KEYWORDS:
        return asn, DOMESTIC_ASN_KEYWORDS[asn]
    friendly = org_str or isp_str or as_str or "Unknown"
    return asn, friendly


def _query_ip_api_single(ip_str: str, timeout: float = 2.5) -> Optional[IPIntel]:
    """Query ip-api.com for a single IP."""
    url = f"http://ip-api.com/json/{ip_str}?fields=status,country,countryCode,regionName,city,isp,org,as,query&lang=zh-CN"
    req = urllib.request.Request(url, headers={"User-Agent": "DNSGuard-Checker/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        if data.get("status") != "success":
            return None
        cc = data.get("countryCode", "UNKNOWN")
        asn, friendly_isp = _parse_asn_org(data.get("as", ""), data.get("isp", ""), data.get("org", ""))
        return IPIntel(
            ip=ip_str,
            country_code=cc,
            country_name=COUNTRY_CN_MAP.get(cc, data.get("country", cc)),
            region=data.get("regionName", ""),
            city=data.get("city", ""),
            asn=asn,
            isp=friendly_isp,
            org=data.get("org", "") or data.get("isp", ""),
            is_cn=(cc == "CN"),
        )
    except Exception:
        return None


def _query_ipwhois_single(ip_str: str, timeout: float = 2.5) -> Optional[IPIntel]:
    """Fallback GeoIP lookup via ipwho.is (HTTPS)."""
    url = f"https://ipwho.is/{ip_str}?lang=zh-CN"
    req = urllib.request.Request(url, headers={"User-Agent": "DNSGuard-Checker/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        if not data.get("success", False):
            return None
        cc = data.get("country_code", "UNKNOWN")
        conn = data.get("connection") or {}
        raw_asn = f"AS{conn.get('asn')}" if conn.get("asn") else ""
        asn, friendly_isp = _parse_asn_org(raw_asn, conn.get("isp", ""), conn.get("org", ""))
        return IPIntel(
            ip=ip_str,
            country_code=cc,
            country_name=COUNTRY_CN_MAP.get(cc, data.get("country", cc)),
            region=data.get("region", ""),
            city=data.get("city", ""),
            asn=asn,
            isp=friendly_isp,
            org=conn.get("org", "") or conn.get("isp", ""),
            is_cn=(cc == "CN"),
        )
    except Exception:
        return None


def enrich_ip(ip_str: str, timeout: float = 2.5) -> IPIntel:
    """Enrich a single IP address with caching, offline heuristics, and online GeoIP fallback."""
    ip_str = ip_str.strip()
    if not ip_str:
        return IPIntel(ip="")

    with _CACHE_LOCK:
        if ip_str in _IP_CACHE:
            return _IP_CACHE[ip_str]

    local_match = classify_local_or_known_ip(ip_str)
    if local_match and (local_match.is_private or local_match.is_fake_ip or local_match.is_loopback):
        with _CACHE_LOCK:
            _IP_CACHE[ip_str] = local_match
        return local_match

    # Try online lookup for full geo location; merge with known tag if present
    online = _query_ip_api_single(ip_str, timeout=timeout) or _query_ipwhois_single(ip_str, timeout=timeout)
    if online:
        if local_match:
            online.provider_tag = local_match.provider_tag
            online.is_anycast_dns = local_match.is_anycast_dns
            if local_match.is_cn:
                online.is_cn = True
        with _CACHE_LOCK:
            _IP_CACHE[ip_str] = online
        return online

    if local_match:
        with _CACHE_LOCK:
            _IP_CACHE[ip_str] = local_match
        return local_match

    fallback = IPIntel(ip=ip_str)
    with _CACHE_LOCK:
        _IP_CACHE[ip_str] = fallback
    return fallback


def enrich_ips_batch(ips: Iterable[str], timeout: float = 3.0) -> Dict[str, IPIntel]:
    """Concurrently enrich a batch of IP addresses."""
    unique_ips = []
    for ip in ips:
        cleaned = (ip or "").strip()
        if cleaned and cleaned not in unique_ips:
            unique_ips.append(cleaned)

    results: Dict[str, IPIntel] = {}
    to_fetch: List[str] = []

    for ip in unique_ips:
        with _CACHE_LOCK:
            if ip in _IP_CACHE:
                results[ip] = _IP_CACHE[ip]
                continue
        local_match = classify_local_or_known_ip(ip)
        if local_match and (local_match.is_private or local_match.is_fake_ip or local_match.is_loopback):
            with _CACHE_LOCK:
                _IP_CACHE[ip] = local_match
            results[ip] = local_match
        else:
            to_fetch.append(ip)

    if not to_fetch:
        return results

    # Try ip-api.com batch endpoint first for up to 15 IPs
    if len(to_fetch) > 1:
        try:
            batch_url = "http://ip-api.com/batch?fields=status,country,countryCode,regionName,city,isp,org,as,query&lang=zh-CN"
            payload = json.dumps(to_fetch[:25]).encode("utf-8")
            req = urllib.request.Request(
                batch_url,
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "DNSGuard-Checker/1.0"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                batch_data = json.loads(resp.read().decode("utf-8", errors="replace"))
            if isinstance(batch_data, list):
                for item in batch_data:
                    q_ip = item.get("query")
                    if q_ip and item.get("status") == "success":
                        cc = item.get("countryCode", "UNKNOWN")
                        asn, friendly_isp = _parse_asn_org(
                            item.get("as", ""), item.get("isp", ""), item.get("org", "")
                        )
                        local_m = classify_local_or_known_ip(q_ip)
                        intel = IPIntel(
                            ip=q_ip,
                            country_code=cc,
                            country_name=COUNTRY_CN_MAP.get(cc, item.get("country", cc)),
                            region=item.get("regionName", ""),
                            city=item.get("city", ""),
                            asn=asn,
                            isp=friendly_isp,
                            org=item.get("org", "") or item.get("isp", ""),
                            is_cn=(cc == "CN") or bool(local_m and local_m.is_cn),
                            is_anycast_dns=bool(local_m and local_m.is_anycast_dns),
                            provider_tag=local_m.provider_tag if local_m else "",
                        )
                        with _CACHE_LOCK:
                            _IP_CACHE[q_ip] = intel
                        results[q_ip] = intel
        except Exception:
            pass

    remaining = [ip for ip in to_fetch if ip not in results]
    if remaining:
        with ThreadPoolExecutor(max_workers=min(8, len(remaining))) as pool:
            futs = {pool.submit(enrich_ip, ip, timeout): ip for ip in remaining}
            for fut, ip in futs.items():
                try:
                    results[ip] = fut.result()
                except Exception:
                    results[ip] = classify_local_or_known_ip(ip) or IPIntel(ip=ip)

    return results
