#!/usr/bin/env python3
"""
Генерирует максимально разнообразную подписку AmneziaWG для WARP.
Источники: awgconfig.com (основной), yota-warp-self.vercel.app (резервный).

Разнообразие:
  • mode:        legacy / awg2 / awg3 / awg31
  • endpointMode: hostname / lab
  • warpPort:    2408 / 500 / 4500 / 1701 / 880 / 8854
  • cps:         auto / static / sip / stun / quic / dns / dtls
  • mobile / router: случайное включение
  • тайминги AWG 3.x: случайные допустимые диапазоны
  • yota-warp:   dns / mtu / allowed_ips / keepalive / amnezia
"""

import base64
import json
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

# ==================== КОНФИГУРАЦИЯ ====================
API_BASE = "https://awgconfig.com/api/warp"
FALLBACK_API_BASE = "https://yota-warp-self.vercel.app/api/generate"

TARGET_TOTAL = 50            # итоговое число конфигов (с запасом на дубли)
COUNT_PER_REQUEST = 3        # максимум для awgconfig.com
REQUEST_DELAY = 6            # пауза между успешными запросами
RETRY_DELAY = 5              # пауза после обычной неудачи (не 429)
RATE_LIMIT_BASE_DELAY = 10   # базовая пауза при 429 (экспоненциально)
MAX_CONSECUTIVE_FAILURES = 3 # неудач подряд до смены API
MAX_RATE_LIMIT_HITS = 5      # отдельный бюджет для 429
MAX_ATTEMPTS = 60            # общий предохранитель

LINKS_FILE = "warp-awg-links.txt"
ZIP_FILE = "warp-awg-configs.zip"
CONTAINER_FILE = "warp-awg-container.json"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# ==================== ВАЛИДАЦИЯ КЛЮЧЕЙ ====================
WG_PRIVKEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")

ALLOWED_CPS_TAGS = {"b", "r", "rc", "rd", "dz", "t", "d", "ds"}
CPS_QUERY_KEYS = [
    "i1", "i2", "i3", "i4", "i5",
    "jc", "jmin", "jmax",
    "s1", "s2", "s3", "s4",
    "h1", "h2", "h3", "h4",
    "contentpaddingaddition", "rekeyaftertime", "rekeytimeout",
    "rejectaftertime", "keepalivetimeout", "maxhandshakeattempts",
    "randomtrailers", "disablecookies",
    "mtu", "dns",
]

# ==================== РАЗНООБРАЗИЕ ПАРАМЕТРОВ ====================
MODES = ["legacy", "awg2", "awg3", "awg31"]
ENDPOINT_MODES = ["hostname","lab","lab","lab","lab","lab"]
WARP_PORTS = [2408, 500, 4500, 1701, 880, 8854, 955, 7103]
CPS_MODES = ["auto", "static", "sip", "stun", "quic", "dns", "dtls"]
KEEPALIVE_RANGES = ["25", "25-35", "15-25", "30-40", "20-30"]
PADDING_RANGES = ["10-100", "20-80", "30-90", "off"]
REKEY_AFTER = ["100-120", "90-110", "110-130"]
REKEY_TIMEOUT = ["3-7", "4-8", "2-6"]
REJECT_AFTER = ["150-180", "160-190", "140-170"]
KEEPALIVE_TIMEOUT = ["5-15", "6-16", "4-14"]
MAX_HANDSHAKE = ["15-20", "10-15", "12-18"]

YOTA_DNS = ["1.1.1.1", "8.8.8.8", "1.1.1.1,1.0.0.1", "9.9.9.9"]
YOTA_MTU = [1280, 1360, 1420]
YOTA_ALLOWED_IPS = ["0.0.0.0/0", "0.0.0.0/0,::/0"]
YOTA_KEEPALIVE = [25, 30, 35, 40]


def random_awgconfig_params():
    """Случайная комбинация параметров для awgconfig.com."""
    mode = random.choice(MODES)
    params = {
        "mode": mode,
        "count": str(COUNT_PER_REQUEST),
        "endpointMode": random.choice(ENDPOINT_MODES),
        "cps": random.choice(CPS_MODES),
        "persistentKeepalive": random.choice(KEEPALIVE_RANGES),
    }
    # Порт имеет смысл только при hostname, но lab тоже принимает как предпочтение
    params["warpPort"] = str(random.choice(WARP_PORTS))

    # Мобильный / роутерный профиль — взаимоисключающие, выбираем один или ни одного
    profile = random.choice([None, "mobile", "router"])
    if profile:
        params[profile] = "1"

    # Дополнительные тайминги и паддинг для AWG 3.x
    if mode in ("awg3", "awg31"):
        params["contentPaddingAddition"] = random.choice(PADDING_RANGES)
        params["rekeyAfterTime"] = random.choice(REKEY_AFTER)
        params["rekeyTimeout"] = random.choice(REKEY_TIMEOUT)
        params["rejectAfterTime"] = random.choice(REJECT_AFTER)
        params["keepaliveTimeout"] = random.choice(KEEPALIVE_TIMEOUT)
        params["maxHandshakeAttempts"] = random.choice(MAX_HANDSHAKE)

    return params


def random_yota_params():
    """Случайная комбинация параметров для yota-warp."""
    return {
        "dns": random.choice(YOTA_DNS),
        "mtu": str(random.choice(YOTA_MTU)),
        "allowed_ips": random.choice(YOTA_ALLOWED_IPS),
        "keepalive": str(random.choice(YOTA_KEEPALIVE)),
        "amnezia": random.choice(["true", "false"]),
    }


# ==================== ПАРСИНГ .CONF ====================
def parse_conf(conf_text):
    iface, peer = {}, {}
    section = None
    for line in conf_text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            section = line.strip("[]").lower()
            continue
        if "=" in line and section:
            key, value = line.split("=", 1)
            key, value = key.strip().lower(), value.strip()
            if section in ("interface", "device"):
                iface[key] = value
            elif section == "peer":
                peer[key] = value
    return iface, peer


def sanitize_cps_tag(value):
    if not value:
        return value
    value = value.strip()
    if re.fullmatch(r"<b 0x[0-9a-fA-F]+>", value):
        return value
    tokens = re.findall(r"<([a-zA-Z]+)(?:\s+0x([0-9a-fA-F]+)|\s+(\d+))?>", value)
    out = []
    for tag, hex_val, num in tokens:
        tag = tag.lower()
        if tag not in ALLOWED_CPS_TAGS:
            continue
        if tag == "b" and hex_val:
            out.append(f"<b 0x{hex_val}>")
        elif tag in ("r", "rc", "rd", "dz") and num:
            out.append(f"<{tag} {num}>")
        elif tag in ("t", "d", "ds"):
            out.append(f"<{tag}>")
    return "".join(out) if out else "<r 16>"


def iface_peer_to_awg_link(iface, peer):
    priv_raw = iface.get("privatekey")
    endpoint = peer.get("endpoint")
    if not priv_raw or not endpoint:
        return None
    priv = priv_raw.strip().strip('"').strip("'")
    if not WG_PRIVKEY_RE.fullmatch(priv):
        return None

    if endpoint.startswith("["):
        host, _, port = endpoint.partition("]:")
        host = host.lstrip("[")
    else:
        host, _, port = endpoint.partition(":")
    if not host or not port.isdigit() or not (1 <= int(port) <= 65535):
        return None

    query = {}
    pub = peer.get("publickey")
    if pub:
        query["public_key"] = pub
    if iface.get("address"):
        query["address"] = iface["address"].replace(" ", "")

    for k in CPS_QUERY_KEYS:
        if k in iface:
            query[k] = sanitize_cps_tag(iface[k]) if k.startswith("i") else iface[k]
    if "persistentkeepalive" in peer:
        query["persistent_keepalive_interval"] = peer["persistentkeepalive"]

    qs = urllib.parse.urlencode(query, doseq=True, quote_via=urllib.parse.quote)
    return f"awg://{priv}@{host}:{port}?{qs}"


# ==================== ЗАПРОСЫ К API ====================
def extract_conf_texts(resp):
    texts = []
    if isinstance(resp.get("configs"), list):
        for c in resp["configs"]:
            if "content" in c:
                try:
                    texts.append(base64.b64decode(c["content"]).decode("utf-8"))
                except Exception:
                    pass
    if "content" in resp:
        try:
            texts.append(base64.b64decode(resp["content"]).decode("utf-8"))
        except Exception:
            pass
    if isinstance(resp.get("config"), str) and "[Interface]" in resp["config"]:
        texts.append(resp["config"])
    return texts


def request_api(base, params, rate_limit_hits=0):
    url = f"{base}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 429:
            retry_after = e.headers.get("Retry-After")
            if retry_after and retry_after.isdigit():
                wait = min(int(retry_after), 180)
            else:
                wait = min(RATE_LIMIT_BASE_DELAY * (2 ** rate_limit_hits), 180)
            print(f"  [!] 429. Ждём {wait}с (Retry-After={'да' if retry_after else 'нет'})")
            time.sleep(wait)
            return None, "rate_limit"
        if e.code >= 500:
            print(f"  [!] Серверная ошибка {e.code}")
            return None, "server"
        print(f"  [!] HTTP {e.code}")
        return None, "network"
    except json.JSONDecodeError as e:
        print(f"  [!] Битый JSON: {e}")
        return None, "empty"
    except Exception as e:
        print(f"  [!] Сетевая ошибка: {e}")
        return None, "network"

    if not data.get("success", True):
        print("  [!] API вернул success=false")
        return None, "empty"
    texts = extract_conf_texts(data)
    if not texts:
        print("  [!] API не вернул валидных .conf")
        return None, "empty"
    return texts, None


def fetch_from_api(base, param_generator):
    collected = []
    consecutive_failures = 0
    rate_limit_hits = 0
    attempts = 0

    while len(collected) < TARGET_TOTAL and attempts < MAX_ATTEMPTS:
        attempts += 1
        params = param_generator()
        print(f"  [>] Параметры: { {k: v for k, v in params.items() if k != 'count'} }")
        texts, err = request_api(base, params, rate_limit_hits)

        if texts is None:
            if err == "rate_limit":
                rate_limit_hits += 1
                print(f"  [~] Rate limit {rate_limit_hits}/{MAX_RATE_LIMIT_HITS} (не считается неудачей)")
                if rate_limit_hits >= MAX_RATE_LIMIT_HITS:
                    return collected, "exhausted"
                continue
            consecutive_failures += 1
            print(f"  [~] Неудача {consecutive_failures}/{MAX_CONSECUTIVE_FAILURES} подряд")
            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                return collected, "exhausted"
            time.sleep(RETRY_DELAY)
            continue

        consecutive_failures = 0
        rate_limit_hits = 0
        collected.extend(texts)
        print(f"  [+] +{len(texts)} (всего {len(collected)})")
        if len(collected) < TARGET_TOTAL:
            time.sleep(REQUEST_DELAY)

    return collected, "done"


def fetch_all_conf_texts():
    all_texts = []

    # Основной API — максимальное разнообразие
    print(f"[*] API: {API_BASE}")
    texts, reason = fetch_from_api(API_BASE, random_awgconfig_params)
    if texts:
        all_texts.extend(texts)
        print(f"[+] {API_BASE}: {len(texts)} (накоплено: {len(all_texts)})")
    if len(all_texts) >= TARGET_TOTAL:
        return deduplicate(all_texts)[:TARGET_TOTAL]

    # Резервный API — тоже с разнообразием
    print(f"[*] API: {FALLBACK_API_BASE}")
    texts, reason = fetch_from_api(FALLBACK_API_BASE, random_yota_params)
    if texts:
        all_texts.extend(texts)
        print(f"[+] {FALLBACK_API_BASE}: {len(texts)} (накоплено: {len(all_texts)})")

    if not all_texts:
        raise SystemExit("Ни один API не дал конфигов.")

    return deduplicate(all_texts)[:TARGET_TOTAL]


def deduplicate(texts):
    seen = set()
    unique = []
    for t in texts:
        iface, _ = parse_conf(t)
        key = iface.get("privatekey", "")
        if key and key in seen:
            continue
        seen.add(key)
        unique.append(t)
    print(f"[*] После дедупликации: {len(unique)} из {len(texts)}")
    return unique


# ==================== ЗАПИСЬ ФАЙЛОВ ====================
def build_json_container(texts):
    servers = []
    for t in texts:
        iface, peer = parse_conf(t)
        ep = peer.get("endpoint", "unknown")
        name = ep.replace(":", "-").replace(".", "-")
        b64 = base64.urlsafe_b64encode(t.encode()).decode().rstrip("=")
        servers.append({"name": name, "config": b64})
    return {"type": "amneziawg", "servers": servers} if servers else None


def main():
    texts = fetch_all_conf_texts()
    print(f"[*] Итого .conf: {len(texts)}")

    # Фильтр валидности перед записью
    texts = [t for t in texts if all(x in t for x in ("[Interface]", "[Peer]", "PrivateKey", "PublicKey"))]
    print(f"[*] После фильтра .conf: {len(texts)}")

    links, skipped = [], 0
    for t in texts:
        iface, peer = parse_conf(t)
        link = iface_peer_to_awg_link(iface, peer)
        if link:
            links.append(link)
        else:
            skipped += 1
    with open(LINKS_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(links))
    print(f"[✓] {len(links)} ссылок в {LINKS_FILE} (пропущено: {skipped})")

    with zipfile.ZipFile(ZIP_FILE, "w", zipfile.ZIP_DEFLATED) as z:
        for i, t in enumerate(texts, 1):
            z.writestr(f"warp-awg-{i}.conf", t)
    print(f"[✓] {len(texts)} .conf в {ZIP_FILE}")

    container = build_json_container(texts)
    if container:
        with open(CONTAINER_FILE, "w", encoding="utf-8") as f:
            json.dump(container, f, ensure_ascii=False, indent=2)
        print(f"[✓] JSON-контейнер: {len(container['servers'])} серверов")


if __name__ == "__main__":
    main()
