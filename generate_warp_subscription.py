#!/usr/bin/env python3
import base64, json, re, time, urllib.error, urllib.parse, urllib.request, zipfile

API_BASE = "https://awgconfig.com/api/warp"
FALLBACK_API_BASE = "https://yota-warp-self.vercel.app/api/generate"
MODE = "awg31"
COUNT_PER_REQUEST = 3
TARGET_TOTAL = 15

LINKS_FILE = "warp-awg-links.txt"
ZIP_FILE = "warp-awg-configs.zip"
CONTAINER_FILE = "warp-awg-container.json"

# --- Логика устойчивости ---
REQUEST_DELAY = 6              # пауза между успешными запросами к одному API
RETRY_DELAY = 5                # пауза после обычной неудачи (не 429)
RATE_LIMIT_BASE_DELAY = 15     # базовая пауза при 429 (растёт экспоненциально)
MAX_CONSECUTIVE_FAILURES = 3   # сколько неудач подряд до переключения API
MAX_ATTEMPTS = 40              # предохранитель от бесконечного цикла

WG_PRIVKEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")
ALLOWED_CPS_TAGS = {"b", "r", "rc", "rd", "dz", "t", "d", "ds"}
CPS_QUERY_KEYS = [
    "i1", "i2", "i3", "i4", "i5", "jc", "jmin", "jmax",
    "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
    "contentpaddingaddition", "rekeyaftertime", "rekeytimeout",
    "rejectaftertime", "keepalivetimeout", "maxhandshakeattempts",
    "randomtrailers", "disablecookies", "mtu", "dns",
]

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

def request_api(base, rate_limit_hits=0):
    """
    Один запрос к API.
    Возвращает (texts_or_None, error_type).
    error_type ∈ {None, 'rate_limit', 'server', 'network', 'empty'}.
    """
    params = {"mode": MODE, "count": str(COUNT_PER_REQUEST)}
    if "awgconfig.com" in base:
        params["endpointMode"] = "lab"
    url = f"{base}?{urllib.parse.urlencode(params)}"
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            data = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 429:
            wait = min(RATE_LIMIT_BASE_DELAY * (2 ** rate_limit_hits), 120)
            print(f"  [!] Rate limit 429. Ждём {wait}с (попытка {rate_limit_hits + 1})")
            time.sleep(wait)
            return None, "rate_limit"
        if e.code >= 500:
            print(f"  [!] Серверная ошибка {e.code}")
            return None, "server"
        print(f"  [!] HTTP {e.code}")
        return None, "network"
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

def fetch_from_api(base):
    """
    Пытается собрать TARGET_TOTAL конфигов с одного API.
    Возвращает (собрано_текстов, причина_остановки):
      'done'      — набрали цель,
      'exhausted' — упёрлись в лимит неудач.
    """
    collected = []
    consecutive_failures = 0
    rate_limit_hits = 0
    attempts = 0
    while len(collected) < TARGET_TOTAL and attempts < MAX_ATTEMPTS:
        attempts += 1
        texts, err = request_api(base, rate_limit_hits)
        if texts is None:
            consecutive_failures += 1
            if err == "rate_limit":
                rate_limit_hits += 1
            print(f"  [~] Неудача {consecutive_failures}/{MAX_CONSECUTIVE_FAILURES} подряд")
            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                return collected, "exhausted"
            if err != "rate_limit":
                time.sleep(RETRY_DELAY)
            continue
        # Успех
        consecutive_failures = 0
        rate_limit_hits = 0
        collected.extend(texts)
        print(f"  [+] +{len(texts)} (всего {len(collected)})")
        if len(collected) < TARGET_TOTAL:
            time.sleep(REQUEST_DELAY)
    return collected, "done"

def fetch_all_conf_texts():
    """
    Опрашивает API по порядку, накапливая результаты.
    Возвращает дедуплицированный список, даже если оба API «исчерпаны».
    """
    all_texts = []
    for base in (API_BASE, FALLBACK_API_BASE):
        print(f"[*] API: {base}")
        texts, reason = fetch_from_api(base)
        if texts:
            all_texts.extend(texts)
            print(f"[+] {base}: {len(texts)} конфигов (накоплено: {len(all_texts)})")
        else:
            print(f"[!] {base}: 0 конфигов")
        if len(all_texts) >= TARGET_TOTAL:
            print(f"[✓] Набрали {len(all_texts)} — останавливаемся")
            break
        if reason == "exhausted" and texts:
            print(f"[~] {base} исчерпан — переключаемся на следующий API")
        elif reason == "done" and texts:
            print(f"[~] {base} отдал всё что мог — добираем с резервного")

    if not all_texts:
        raise SystemExit("Ни один API не дал конфигов.")

    # Дедупликация по приватному ключу (уникален для каждого конфига)
    seen_keys = set()
    unique = []
    for t in all_texts:
        iface, _ = parse_conf(t)
        key = iface.get("privatekey", "")
        if key and key in seen_keys:
            continue
        seen_keys.add(key)
        unique.append(t)
    print(f"[*] После дедупликации: {len(unique)} из {len(all_texts)}")
    return unique[:TARGET_TOTAL]

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
    print(f"[*] Итого .conf для записи: {len(texts)}")

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
