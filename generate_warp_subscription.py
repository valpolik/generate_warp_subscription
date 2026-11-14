#!/usr/bin/env python3
import base64, io, json, os, re, time, urllib.parse, urllib.request, zipfile

API_BASE = "https://awgconfig.com/api/warp"
FALLBACK_API_BASE = "https://yota-warp-self.vercel.app/api/generate"
MODE = "awg31"
COUNT_PER_REQUEST = 3
TARGET_TOTAL = 15
LINKS_FILE = "warp-awg-links.txt"
ZIP_FILE = "warp-awg-configs.zip"
CONTAINER_FILE = "warp-awg-container.json"
REQUEST_DELAY = 2

# Разрешённые теги для I1–I5: <b 0x...>, <r N>, <rc N>, <rd N>, <dz N>, <t>, <d>, <ds>
ALLOWED_CPS_TAGS = {"b", "r", "rc", "rd", "dz", "t", "d", "ds"}

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
    """Убирает пробелы внутри тегов и заменяет недопустимые теги на <r 16>."""
    if not value or not value.startswith("<"):
        return value
    # Если тег уже корректный (<b 0x...>), оставляем как есть
    if re.match(r"^<b 0x[0-9a-fA-F]+>$", value.strip()):
        return value.strip()
    # Иначе пытаемся собрать допустимую последовательность
    tokens = re.findall(r"<([a-z]+)(?:\s+0x([0-9a-fA-F]+)|\s+(\d+))?>", value)
    result = []
    for tag, hex_val, num in tokens:
        if tag not in ALLOWED_CPS_TAGS:
            continue
        if tag == "b" and hex_val:
            result.append(f"<b 0x{hex_val}>")
        elif tag in ("r", "rc", "rd", "dz") and num:
            result.append(f"<{tag} {num}>")
        elif tag in ("t", "d", "ds"):
            result.append(f"<{tag}>")
    return "".join(result) if result else "<r 16>"

def iface_peer_to_awg_link(iface, peer):
    priv = iface.get("privatekey")
    endpoint = peer.get("endpoint")
    if not priv or not endpoint:
        return None
    # Проверка, что приватный ключ похож на base64
    if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", priv):
        return None

    if endpoint.startswith("["):
        host, _, port = endpoint.partition("]:")
        host = host.lstrip("[")
    else:
        host, _, port = endpoint.partition(":")

    query = {}
    pub = peer.get("publickey")
    if pub:
        query["public_key"] = pub
    addr = iface.get("address")
    if addr:
        query["address"] = addr.replace(" ", "")

    # Параметры обфускации (все, что могут быть в [Interface])
    cps_keys = ["i1", "i2", "i3", "i4", "i5", "jc", "jmin", "jmax",
                "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
                "contentpaddingaddition", "rekeyaftertime", "rekeytimeout",
                "rejectaftertime", "keepalivetimeout", "maxhandshakeattempts",
                "randomtrailers", "disablecookies", "mtu", "dns"]
    for k in cps_keys:
        if k in iface:
            query[k] = iface[k]

    if "persistentkeepalive" in peer:
        query["persistent_keepalive_interval"] = peer["persistentkeepalive"]

    # Ключевой момент: quote_via=urllib.parse.quote, чтобы пробелы были %20, а не +
    qs = urllib.parse.urlencode(query, doseq=True, quote_via=urllib.parse.quote)
    return f"awg://{priv}@{host}:{port}?{qs}"

def extract_conf_texts(resp):
    texts = []
    if isinstance(resp.get("configs"), list):
        for c in resp["configs"]:
            if "content" in c:
                try:
                    texts.append(base64.b64decode(c["content"]).decode())
                except Exception:
                    pass
    if "content" in resp:
        try:
            texts.append(base64.b64decode(resp["content"]).decode())
        except Exception:
            pass
    if isinstance(resp.get("config"), str) and "[Interface]" in resp["config"]:
        texts.append(resp["config"])
    return texts

def fetch_all_conf_texts():
    all_texts = []
    for base in [API_BASE, FALLBACK_API_BASE]:
        print(f"[*] Пробуем {base}")
        collected = []
        for _ in range(10):
            if len(collected) >= TARGET_TOTAL:
                break
            params = {"mode": MODE, "count": str(COUNT_PER_REQUEST)}
            if "awgconfig.com" in base:
                params["endpointMode"] = "lab"
            url = f"{base}?{urllib.parse.urlencode(params)}"
            try:
                with urllib.request.urlopen(url, timeout=60) as r:
                    data = json.loads(r.read().decode())
            except Exception as e:
                print(f"  [!] Ошибка: {e}")
                break
            texts = extract_conf_texts(data)
            if not texts:
                break
            collected.extend(texts)
            print(f"  [+] +{len(texts)} (всего {len(collected)})")
            time.sleep(REQUEST_DELAY)
        if collected:
            all_texts.extend(collected)
            print(f"[✓] {base} дал {len(collected)}")
        if len(all_texts) >= TARGET_TOTAL:
            break
    return all_texts[:TARGET_TOTAL]

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
    if not texts:
        raise SystemExit("Нет конфигов.")
    print(f"[*] Всего .conf: {len(texts)}")

    links = []
    for t in texts:
        iface, peer = parse_conf(t)
        # Санитизация CPS-тегов в самом .conf (на случай, если API вернул <b+0x...>)
        for k in ["i1", "i2", "i3", "i4", "i5"]:
            if k in iface:
                iface[k] = sanitize_cps_tag(iface[k])
        link = iface_peer_to_awg_link(iface, peer)
        if link:
            links.append(link)
        else:
            print("[!] Пропуск: не удалось собрать ссылку (неверный ключ или endpoint)")

    with open(LINKS_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(links))
    print(f"[✓] {len(links)} ссылок в {LINKS_FILE}")

    with zipfile.ZipFile(ZIP_FILE, "w", zipfile.ZIP_DEFLATED) as z:
        for i, t in enumerate(texts, 1):
            z.writestr(f"warp-awg-{i}.conf", t)
    print(f"[✓] {len(texts)} .conf в {ZIP_FILE}")

    c = build_json_container(texts)
    if c:
        with open(CONTAINER_FILE, "w", encoding="utf-8") as f:
            json.dump(c, f, ensure_ascii=False, indent=2)
        print(f"[✓] JSON-контейнер: {len(c['servers'])} серверов")

if __name__ == "__main__":
    main()
