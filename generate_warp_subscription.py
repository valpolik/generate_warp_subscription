#!/usr/bin/env python3
import base64, json, re, time, urllib.parse, urllib.request, zipfile

API_BASE = "https://awgconfig.com/api/warp"
FALLBACK_API_BASE = "https://yota-warp-self.vercel.app/api/generate"
MODE = "awg31"
COUNT_PER_REQUEST = 3
TARGET_TOTAL = 15
LINKS_FILE = "warp-awg-links.txt"
ZIP_FILE = "warp-awg-configs.zip"
CONTAINER_FILE = "warp-awg-container.json"
REQUEST_DELAY = 5

# Точный шаблон приватного ключа WireGuard (44 символа base64, '=' в конце)
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

    # Очистка ключа от пробелов, кавычек и прочего мусора
    priv = priv_raw.strip().strip('"').strip("'")
    # Жёсткая проверка: ровно 44 символа base64 с '=' в конце
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

def fetch_all_conf_texts():
    all_texts = []
    for base in (API_BASE, FALLBACK_API_BASE):
        print(f"[*] API: {base}")
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
            print(f"[✓] {base}: {len(collected)}")
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

    links, skipped = [], []
    for t in texts:
        iface, peer = parse_conf(t)
        link = iface_peer_to_awg_link(iface, peer)
        if link:
            links.append(link)
        else:
            # Логируем отброшенную строку, чтобы вы могли убедиться, что фильтр работает
            priv_preview = (iface.get("privatekey") or "")[:20]
            skipped.append(f"priv='{priv_preview}...' endpoint={peer.get('endpoint')}")

    with open(LINKS_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(links))
    print(f"[✓] {len(links)} валидных ссылок в {LINKS_FILE}")
    if skipped:
        print(f"[!] Отброшено {len(skipped)} строк с невалидным ключом или endpoint:")
        for s in skipped[:5]:  # показываем первые 5 для примера
            print(f"    - {s}")
        if len(skipped) > 5:
            print(f"    ... и ещё {len(skipped) - 5}")

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
