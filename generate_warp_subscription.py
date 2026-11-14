#!/usr/bin/env python3
"""
Генерирует подписку для Throne с AmneziaWG-конфигами WARP.
Создаёт:
  - warp-awg-links.txt : текстовый файл со ссылками awg:// (по одной на строку)
  - warp-awg-configs.zip : ZIP-архив с .conf файлами (для Android)
  - warp-awg-container.json : JSON-контейнер AmneziaWG (альтернативный формат)
Источник: awgconfig.com API (и резервный yota-warp-self.vercel.app).
"""

import base64
import io
import json
import os
import time
import urllib.parse
import urllib.request
import zipfile

# --- НАСТРОЙКИ ---
# Основной, рекомендованный API
API_BASE = "https://awgconfig.com/api/warp"
# Резервный API (используется, если основной не ответил)
FALLBACK_API_BASE = "https://yota-warp-self.vercel.app/api/generate"

MODE = "awg31"               # awg31, awg3, awg2 или legacy
COUNT_PER_REQUEST = 3        # максимум 3 за один запрос (ограничение API)
TARGET_TOTAL = 15            # сколько всего конфигов хотим в подписке
LINKS_FILE = "warp-awg-links.txt"
ZIP_FILE = "warp-awg-configs.zip"
CONTAINER_FILE = "warp-awg-container.json"
REQUEST_DELAY = 2            # пауза между запросами

# Параметры, которые могут находиться в секции [Interface] или [Device]
AWG_INTERFACE_PARAMS = {
    "privatekey": "private_key",
    "address": "address",
    "dns": "dns",
    "mtu": "mtu",
    "jc": "jc", "jmin": "jmin", "jmax": "jmax",
    "s1": "s1", "s2": "s2", "s3": "s3", "s4": "s4",
    "h1": "h1", "h2": "h2", "h3": "h3", "h4": "h4",
    "i1": "i1", "i2": "i2", "i3": "i3", "i4": "i4", "i5": "i5",
    "contentpaddingaddition": "content_padding_addition",
    "rekeyaftertime": "rekey_after_time",
    "rekeytimeout": "rekey_timeout",
    "rejectaftertime": "reject_after_time",
    "keepalivetimeout": "keepalive_timeout",
    "maxhandshakeattempts": "max_handshake_attempts",
    "randomtrailers": "random_trailers",
    "disablecookies": "disable_cookies",
}

# Параметры секции [Peer]
AWG_PEER_PARAMS = {
    "publickey": "public_key",
    "endpoint": "endpoint",          # "host:port"
    "allowedips": "allowed_ips",
    "persistentkeepalive": "persistent_keepalive_interval",
    "presharedkey": "preshared_key",
}


def parse_conf(conf_text):
    """Разбирает .conf и возвращает словари для Interface и Peer."""
    iface, peer = {}, {}
    section = None
    for line in conf_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("["):
            section = line.strip("[]").lower()
            continue
        if "=" in line and section:
            key, value = line.split("=", 1)
            key = key.strip().lower()
            value = value.strip()
            if section in ("interface", "device"):
                if key in AWG_INTERFACE_PARAMS:
                    iface[AWG_INTERFACE_PARAMS[key]] = value
                iface[key] = value  # сохраняем и «сырые» ключи
            elif section == "peer":
                if key in AWG_PEER_PARAMS:
                    peer[AWG_PEER_PARAMS[key]] = value
                peer[key] = value
    return iface, peer


def iface_peer_to_awg_link(iface, peer):
    """Собирает каноническую ссылку awg:// из разобранных данных."""
    priv = iface.get("private_key") or iface.get("privatekey")
    if not priv:
        return None

    endpoint = peer.get("endpoint")
    if not endpoint:
        return None

    # Разделяем host:port (IPv6 в скобках — упрощённо)
    if endpoint.startswith("["):
        host, _, port = endpoint.partition("]:")
        host = host.lstrip("[")
    else:
        host, _, port = endpoint.partition(":")

    query = {}
    pub = peer.get("public_key") or peer.get("publickey")
    if pub:
        query["public_key"] = pub

    addr = iface.get("address")
    if addr:
        query["address"] = addr.replace(" ", "")

    # Параметры обфускации и таймингов из [Interface] / [Device]
    for k, v in iface.items():
        if k in ("private_key", "privatekey", "address", "public_key", "publickey"):
            continue
        if k in (
            "jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
            "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5",
            "content_padding_addition", "rekey_after_time", "rekey_timeout",
            "reject_after_time", "keepalive_timeout", "max_handshake_attempts",
            "random_trailers", "disable_cookies", "mtu", "dns",
            "persistent_keepalive_interval",
        ):
            query[k] = v

    for k in ("persistent_keepalive_interval", "preshared_key"):
        if k in peer:
            query[k] = peer[k]

    qs = urllib.parse.urlencode(query, doseq=True)
    link = f"awg://{priv}@{host}:{port}"
    if qs:
        link += "?" + qs
    return link


def extract_conf_texts(api_response):
    """
    Извлекает список текстов .conf из ответа API.
    Поддерживает форматы awgconfig.com и yota-warp-self.vercel.app.
    """
    conf_texts = []

    # Вариант 1: массив configs (awgconfig.com)
    if isinstance(api_response.get("configs"), list):
        for cfg in api_response["configs"]:
            if "content" in cfg:
                try:
                    text = base64.b64decode(cfg["content"]).decode("utf-8")
                    conf_texts.append(text)
                except Exception as e:
                    print(f"[!] Ошибка декодирования configs[].content: {e}")
        if conf_texts:
            return conf_texts

    # Вариант 2: поле content (base64) на верхнем уровне (awgconfig.com, count=1)
    if "content" in api_response:
        try:
            text = base64.b64decode(api_response["content"]).decode("utf-8")
            conf_texts.append(text)
        except Exception as e:
            print(f"[!] Ошибка декодирования content: {e}")
        if conf_texts:
            return conf_texts

    # Вариант 3: готовый текст .conf в поле config (yota-warp-self.vercel.app)
    if "config" in api_response and isinstance(api_response["config"], str):
        if "[Interface]" in api_response["config"]:
            conf_texts.append(api_response["config"])
        else:
            print("[!] Поле 'config' не похоже на .conf (нет [Interface]).")

    return conf_texts


def fetch_all_conf_texts():
    """Последовательно опрашивает основной и резервный API, собирает .conf."""
    all_texts = []
    apis = [API_BASE, FALLBACK_API_BASE]

    for base in apis:
        print(f"[*] Пробуем API: {base}")
        collected_from_api = []
        attempts = 0
        while len(collected_from_api) < TARGET_TOTAL and attempts < 10:
            attempts += 1
            params = {"mode": MODE, "count": str(COUNT_PER_REQUEST)}
            # Для awgconfig.com используем endpointMode=lab для уникальных эндпоинтов
            if "awgconfig.com" in base:
                params["endpointMode"] = "lab"
            url = f"{base}?{urllib.parse.urlencode(params)}"
            print(f"  [*] Запрос: {url}")
            try:
                with urllib.request.urlopen(url, timeout=60) as resp:
                    data = json.loads(resp.read().decode())
            except Exception as e:
                print(f"  [!] Ошибка запроса: {e}")
                break

            texts = extract_conf_texts(data)
            if not texts:
                print("  [!] API не вернул валидных .conf, прекращаем опрос этого API.")
                break

            collected_from_api.extend(texts)
            print(f"  [+] Получено {len(texts)} конфигов, всего от этого API: {len(collected_from_api)}")
            time.sleep(REQUEST_DELAY)

        if collected_from_api:
            all_texts.extend(collected_from_api)
            print(f"[✓] API {base} дал {len(collected_from_api)} конфигов.")
        else:
            print(f"[!] API {base} не дал результатов, пробуем следующий.")

        if len(all_texts) >= TARGET_TOTAL:
            break

    return all_texts[:TARGET_TOTAL]


def build_json_container(conf_texts):
    """Создаёт JSON-контейнер AmneziaWG согласно спецификации."""
    servers = []
    for text in conf_texts:
        iface, peer = parse_conf(text)
        endpoint = peer.get("endpoint", "unknown")
        name = endpoint.replace(":", "-").replace(".", "-")
        b64 = base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")
        servers.append({"name": name, "config": b64})
    if not servers:
        return None
    return {"type": "amneziawg", "servers": servers}


def main():
    conf_texts = fetch_all_conf_texts()
    if not conf_texts:
        raise SystemExit("Не удалось получить ни одного .conf ни от одного API.")

    print(f"[*] Всего собрано .conf: {len(conf_texts)}")

    # 1. Текстовый файл со ссылками awg://
    links = []
    for text in conf_texts:
        iface, peer = parse_conf(text)
        link = iface_peer_to_awg_link(iface, peer)
        if link:
            links.append(link)
        else:
            print("[!] Не удалось собрать ссылку awg://, пропускаем.")
    with open(LINKS_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(links))
    print(f"[✓] Записано {len(links)} ссылок в {LINKS_FILE}")

    # 2. ZIP-архив с .conf файлами
    with zipfile.ZipFile(ZIP_FILE, "w", zipfile.ZIP_DEFLATED) as zf:
        for i, text in enumerate(conf_texts, 1):
            zf.writestr(f"warp-awg-{i}.conf", text)
    print(f"[✓] Записано {len(conf_texts)} .conf файлов в {ZIP_FILE}")

    # 3. JSON-контейнер
    container = build_json_container(conf_texts)
    if container:
        with open(CONTAINER_FILE, "w", encoding="utf-8") as f:
            json.dump(container, f, ensure_ascii=False, indent=2)
        print(f"[✓] JSON-контейнер записан в {CONTAINER_FILE} ({len(container['servers'])} серверов)")
    else:
        print("[!] JSON-контейнер не создан (нет валидных серверов).")


if __name__ == "__main__":
    main()
