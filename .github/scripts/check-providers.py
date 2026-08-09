#!/usr/bin/env python3

import json
import os
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


CONFIG_PATH = Path("providers.json")
STATE_PATH = Path(".github/provider-monitor-state.json")
TIMEOUT_SECONDS = 20
USER_AGENT = "MangaTranslate-ProviderMonitor/1.0"


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default


def validate_config(config):
    errors = []
    if not isinstance(config, dict):
        return ["providers.json no contiene un objeto JSON"]
    if not isinstance(config.get("schemaVersion"), int):
        errors.append("falta schemaVersion o no es un número")
    providers = config.get("providers")
    if not isinstance(providers, list) or not providers:
        errors.append("providers no es una lista válida")
        return errors
    seen_ids = set()
    for index, provider in enumerate(providers, 1):
        if not isinstance(provider, dict):
            errors.append(f"proveedor {index}: formato inválido")
            continue
        provider_id = provider.get("id")
        if not isinstance(provider_id, str) or not provider_id:
            errors.append(f"proveedor {index}: falta id")
        elif provider_id in seen_ids:
            errors.append(f"id duplicado: {provider_id}")
        else:
            seen_ids.add(provider_id)
        for field in ("name", "engine"):
            if not isinstance(provider.get(field), str) or not provider[field]:
                errors.append(f"{provider_id or index}: falta {field}")
        language = provider.get("language")
        if not isinstance(language, dict) or not language.get("code"):
            errors.append(f"{provider_id or index}: idioma inválido")
        domains = provider.get("domains")
        if not isinstance(domains, list) or not domains:
            errors.append(f"{provider_id or index}: no tiene dominios")
    return errors


def targets_from(config):
    targets = {}
    for provider in config.get("providers", []):
        if not provider.get("enabled", True):
            continue
        name = provider.get("name", provider.get("id", "Desconocido"))
        urls = list(provider.get("domains", []))
        endpoints = provider.get("endpoints", {})
        if isinstance(endpoints, dict):
            urls.extend(value for value in endpoints.values() if isinstance(value, str))
        for url in urls:
            if not isinstance(url, str) or not url.startswith(("http://", "https://")):
                continue
            targets.setdefault(url, []).append(name)
    return targets


def check_url(url):
    parsed = urllib.parse.urlparse(url)
    try:
        socket.getaddrinfo(parsed.hostname, parsed.port or 443)
    except socket.gaierror as error:
        return False, f"DNS: {error}"

    check_url = url
    if parsed.hostname == "api.mangadex.org" and parsed.path in ("", "/"):
        check_url = "https://api.mangadex.org/ping"

    request = urllib.request.Request(
        check_url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
            "Range": "bytes=0-131071",
        },
    )
    try:
        context = ssl.create_default_context()
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS, context=context) as response:
            status = response.status
            final_url = response.geturl()
            body = response.read(131072)
            content_type = response.headers.get("Content-Type", "").lower()
    except urllib.error.HTTPError as error:
        if error.code in (400, 405):
            return True, f"HTTP {error.code}: servicio accesible"
        if error.code == 404 and (
            (parsed.hostname or "").startswith("api.")
            or parsed.path.rstrip("/") == "/api"
        ):
            return True, "HTTP 404 esperado en la raíz de la API"
        if error.code in (401, 403, 407, 429, 451):
            return False, f"HTTP {error.code}: posible bloqueo, límite, región o VPN"
        return False, f"HTTP {error.code}"
    except urllib.error.URLError as error:
        return False, f"red: {error.reason}"
    except TimeoutError:
        return False, "tiempo de espera agotado"
    except Exception as error:
        return False, f"{type(error).__name__}: {error}"

    if not 200 <= status < 400:
        return False, f"HTTP {status}"
    if len(body) < 2:
        return False, "respuesta vacía"

    final_host = urllib.parse.urlparse(final_url).hostname
    if final_host and parsed.hostname and final_host != parsed.hostname:
        original_root = ".".join(parsed.hostname.lower().split(".")[-2:])
        final_root = ".".join(final_host.lower().split(".")[-2:])
        if original_root != final_root:
            return False, f"redirige a otro dominio: {final_host}"

    sample = body.decode("utf-8", errors="ignore").lower()
    block_markers = (
        "access denied",
        "error 1020",
        "attention required! | cloudflare",
        "cf-chl-",
        "captcha",
        "unavailable for legal reasons",
    )
    if any(marker in sample for marker in block_markers):
        return False, "posible bloqueo, CAPTCHA, región o VPN"
    if "text/html" in content_type and len(sample.strip()) < 80:
        return False, "HTML inesperadamente vacío; la web podría haber cambiado"
    return True, f"HTTP {status}"


def telegram(message):
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        print("Faltan TELEGRAM_BOT_TOKEN o TELEGRAM_CHAT_ID", file=sys.stderr)
        return False
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": message}).encode()
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return 200 <= response.status < 300
    except Exception as error:
        print(f"No se pudo enviar Telegram: {error}", file=sys.stderr)
        return False


def main():
    config = load_json(CONFIG_PATH, {})
    validation_errors = validate_config(config)
    previous = load_json(STATE_PATH, {"targets": {}, "configValid": True})
    current_targets = {}
    incidents = []
    recoveries = []

    for url, providers in targets_from(config).items():
        providers = sorted(set(providers))
        healthy, detail = check_url(url)
        current_targets[url] = {
            "healthy": healthy,
            "providers": providers,
        }
        old = previous.get("targets", {}).get(url)
        label = ", ".join(sorted(set(providers)))
        if not healthy and (old is None or old.get("healthy", True)):
            incidents.append(f"• {label}\n  {url}\n  {detail}")
        elif healthy and old is not None and not old.get("healthy", True):
            recoveries.append(f"• {label}\n  {url}")

    was_config_valid = previous.get("configValid", True)
    if validation_errors and was_config_valid:
        incidents.insert(0, "• providers.json inválido\n  " + "\n  ".join(validation_errors))
    elif not validation_errors and not was_config_valid:
        recoveries.insert(0, "• providers.json vuelve a tener una estructura válida")

    message_parts = []
    if incidents:
        message_parts.append("🚨 MangaTranslate: problemas nuevos\n\n" + "\n\n".join(incidents))
    if recoveries:
        message_parts.append("✅ MangaTranslate: servidores recuperados\n\n" + "\n\n".join(recoveries))
    if os.environ.get("SEND_TEST", "").lower() == "true":
        message_parts.insert(
            0,
            f"✅ Monitor diario de MangaTranslate configurado\n"
            f"Se han comprobado {len(current_targets)} destinos.",
        )
    if message_parts:
        telegram("\n\n".join(message_parts))

    state = {
        "configValid": not validation_errors,
        "configErrors": validation_errors,
        "targets": current_targets,
    }
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(
        json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Comprobados {len(current_targets)} destinos; {len(incidents)} incidencias; {len(recoveries)} recuperaciones")


if __name__ == "__main__":
    main()
