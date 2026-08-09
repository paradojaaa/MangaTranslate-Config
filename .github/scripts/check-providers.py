#!/usr/bin/env python3

import json
import os
import random
import re
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
USER_AGENT = (
    "Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) "
    "AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1"
)


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
        if error.code in (401, 403, 429):
            return True, f"HTTP {error.code}: accesible, pero bloquea comprobaciones automatizadas"
        if error.code in (407, 451):
            return False, f"HTTP {error.code}: posible bloqueo, región o VPN"
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


def provider_probe_url(provider):
    base = provider["domains"][0].rstrip("/")
    provider_id = provider.get("id", "")
    engine = provider.get("engine", "")
    language = provider.get("language", {}).get("code", "en").split("-")[0]
    if engine == "mangadex":
        query = urllib.parse.urlencode(
            {
                "limit": 5,
                "includes[]": "cover_art",
                "contentRating[]": "safe",
                "availableTranslatedLanguage[]": language,
            }
        )
        return f"{base}/manga?{query}"
    suffixes = {
        "rawdevart": "/spa/home",
        "rawkuma": "/wp-json/wp/v2/manga?per_page=5&_embed",
        "senmanga": "/api/directory?page=1&type=Manga&order=popular",
        "remanga": "/v2/titles/top/?count=5&page=1&period=all&section=all&tag=all",
        "inventario-oculto": "/?s=&post_type=wp-manga&m_orderby=views",
    }
    return base + suffixes.get(provider_id, "/")


def fetch_probe(url, referer=None, byte_limit=524288):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/json;q=0.9,image/*;q=0.8,*/*;q=0.7",
            "Referer": referer or url,
        },
    )
    context = ssl.create_default_context()
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS, context=context) as response:
        return (
            response.status,
            response.geturl(),
            response.headers.get("Content-Type", "").lower(),
            response.read(byte_limit),
        )


def nested_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from nested_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from nested_strings(child)


def mangadex_images(payload):
    result = []
    for manga in payload.get("data", []):
        manga_id = manga.get("id")
        for relationship in manga.get("relationships", []):
            if relationship.get("type") != "cover_art":
                continue
            filename = relationship.get("attributes", {}).get("fileName")
            if manga_id and filename:
                result.append(
                    f"https://uploads.mangadex.org/covers/{manga_id}/{filename}.256.jpg"
                )
    return result


def image_candidates(body, content_type, base_url, provider):
    values = []
    if "json" in content_type or body.lstrip().startswith((b"{", b"[")):
        payload = json.loads(body.decode("utf-8"))
        if provider.get("engine") == "mangadex" and isinstance(payload, dict):
            values.extend(mangadex_images(payload))
        values.extend(nested_strings(payload))
    else:
        text = body.decode("utf-8", errors="ignore")
        values.extend(
            re.findall(
                r'''(?is)(?:src|data-src|data-lazy-src|data-original|content)\s*=\s*["']([^"']+)["']''',
                text,
            )
        )

    candidates = []
    seen = set()
    for raw in values:
        raw = raw.replace("\\/", "/").replace("&amp;", "&").strip()
        lower = raw.lower()
        looks_like_image = bool(
            re.search(r"\.(?:jpe?g|png|webp|avif|gif)(?:[?#].*)?$", lower)
            or "/covers/" in lower
            or "/media/" in lower
            or "/uploads/" in lower
        )
        if not looks_like_image or raw.startswith("data:"):
            continue
        absolute = urllib.parse.urljoin(base_url, raw)
        if absolute.startswith(("http://", "https://")) and absolute not in seen:
            seen.add(absolute)
            candidates.append(absolute)
    random.SystemRandom().shuffle(candidates)
    candidates.sort(
        key=lambda value: not any(
            marker in value.lower()
            for marker in ("cover", "manga", "media", "uploads", "thumbnail")
        )
    )
    return candidates


def is_image(body, content_type):
    if content_type.startswith("image/") and len(body) >= 32:
        return True
    signatures = (
        b"\xff\xd8\xff",
        b"\x89PNG\r\n\x1a\n",
        b"GIF87a",
        b"GIF89a",
        b"RIFF",
    )
    return len(body) >= 32 and (
        body.startswith(signatures) or b"ftypavif" in body[:32] or b"ftypheic" in body[:32]
    )


def check_provider(provider):
    name = provider.get("name", provider.get("id", "Desconocido"))
    base = provider["domains"][0]
    base_ok, base_detail = check_url(base)
    if not base_ok:
        return False, base_detail

    probe_url = provider_probe_url(provider)
    try:
        _, final_url, content_type, body = fetch_probe(probe_url)
        candidates = image_candidates(body, content_type, final_url, provider)
    except urllib.error.HTTPError as error:
        if error.code in (401, 403, 429):
            return True, f"HTTP {error.code}: GitHub no puede hacer la prueba completa"
        return False, f"el catálogo de {name} responde HTTP {error.code}"
    except (ValueError, json.JSONDecodeError) as error:
        return False, f"el catálogo cambió de estructura: {error}"
    except Exception as error:
        return False, f"no se pudo abrir el catálogo: {error}"

    if not candidates:
        return False, "el catálogo responde, pero no se encuentra ninguna portada"

    errors = []
    for image_url in candidates[:8]:
        try:
            status, _, image_type, image_body = fetch_probe(
                image_url,
                referer=final_url,
                byte_limit=16384,
            )
            if 200 <= status < 400 and is_image(image_body, image_type):
                return True, "catálogo y una imagen comprobados correctamente"
            errors.append(f"HTTP {status} o contenido no válido")
        except urllib.error.HTTPError as error:
            errors.append(f"HTTP {error.code}")
        except Exception as error:
            errors.append(str(error))
    return False, "se encontraron mangas, pero no se pudo cargar ninguna imagen: " + errors[0]


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
    migrating_state = previous.get("monitorVersion") != 3
    current_targets = {}
    incidents = []
    recoveries = []

    enabled_providers = [
        provider
        for provider in config.get("providers", [])
        if isinstance(provider, dict) and provider.get("enabled", True)
    ]
    for provider in enabled_providers:
        provider_id = provider.get("id", provider.get("name", "desconocido"))
        label = provider.get("name", provider_id)
        language = provider.get("language", {}).get("name")
        if language:
            label = f"{label} ({language})"
        healthy, detail = check_provider(provider)
        print(f"{'OK' if healthy else 'ERROR'} · {label}: {detail}")
        current_targets[provider_id] = {
            "healthy": healthy,
            "name": label,
        }
        old = previous.get("targets", {}).get(provider_id)
        if not healthy and (old is None or old.get("healthy", True)):
            incidents.append(f"• {label}\n  {detail}")
        elif healthy and old is not None and not old.get("healthy", True) and not migrating_state:
            recoveries.append(f"• {label}")

    was_config_valid = previous.get("configValid", True)
    if validation_errors and was_config_valid:
        incidents.insert(0, "• providers.json inválido\n  " + "\n  ".join(validation_errors))
    elif not validation_errors and not was_config_valid and not migrating_state:
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
            f"Se han probado {len(current_targets)} catálogos y sus imágenes.",
        )
    if message_parts:
        telegram("\n\n".join(message_parts))

    state = {
        "monitorVersion": 3,
        "configValid": not validation_errors,
        "configErrors": validation_errors,
        "targets": current_targets,
    }
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(
        json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Comprobados {len(current_targets)} proveedores; {len(incidents)} incidencias; {len(recoveries)} recuperaciones")


if __name__ == "__main__":
    main()
