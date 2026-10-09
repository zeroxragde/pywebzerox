# ============================================================
# RPG Web Server
# ============================================================

import copy
import hashlib
import hmac
import html
import importlib.util
import json
import mimetypes
import os
import re
import secrets
import sys
import threading
import traceback
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from routes import RouteManager

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")

DEFAULT_CONFIG = {
    "server": {
        "host": "0.0.0.0",
        "port": 8080,
        "server_name": "RPG Web Server",
        "document_root": "./web",
        "static_root": "./static",
        "api_root": "./api",
        "max_body_size_mb": 10
    },
    "web": {
        "extension": ".web",
        "index": "index.web",
        "interpreter": True,
        "debug": True
    },
    "session": {
        "enabled": True,
        "cookie_name": "RPGSESSION",
        "lifetime_minutes": 60,
        "renew_on_request": True,
        "http_only": True,
        "secure": False,
        "same_site": "Lax",
        "path": "/"
    },
    "csrf": {
        "enabled": True,
        "token_length": 32,
        "field_name": "_token",
        "header_name": "X-CSRF-TOKEN",
        "protect_methods": ["POST", "PUT", "PATCH", "DELETE"],
        "verify_origin": True,
        "excluded_paths": []
    },
    "swagger": {
        "enabled": True,
        "path": "/swagger",
        "json_path": "/swagger/openapi.json",
        "title": "RPG API",
        "version": "1.0.0",
        "ui_cdn_base": "https://unpkg.com/swagger-ui-dist@5"
    },
    "routing": {
        "enabled": True,
        "routes_file": "./routes.py",
        "auto_discover": True,
        "api_auto_discover": False,
        "legacy_web_prefix_redirect": True
    },
    "security": {
        "directory_listing": False,
        "allow_hidden_files": False
    },
    "logging": {
        "enabled": True,
        "access_log": "./logs/access.log",
        "error_log": "./logs/error.log"
    }
}


def deep_merge(defaults, current):
    for key, value in defaults.items():
        if key not in current:
            current[key] = copy.deepcopy(value)
        elif isinstance(value, dict) and isinstance(current[key], dict):
            deep_merge(value, current[key])


class Config:
    def __init__(self, path=CONFIG_FILE):
        self.path = path
        self.data = self.load()

    def load(self):
        if not os.path.exists(self.path):
            data = copy.deepcopy(DEFAULT_CONFIG)
            with open(self.path, "w", encoding="utf-8") as file:
                json.dump(data, file, indent=4, ensure_ascii=False)
            return data

        with open(self.path, "r", encoding="utf-8") as file:
            current = json.load(file)

        original = json.dumps(current, sort_keys=True)
        deep_merge(DEFAULT_CONFIG, current)
        if json.dumps(current, sort_keys=True) != original:
            with open(self.path, "w", encoding="utf-8") as file:
                json.dump(current, file, indent=4, ensure_ascii=False)
        return current

    def get(self, *keys, default=None):
        value = self.data
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default


class Logger:
    def __init__(self, config):
        self.enabled = config.get("logging", "enabled", default=True)
        self.access_log = self.resolve(config.get("logging", "access_log", default="./logs/access.log"))
        self.error_log = self.resolve(config.get("logging", "error_log", default="./logs/error.log"))
        self.lock = threading.RLock()
        if self.enabled:
            for path in (self.access_log, self.error_log):
                directory = os.path.dirname(path)
                if directory:
                    os.makedirs(directory, exist_ok=True)

    @staticmethod
    def resolve(path):
        return path if os.path.isabs(path) else os.path.join(BASE_DIR, path)

    def _write(self, path, message):
        if not self.enabled:
            return
        with self.lock:
            with open(path, "a", encoding="utf-8") as file:
                timestamp = datetime.now().isoformat(sep=" ", timespec="seconds")
                file.write(f"[{timestamp}] {message}\n")

    def access(self, message):
        self._write(self.access_log, message)

    def error(self, message):
        self._write(self.error_log, message)


class Session:
    def __init__(self, session_id, lifetime_minutes, csrf_length):
        now = datetime.now()
        self.id = session_id
        self.created_at = now
        self.last_access = now
        self.expires_at = now + timedelta(minutes=lifetime_minutes)
        self.csrf_token = secrets.token_urlsafe(csrf_length)
        self.data = {}

    def is_expired(self):
        return datetime.now() >= self.expires_at

    def renew(self, lifetime_minutes):
        self.last_access = datetime.now()
        self.expires_at = self.last_access + timedelta(minutes=lifetime_minutes)


class SessionManager:
    def __init__(self, config):
        self.enabled = config.get("session", "enabled", default=True)
        self.lifetime = int(config.get("session", "lifetime_minutes", default=60))
        self.csrf_length = int(config.get("csrf", "token_length", default=32))
        self.sessions = {}
        self.lock = threading.RLock()

    def create(self):
        with self.lock:
            session_id = secrets.token_urlsafe(48)
            while session_id in self.sessions:
                session_id = secrets.token_urlsafe(48)
            session = Session(session_id, self.lifetime, self.csrf_length)
            self.sessions[session_id] = session
            return session

    def get(self, session_id):
        if not self.enabled or not session_id:
            return None
        with self.lock:
            session = self.sessions.get(session_id)
            if not session:
                return None
            if session.is_expired():
                self.sessions.pop(session_id, None)
                return None
            return session

    def regenerate(self, old_session=None):
        new_session = self.create()
        if old_session:
            new_session.data = dict(old_session.data)
            self.destroy(old_session.id)
        return new_session

    def destroy(self, session_id):
        with self.lock:
            self.sessions.pop(session_id, None)

    def cleanup(self):
        with self.lock:
            expired = [sid for sid, session in self.sessions.items() if session.is_expired()]
            for sid in expired:
                self.sessions.pop(sid, None)


class WebRequest:
    def __init__(self, handler, session):
        parsed = urlparse(handler.path)
        self.handler = handler
        self.method = handler.command.upper()
        self.path = unquote(parsed.path)
        self.query_string = parsed.query
        self.query = {
            key: values[-1]
            for key, values in parse_qs(parsed.query, keep_blank_values=True).items()
        }
        self.headers = {key.lower(): value for key, value in handler.headers.items()}
        self.form = {}
        self.json = None
        self.params = {}
        self.session = session
        self.api_module = None
        if self.method in ("POST", "PUT", "PATCH", "DELETE"):
            self._read_body()

    def _read_body(self):
        length = int(self.headers.get("content-length", "0") or "0")
        raw = self.handler.read_body(length)
        content_type = self.headers.get("content-type", "").lower()

        if "application/json" in content_type:
            try:
                self.json = json.loads(raw.decode("utf-8") or "{}")
            except (UnicodeDecodeError, json.JSONDecodeError):
                self.json = None
            return

        if "application/x-www-form-urlencoded" in content_type or raw:
            decoded = raw.decode("utf-8")
            self.form = {
                key: values[-1]
                for key, values in parse_qs(decoded, keep_blank_values=True).items()
            }

    def get(self, name, default=None):
        if name in self.params:
            return self.params[name]
        if name in self.query:
            return self.query[name]
        if name in self.form:
            return self.form[name]
        if isinstance(self.json, dict) and name in self.json:
            return self.json[name]
        return default

    def input(self, name, default=None):
        return self.get(name, default)


class WebResponse:
    def __init__(self):
        self.status = 200
        self.headers = {"Content-Type": "text/html; charset=utf-8"}
        self.body = b""

    def set_header(self, name, value):
        self.headers[name] = str(value)
        return self

    def text(self, value, status=200):
        self.status = status
        self.headers["Content-Type"] = "text/plain; charset=utf-8"
        self.body = str(value).encode("utf-8")
        return self

    def html(self, value, status=200):
        self.status = status
        self.headers["Content-Type"] = "text/html; charset=utf-8"
        self.body = str(value).encode("utf-8")
        return self

    def json(self, value, status=200):
        self.status = status
        self.headers["Content-Type"] = "application/json; charset=utf-8"
        self.body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        return self


class ApiRouter:
    """Resuelve endpoints declarados en API_ROUTES dentro de routes.py.

    Por defecto NO publica automáticamente todos los .py de api/.
    El destino físico de cada endpoint se configura expresamente en routes.py.
    """

    def __init__(self, api_root, route_manager, project_root=None, auto_discover=False):
        self.api_root = os.path.abspath(api_root)
        self.route_manager = route_manager
        self.project_root = os.path.abspath(project_root or BASE_DIR)
        self.auto_discover = bool(auto_discover)
        self.cache = {}
        self.lock = threading.RLock()

    def _safe_path(self, root, path):
        try:
            return os.path.commonpath([
                os.path.abspath(root),
                os.path.abspath(path)
            ]) == os.path.abspath(root)
        except (ValueError, OSError):
            return False

    def _route_definition(self, entry):
        if isinstance(entry, str):
            return {"file": entry}
        if isinstance(entry, dict):
            return entry
        return None

    def _resolve_target(self, definition):
        if not isinstance(definition, dict):
            return None

        relative_file = definition.get("file")
        if not isinstance(relative_file, str) or not relative_file.strip():
            return None
        if os.path.isabs(relative_file):
            return None

        # Las rutas de archivo se expresan respecto a la raíz del proyecto,
        # por ejemplo: api/auth/register.py o controllers/auth/register.py.
        target = os.path.abspath(
            os.path.join(self.project_root, relative_file)
        )
        if not self._safe_path(self.project_root, target):
            return None

        if not target.endswith(".py"):
            target += ".py"

        # Solo se permiten destinos Python; evitar publicar rutas ocultas.
        relative = os.path.relpath(target, self.project_root)
        if any(part.startswith(".") for part in relative.split(os.sep)):
            return None

        if not os.path.isfile(target):
            return None

        return target

    def _configured_routes(self):
        routes = self.route_manager.get_api_routes()
        if not isinstance(routes, dict):
            routes = {}
        result = dict(routes)

        # Compatibilidad opcional. Desactivada por defecto para que las URLs
        # públicas de la API se administren desde routes.py.
        if self.auto_discover and os.path.isdir(self.api_root):
            for root, _, names in os.walk(self.api_root):
                for name in sorted(names):
                    if not name.endswith(".py") or name.startswith("_"):
                        continue
                    physical_path = os.path.join(root, name)
                    relative = os.path.relpath(
                        physical_path,
                        self.project_root
                    ).replace(os.sep, "/")[:-3]
                    parts = relative.split("/")
                    if parts[-1] == "index":
                        parts = parts[:-1]
                    if parts and parts[-1] == "[id]":
                        parts[-1] = "{id}"
                    route = "/api" + ("/" + "/".join(parts) if parts else "")
                    result.setdefault(route, {"file": relative + ".py"})

        return result

    def _load_module(self, path, route):
        path = os.path.abspath(path)
        try:
            mtime = os.path.getmtime(path)
            size = os.path.getsize(path)
        except OSError:
            return None

        with self.lock:
            cached = self.cache.get(path)
            if cached and cached[0] == (mtime, size):
                return cached[1], cached[2], dict(cached[3])

            module_name = "rpg_api_" + hashlib.sha256(
                path.encode("utf-8")
            ).hexdigest()
            sys.modules.pop(module_name, None)
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                return None

            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            params = {}
            self.cache[path] = ((mtime, size), module, route, params)
            return module, route, params

    def discover(self):
        """Lista solo las rutas API registradas y cuyos scripts existen."""
        discovered = []
        definitions = self._configured_routes()

        for route, entry in sorted(definitions.items(), key=lambda item: str(item[0])):
            if not isinstance(route, str):
                continue

            normalized_route = RouteManager._normalize_path(route)
            if normalized_route is None:
                continue
            if normalized_route != "/api" and not normalized_route.startswith("/api/"):
                continue

            definition = self._route_definition(entry)
            target = self._resolve_target(definition)
            if target is None:
                continue

            discovered.append((normalized_route, target, definition))

        return discovered

    def resolve(self, request_path):
        path = RouteManager._normalize_path(request_path)
        if path is None:
            return None
        if path != "/api" and not path.startswith("/api/"):
            return None

        definitions = self._configured_routes()
        ordered_routes = sorted(
            definitions.items(),
            key=lambda item: ("{" in str(item[0]), -len(str(item[0])))
        )

        for route_template, entry in ordered_routes:
            if not isinstance(route_template, str):
                continue

            route_template = RouteManager._normalize_path(route_template)
            if route_template is None:
                continue
            if route_template != "/api" and not route_template.startswith("/api/"):
                continue

            params = RouteManager._template_match(route_template, path)
            if params is None:
                continue

            definition = self._route_definition(entry)
            target = self._resolve_target(definition)
            if target is None:
                continue

            loaded = self._load_module(target, route_template)
            if not loaded:
                continue

            module, matched_route, _cached_params = loaded
            # Devolver la definición para que los métodos y metadatos provengan
            # de routes.py, con fallback a `methods` dentro del endpoint.
            return module, matched_route, params, definition

        return None


class SwaggerBuilder:
    def __init__(self, router, config):
        self.router = router
        self.config = config

    @staticmethod
    def _summary(path):
        name = path.rstrip("/").split("/")[-1] or "API"
        return name.replace("_", " ").replace("-", " ").title()

    def build(self):
        paths = {}
        for route, file_path, definition in self.router.discover():
            try:
                result = self.router._load_module(file_path, route)
            except Exception:
                continue
            if not result:
                continue

            module, _, _ = result
            docs = getattr(module, "swagger", {}) or {}
            methods = definition.get("methods") or getattr(module, "methods", ["GET"])
            openapi_route = route

            for method in methods:
                method = str(method).lower()
                operation = {
                    "summary": docs.get("summary", self._summary(route)),
                    "responses": docs.get("responses", {
                        "200": {"description": "Successful response"}
                    })
                }
                for source_key, target_key in (
                    ("description", "description"),
                    ("tags", "tags"),
                    ("operation_id", "operationId"),
                    ("parameters", "parameters"),
                    ("request_body", "requestBody")
                ):
                    if docs.get(source_key):
                        operation[target_key] = docs[source_key]

                if "operationId" not in operation:
                    operation["operationId"] = re.sub(
                        r"[^A-Za-z0-9_]+", "_",
                        f"{method}_{openapi_route.strip('/')}"
                    ).strip("_")

                path_params = re.findall(r"{([^}]+)}", openapi_route)
                if path_params:
                    parameters = operation.setdefault("parameters", [])
                    existing = {
                        item.get("name") for item in parameters
                        if item.get("in") == "path"
                    }
                    for param in path_params:
                        if param not in existing:
                            parameters.append({
                                "name": param,
                                "in": "path",
                                "required": True,
                                "schema": {"type": "string"}
                            })
                paths.setdefault(openapi_route, {})[method] = operation

        return {
            "openapi": "3.0.3",
            "info": {
                "title": self.config.get("swagger", "title", default="RPG API"),
                "version": self.config.get("swagger", "version", default="1.0.0")
            },
            "servers": [{"url": "/"}],
            "paths": paths
        }


class WebInterpreter:
    BLOCK_RE = re.compile(r"<\?web(.*?)\?>|<\?=(.*?)\?>", re.DOTALL)

    def __init__(self, config):
        self.enabled = config.get("web", "interpreter", default=True)

    def render(self, source, request, session, server_info, csrf_token):
        source = source.replace(
            "@csrf",
            ('<input type="hidden" name="_token" value="' + html.escape(str(csrf_token), quote=True) + '">')
            if csrf_token else ""
        )
        if not self.enabled:
            return source

        env = {
            "request": request,
            "session": session,
            "server": server_info,
            "csrf_token": csrf_token,
            "csrf": csrf_token
        }
        # El intérprete ejecuta Python; estos builtins reducidos NO constituyen un sandbox.
        safe_builtins = {
            "str": str, "int": int, "float": float, "bool": bool,
            "len": len, "range": range, "enumerate": enumerate,
            "min": min, "max": max, "sum": sum, "round": round,
            "print": print
        }

        result = []
        cursor = 0
        for match in self.BLOCK_RE.finditer(source):
            result.append(source[cursor:match.start()])
            code = match.group(1)
            expression = match.group(2)

            if code is not None:
                local_env = dict(env)
                exec(code, {"__builtins__": safe_builtins}, local_env)
                for key, value in local_env.items():
                    if not key.startswith("__"):
                        env[key] = value
            else:
                value = eval(expression, {"__builtins__": safe_builtins}, env)
                result.append("" if value is None else str(value))
            cursor = match.end()

        result.append(source[cursor:])
        return "".join(result)


class RPGRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "RPGWebServer/1.0"

    config = None
    logger = None
    sessions = None
    interpreter = None
    api_router = None
    swagger_builder = None
    route_manager = None

    def log_message(self, fmt, *args):
        if self.logger:
            self.logger.access(f"{self.address_string()} - {fmt % args}")

    def read_body(self, length):
        max_size = int(self.config.get("server", "max_body_size_mb", default=10)) * 1024 * 1024
        if length > max_size:
            raise ValueError("Payload Too Large")
        if length <= 0:
            return b""
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise ValueError("Incomplete request body")
        return raw

    def _session_from_cookie(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:
            return None
        morsel = cookie.get(self.config.get("session", "cookie_name", default="RPGSESSION"))
        return self.sessions.get(morsel.value) if morsel else None

    def _set_session_cookie(self, session_id):
        name = self.config.get("session", "cookie_name", default="RPGSESSION")
        lifetime = int(self.config.get("session", "lifetime_minutes", default=60)) * 60
        path = self.config.get("session", "path", default="/")
        parts = [
            f"{name}={session_id}",
            f"Path={path}",
            f"Max-Age={lifetime}",
            f"SameSite={self.config.get('session', 'same_site', default='Lax')}"
        ]
        if self.config.get("session", "http_only", default=True):
            parts.append("HttpOnly")
        if self.config.get("session", "secure", default=False):
            parts.append("Secure")
        self.send_header("Set-Cookie", "; ".join(parts))

    def setup_request(self):
        session = self._session_from_cookie()
        created = False
        if self.sessions.enabled and session is None:
            session = self.sessions.create()
            created = True
        elif session and self.config.get("session", "renew_on_request", default=True):
            session.renew(self.sessions.lifetime)
        return session, created

    def validate_csrf(self, request, session):
        cfg = self.config.get("csrf", default={}) or {}
        if not cfg.get("enabled", True):
            return True
        if request.method not in cfg.get("protect_methods", []):
            return True
        if request.path in cfg.get("excluded_paths", []):
            return True

        module = getattr(request, "api_module", None)
        if module is not None and getattr(module, "csrf_exempt", False):
            return True

        if cfg.get("verify_origin", True):
            origin = request.headers.get("origin")
            host = request.headers.get("host")
            if origin and host:
                secure = self.config.get("session", "secure", default=False)
                expected = ("https" if secure else "http") + "://" + host
                if origin.rstrip("/") != expected.rstrip("/"):
                    return False

        if not session:
            return False
        header_name = cfg.get("header_name", "X-CSRF-TOKEN").lower()
        token = request.headers.get(header_name)
        if token is None:
            token = request.get(cfg.get("field_name", "_token"))
        if not token:
            return False
        return hmac.compare_digest(str(token), str(session.csrf_token))

    def do_GET(self):
        self.dispatch()

    def do_HEAD(self):
        self.dispatch(head_only=True)

    def do_POST(self):
        self.dispatch()

    def do_PUT(self):
        self.dispatch()

    def do_PATCH(self):
        self.dispatch()

    def do_DELETE(self):
        self.dispatch()

    def dispatch(self, head_only=False):
        started = datetime.now()
        session = None
        session_created = False

        try:
            session, session_created = self.setup_request()
            request = WebRequest(self, session)

            swagger_response = self.handle_swagger(request)
            if swagger_response is not None:
                response = swagger_response
            else:
                api_result = self.api_router.resolve(request.path)
                if api_result:
                    module, _route, params, definition = api_result
                    request.params = params
                    request.api_module = module
                    request.api_methods = definition.get("methods")
                    request.route_name = definition.get("name")
                    response = self.handle_api(module, request)
                else:
                    request.api_module = None
                    response = self.handle_web_or_static(request)

            self.send_response(response.status)
            for name, value in response.headers.items():
                self.send_header(name, value)
            if session_created and session:
                self._set_session_cookie(session.id)
            self.send_header("Content-Length", str(0 if head_only else len(response.body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if not head_only and response.body:
                self.wfile.write(response.body)

            elapsed = (datetime.now() - started).total_seconds() * 1000
            self.logger.access(f"{self.command} {self.path} -> {response.status} ({elapsed:.1f} ms)")

        except ValueError as exc:
            self._send_error_response(WebResponse().json({"success": False, "message": str(exc)}, 413), head_only)
        except Exception:
            error = traceback.format_exc()
            if self.logger:
                self.logger.error(error)
            message = error if self.config.get("web", "debug", default=False) else "Internal Server Error"
            self._send_error_response(WebResponse().text(message, 500), head_only)

    def _send_error_response(self, response, head_only=False):
        try:
            self.send_response(response.status)
            for name, value in response.headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(0 if head_only else len(response.body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if not head_only and response.body:
                self.wfile.write(response.body)
        except Exception:
            pass

    def handle_swagger(self, request):
        cfg = self.config.get("swagger", default={}) or {}
        if not cfg.get("enabled", True):
            return None

        swagger_path = str(cfg.get("path", "/swagger")).rstrip("/") or "/swagger"
        json_path = str(cfg.get("json_path", swagger_path + "/openapi.json"))

        if request.path == json_path:
            return WebResponse().json(self.swagger_builder.build(), 200)

        if request.path in (swagger_path, swagger_path + "/"):
            cdn = str(cfg.get("ui_cdn_base", "https://unpkg.com/swagger-ui-dist@5")).rstrip("/")
            title = html.escape(str(cfg.get("title", "RPG API")) + " - Swagger")
            css_url = html.escape(cdn + "/swagger-ui.css", quote=True)
            js_url = html.escape(cdn + "/swagger-ui-bundle.js", quote=True)
            json_url = json.dumps(json_path)
            page = f'''<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="stylesheet" href="{css_url}">
</head>
<body>
<div id="swagger-ui"></div>
<script src="{js_url}"></script>
<script>
window.onload = function() {{
  window.ui = SwaggerUIBundle({{
    url: {json_url},
    dom_id: '#swagger-ui',
    deepLinking: true,
    presets: [SwaggerUIBundle.presets.apis],
    layout: 'BaseLayout'
  }});
}};
</script>
</body>
</html>'''
            return WebResponse().html(page, 200)
        return None

    def handle_api(self, module, request):
        methods = getattr(request, "api_methods", None)
        if methods is None:
            methods = getattr(module, "methods", None)
        if methods is not None:
            allowed = {str(method).upper() for method in methods}
            if request.method not in allowed:
                return WebResponse().json(
                    {"success": False, "message": "Method Not Allowed"}, 405
                ).set_header("Allow", ", ".join(sorted(allowed)))

        if not self.validate_csrf(request, request.session):
            return WebResponse().json({"success": False, "message": "CSRF validation failed"}, 403)

        endpoint = getattr(module, "endpoint", None)
        if not callable(endpoint):
            return WebResponse().json({
                "success": False,
                "message": "El endpoint debe definir endpoint(request, response)"
            }, 500)

        response = WebResponse()
        result = endpoint(request, response)
        if isinstance(result, WebResponse):
            return result
        if result is None:
            return response
        if isinstance(result, tuple) and len(result) == 2:
            payload, status = result
            return response.json(payload, int(status))
        return response.json(result)

    def handle_web_or_static(self, request):
        path = request.path

        # La API tiene un espacio reservado y nunca se resuelve como página .web.
        if path == "/api" or path.startswith("/api/"):
            return WebResponse().json(
                {"success": False, "message": "API endpoint not found"},
                404
            )

        # Recursos estáticos: /static/css/site.css
        static_root = self._absolute_path(
            self.config.get("server", "static_root", default="./static")
        )

        if path == "/static" or path.startswith("/static/"):
            relative = path[len("/static"):].lstrip("/")
            static_path = os.path.abspath(
                os.path.join(static_root, relative)
            )
            if not self._safe_path(static_root, static_path):
                return WebResponse().text("Forbidden", 403)
            return self.serve_file(static_path)

        # Rutas virtuales limpias: /login -> web/login.web
        # Las rutas legacy /web/login se redirigen a /login.
        if not self.config.get("routing", "enabled", default=True):
            return self._serve_legacy_web_path(request)

        if self.route_manager is None:
            return WebResponse().text("Internal Server Error: route manager not configured", 500)

        match = self.route_manager.resolve(path)

        if match is None:
            return WebResponse().text("Not Found", 404)

        # Redirección a URL canónica, preservando query string.
        redirect_to = match.get("redirect")
        if redirect_to:
            if request.query_string:
                redirect_to += "?" + request.query_string
            response = WebResponse().text("Redirecting", 301)
            response.set_header("Location", redirect_to)
            return response

        page_path = match.get("file")
        if not page_path:
            return WebResponse().text("Not Found", 404)

        request.params = match.get("params", {})
        request.route_name = match.get("name")

        methods = match.get("methods")
        if methods:
            allowed = {str(method).upper() for method in methods}
            if request.method not in allowed:
                response = WebResponse().text("Method Not Allowed", 405)
                response.set_header("Allow", ", ".join(sorted(allowed)))
                return response

        return self.render_web_file(page_path, request)

    def _serve_legacy_web_path(self, request):
        """Compatibilidad opcional con el modo anterior de publicar /web/... ."""
        path = request.path
        document_root = self._absolute_path(
            self.config.get("server", "document_root", default="./web")
        )
        extension = self.config.get("web", "extension", default=".web")
        index_name = self.config.get("web", "index", default="index.web")

        if path == "/web" or path.startswith("/web/"):
            relative = path[len("/web"):].lstrip("/")
        else:
            relative = path.lstrip("/")

        if not relative:
            candidate = os.path.join(document_root, index_name)
        else:
            requested = os.path.abspath(
                os.path.join(document_root, unquote(relative))
            )
            if not self._safe_path(document_root, requested):
                return WebResponse().text("Forbidden", 403)

            if os.path.isdir(requested):
                candidate = os.path.join(requested, index_name)
            elif requested.endswith(extension):
                candidate = requested
            else:
                candidate = requested + extension

        if not self._safe_path(document_root, candidate):
            return WebResponse().text("Forbidden", 403)
        if not os.path.isfile(candidate):
            return WebResponse().text("Not Found", 404)
        return self.render_web_file(candidate, request)

    @staticmethod
    def _absolute_path(path):
        return path if os.path.isabs(path) else os.path.join(BASE_DIR, path)

    @staticmethod
    def _safe_path(root, target):
        try:
            root = os.path.abspath(root)
            target = os.path.abspath(target)
            return os.path.commonpath([root, target]) == root
        except ValueError:
            return False

    def render_web_file(self, path, request):
        document_root = self._absolute_path(
            self.config.get("server", "document_root", default="./web")
        )
        path = os.path.abspath(path)

        if not self._safe_path(document_root, path):
            return WebResponse().text("Forbidden", 403)
        if not os.path.isfile(path):
            return WebResponse().text("Not Found", 404)

        extension = self.config.get("web", "extension", default=".web")
        if not path.endswith(extension):
            return WebResponse().text("Not Found", 404)

        with open(path, "r", encoding="utf-8") as file:
            source = file.read()

        server_info = {
            "name": self.config.get("server", "server_name", default="RPG Web Server"),
            "host": self.config.get("server", "host", default="0.0.0.0"),
            "port": self.config.get("server", "port", default=8080)
        }
        csrf_token = request.session.csrf_token if request.session else ""
        rendered = self.interpreter.render(
            source,
            request,
            request.session,
            server_info,
            csrf_token
        )
        return WebResponse().html(rendered)

    def serve_file(self, path):
        if not os.path.isfile(path):
            return WebResponse().text("Not Found", 404)
        try:
            with open(path, "rb") as file:
                body = file.read()
        except PermissionError:
            return WebResponse().text("Forbidden", 403)
        response = WebResponse()
        response.body = body
        response.headers["Content-Type"] = mimetypes.guess_type(path)[0] or "application/octet-stream"
        return response

    # Guarda el request actual antes de resolver la ruta virtual.
    def _dispatch_request(self, request):
        self._current_request = request
        try:
            swagger_response = self.handle_swagger(request)
            if swagger_response is not None:
                return swagger_response

            api_result = self.api_router.resolve(request.path)
            if api_result:
                module, _route, params, definition = api_result
                request.params = params
                request.api_module = module
                request.api_methods = definition.get("methods")
                request.route_name = definition.get("name")
                return self.handle_api(module, request)

            request.api_module = None
            return self.handle_web_or_static(request)
        finally:
            self._current_request = None


def prepare_directories():
    directories = [
        os.path.join(BASE_DIR, "web"),
        os.path.join(BASE_DIR, "static", "css"),
        os.path.join(BASE_DIR, "static", "js"),
        os.path.join(BASE_DIR, "static", "images"),
        os.path.join(BASE_DIR, "api", "auth"),
        os.path.join(BASE_DIR, "data"),
        os.path.join(BASE_DIR, "logs")
    ]
    for directory in directories:
        os.makedirs(directory, exist_ok=True)


def create_default_index(config):
    document_root = config.get("server", "document_root", default="./web")
    if not os.path.isabs(document_root):
        document_root = os.path.join(BASE_DIR, document_root)
    os.makedirs(document_root, exist_ok=True)

    index_path = os.path.join(document_root, config.get("web", "index", default="index.web"))
    if os.path.exists(index_path):
        return

    content = '''<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><title>RPG Web Server</title></head>
<body>
<h1>RPG Web Server</h1>
<?web
count = session.data.get("count", 0)
count += 1
session.data["count"] = count
print("Página procesada por Python.")
?>
<p>Visitas de esta sesión: <?= count ?></p>
<form method="POST">@csrf<button type="submit">Probar POST</button></form>
<p><a href="/login">Abrir login</a></p>
</body>
</html>'''
    with open(index_path, "w", encoding="utf-8") as file:
        file.write(content)


def start_server():
    config = Config()
    prepare_directories()
    create_default_index(config)

    logger = Logger(config)
    sessions = SessionManager(config)
    interpreter = WebInterpreter(config)

    api_root = config.get("server", "api_root", default="./api")
    if not os.path.isabs(api_root):
        api_root = os.path.join(BASE_DIR, api_root)

    routes_file = config.get("routing", "routes_file", default="./routes.py")
    if not os.path.isabs(routes_file):
        routes_file = os.path.join(BASE_DIR, routes_file)

    document_root = config.get("server", "document_root", default="./web")
    if not os.path.isabs(document_root):
        document_root = os.path.join(BASE_DIR, document_root)

    route_manager = RouteManager(
        document_root=document_root,
        routes_file=routes_file,
        extension=config.get("web", "extension", default=".web"),
        index_name=config.get("web", "index", default="index.web"),
        auto_discover=config.get("routing", "auto_discover", default=True),
        legacy_web_prefix_redirect=config.get(
            "routing", "legacy_web_prefix_redirect", default=True
        )
    )

    api_router = ApiRouter(
        api_root=api_root,
        route_manager=route_manager,
        project_root=BASE_DIR,
        auto_discover=config.get("routing", "api_auto_discover", default=False)
    )
    swagger_builder = SwaggerBuilder(api_router, config)

    RPGRequestHandler.config = config
    RPGRequestHandler.logger = logger
    RPGRequestHandler.sessions = sessions
    RPGRequestHandler.interpreter = interpreter
    RPGRequestHandler.api_router = api_router
    RPGRequestHandler.swagger_builder = swagger_builder
    RPGRequestHandler.route_manager = route_manager

    host = config.get("server", "host", default="0.0.0.0")
    port = int(config.get("server", "port", default=8080))
    document_root = config.get("server", "document_root", default="./web")
    if not os.path.isabs(document_root):
        document_root = os.path.join(BASE_DIR, document_root)

    httpd = ThreadingHTTPServer((host, port), RPGRequestHandler)

    print()
    print("========================================")
    print("           RPG WEB SERVER")
    print("========================================")
    print(f"Servidor : http://127.0.0.1:{port}")
    print(f"API      : http://127.0.0.1:{port}/api/")
    print(f"Web      : {os.path.abspath(document_root)}")
    if config.get("swagger", "enabled", default=True):
        swagger_path = config.get("swagger", "path", default="/swagger")
        print(f"Swagger  : http://127.0.0.1:{port}{swagger_path}")
    else:
        print("Swagger  : DESACTIVADO")
    print("Rutas    : /login -> web/login.web")
    print(f"Routefile: {os.path.abspath(routes_file)}")
    print("========================================")
    print()

    logger.access(f"Servidor iniciado en {host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor detenido.")
    finally:
        httpd.server_close()
        logger.access("Servidor detenido")


# Replace dispatch implementation with one that keeps the active request
# available to the virtual-web renderer.
def _dispatch(self, head_only=False):
    started = datetime.now()
    session = None
    session_created = False
    try:
        session, session_created = self.setup_request()
        request = WebRequest(self, session)
        response = self._dispatch_request(request)

        self.send_response(response.status)
        for name, value in response.headers.items():
            self.send_header(name, value)
        if session_created and session:
            self._set_session_cookie(session.id)
        self.send_header("Content-Length", str(0 if head_only else len(response.body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if not head_only and response.body:
            self.wfile.write(response.body)

        elapsed = (datetime.now() - started).total_seconds() * 1000
        self.logger.access(f"{self.command} {self.path} -> {response.status} ({elapsed:.1f} ms)")
    except ValueError as exc:
        self._send_error_response(WebResponse().json({"success": False, "message": str(exc)}, 413), head_only)
    except Exception:
        error = traceback.format_exc()
        if self.logger:
            self.logger.error(error)
        message = error if self.config.get("web", "debug", default=False) else "Internal Server Error"
        self._send_error_response(WebResponse().text(message, 500), head_only)

RPGRequestHandler.dispatch = _dispatch

if __name__ == "__main__":
    start_server()
