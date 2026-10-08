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
    def __init__(self, api_root):
        self.api_root = os.path.abspath(api_root)
        self.cache = {}
        self.lock = threading.RLock()
        self.route_signature = None

    def _signature(self):
        files = []
        if not os.path.isdir(self.api_root):
            return ()
        for root, _, names in os.walk(self.api_root):
            for name in names:
                if not name.endswith(".py") or name.startswith("_"):
                    continue
                path = os.path.join(root, name)
                try:
                    files.append((path, os.path.getmtime(path), os.path.getsize(path)))
                except OSError:
                    pass
        return tuple(sorted(files))

    def refresh(self):
        signature = self._signature()
        if signature != self.route_signature:
            with self.lock:
                if signature != self.route_signature:
                    self.cache.clear()
                    self.route_signature = signature

    def _safe_path(self, path):
        try:
            return os.path.commonpath([self.api_root, os.path.abspath(path)]) == self.api_root
        except ValueError:
            return False

    def _load_module(self, path, route):
        path = os.path.abspath(path)
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return None

        with self.lock:
            cached = self.cache.get(path)
            if cached and cached[0] == mtime:
                return cached[1], cached[2], dict(cached[3])

            module_name = "rpg_api_" + hashlib.sha256(path.encode("utf-8")).hexdigest()
            sys.modules.pop(module_name, None)
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                return None

            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            params = {}
            self.cache[path] = (mtime, module, route, params)
            return module, route, params

    def discover(self):
        self.refresh()
        routes = []
        if not os.path.isdir(self.api_root):
            return routes

        for root, _, names in os.walk(self.api_root):
            for name in sorted(names):
                if not name.endswith(".py") or name.startswith("_"):
                    continue
                path = os.path.join(root, name)
                relative = os.path.relpath(path, self.api_root).replace(os.sep, "/")[:-3]
                parts = relative.split("/")
                if parts[-1] == "index":
                    parts = parts[:-1]
                route = "/api" + ("/" + "/".join(parts) if parts else "")
                routes.append((route, path))
        return routes

    def resolve(self, request_path):
        self.refresh()
        if request_path != "/api" and not request_path.startswith("/api/"):
            return None

        relative = request_path[4:].strip("/")
        parts = [part for part in relative.split("/") if part] if relative else ["index"]

        direct = os.path.join(self.api_root, *parts) + ".py"
        if self._safe_path(direct) and os.path.isfile(direct):
            route = "/api/" + "/".join(parts)
            return self._load_module(direct, route)

        index_path = os.path.join(self.api_root, *parts, "index.py")
        if self._safe_path(index_path) and os.path.isfile(index_path):
            route = "/api/" + "/".join(parts)
            return self._load_module(index_path, route)

        if len(parts) >= 2:
            parent = parts[:-1]
            dynamic_path = os.path.join(self.api_root, *parent, "[id].py")
            if self._safe_path(dynamic_path) and os.path.isfile(dynamic_path):
                route = "/api/" + "/".join(parent + ["[id]"])
                result = self._load_module(dynamic_path, route)
                if result:
                    module, route, params = result
                    params = dict(params)
                    params["id"] = parts[-1]
                    return module, route, params
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
        for route, file_path in self.router.discover():
            try:
                result = self.router._load_module(file_path, route)
            except Exception:
                continue
            if not result:
                continue

            module, _, _ = result
            docs = getattr(module, "swagger", {}) or {}
            methods = getattr(module, "methods", ["GET"])
            openapi_route = re.sub(r"\[([^\]]+)\]", r"{\1}", route)

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
                    module, _route, params = api_result
                    request.params = params
                    request.api_module = module
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

        # Los endpoints y la documentación tienen espacios separados.
        if path == "/api" or path.startswith("/api/"):
            return WebResponse().json({"success": False, "message": "API endpoint not found"}, 404)

        # Archivos estáticos: /static/css/site.css
        static_root = self._absolute_path(self.config.get("server", "static_root", default="./static"))
        document_root = self._absolute_path(self.config.get("server", "document_root", default="./web"))

        if path == "/static" or path.startswith("/static/"):
            relative = path[len("/static"):].lstrip("/")
            static_path = os.path.abspath(os.path.join(static_root, relative))
            if not self._safe_path(static_root, static_path):
                return WebResponse().text("Forbidden", 403)
            return self.serve_file(static_path)

        # RUTAS VIRTUALES:
        # /web/login       -> web/login.web
        # /web/admin       -> web/admin.web o web/admin/index.web
        # /web/admin/      -> web/admin/index.web
        # /web/admin/login -> web/admin/login.web
        # Este prefijo separado evita conflictos con /api/...
        if path == "/web" or path.startswith("/web/"):
            return self.serve_virtual_web(path, document_root)

        # Mantiene compatibilidad con URLs antiguas y la raíz /.
        relative_path = path.lstrip("/")
        web_path = os.path.abspath(os.path.join(document_root, relative_path))
        if not self._safe_path(document_root, web_path):
            return WebResponse().text("Forbidden", 403)

        if path == "/" or path.endswith("/") or os.path.isdir(web_path):
            web_path = os.path.join(web_path, self.config.get("web", "index", default="index.web"))

        if not self._safe_path(document_root, web_path):
            return WebResponse().text("Forbidden", 403)
        if not os.path.isfile(web_path):
            return WebResponse().text("Not Found", 404)

        extension = self.config.get("web", "extension", default=".web")
        if web_path.endswith(extension):
            return self.render_web_file(web_path, request)
        return self.serve_file(web_path)

    def serve_virtual_web(self, request_path, document_root):
        extension = self.config.get("web", "extension", default=".web")
        index_name = self.config.get("web", "index", default="index.web")

        if request_path == "/web":
            relative = ""
            has_trailing_slash = True
        else:
            relative = request_path[len("/web/"):]
            has_trailing_slash = request_path.endswith("/")

        relative = unquote(relative).strip("/")
        if not relative:
            candidate = os.path.join(document_root, index_name)
            if not self._safe_path(document_root, candidate):
                return WebResponse().text("Forbidden", 403)
            return self.render_web_file(candidate, None) if os.path.isfile(candidate) else WebResponse().text("Not Found", 404)

        requested = os.path.abspath(os.path.join(document_root, relative))
        if not self._safe_path(document_root, requested):
            return WebResponse().text("Forbidden", 403)

        # /web/admin/ -> web/admin/index.web
        if has_trailing_slash or os.path.isdir(requested):
            candidate = os.path.join(requested, index_name)
            if not self._safe_path(document_root, candidate):
                return WebResponse().text("Forbidden", 403)
            if os.path.isfile(candidate):
                return self.render_web_file(candidate, None)
            return WebResponse().text("Not Found", 404)

        # Si se indica explícitamente .web, resolver ese archivo.
        if requested.endswith(extension):
            candidate = requested
        else:
            # /web/login -> web/login.web
            candidate = requested + extension

        if not self._safe_path(document_root, candidate):
            return WebResponse().text("Forbidden", 403)
        if os.path.isfile(candidate):
            return self.render_web_file(candidate, None)

        # Permitir /web/carpeta si contiene index.web.
        if os.path.isdir(requested):
            index_path = os.path.join(requested, index_name)
            if self._safe_path(document_root, index_path) and os.path.isfile(index_path):
                return self.render_web_file(index_path, None)

        return WebResponse().text("Not Found", 404)

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

    def render_web_file(self, path, request=None):
        document_root = self._absolute_path(self.config.get("server", "document_root", default="./web"))
        if not self._safe_path(document_root, path):
            return WebResponse().text("Forbidden", 403)
        if not os.path.isfile(path):
            return WebResponse().text("Not Found", 404)

        if request is None:
            # Las rutas virtuales llegan aquí desde dispatch; usar la petición actual.
            request = getattr(self, "_current_request", None)
        if request is None:
            return WebResponse().text("Internal Server Error", 500)

        extension = self.config.get("web", "extension", default=".web")
        if not path.endswith(extension):
            return self.serve_file(path)

        with open(path, "r", encoding="utf-8") as file:
            source = file.read()

        server_info = {
            "name": self.config.get("server", "server_name", default="RPG Web Server"),
            "host": self.config.get("server", "host", default="0.0.0.0"),
            "port": self.config.get("server", "port", default=8080)
        }
        csrf_token = request.session.csrf_token if request.session else ""
        rendered = self.interpreter.render(source, request, request.session, server_info, csrf_token)
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
                module, _route, params = api_result
                request.params = params
                request.api_module = module
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
<p><a href="/web/login">Abrir login</a></p>
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

    api_router = ApiRouter(api_root)
    swagger_builder = SwaggerBuilder(api_router, config)

    RPGRequestHandler.config = config
    RPGRequestHandler.logger = logger
    RPGRequestHandler.sessions = sessions
    RPGRequestHandler.interpreter = interpreter
    RPGRequestHandler.api_router = api_router
    RPGRequestHandler.swagger_builder = swagger_builder

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
    print("Rutas    : /web/nombre -> web/nombre.web")
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
