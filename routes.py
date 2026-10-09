"""Sistema de rutas virtuales del RPG Web Server.

Edición habitual:
    ROUTES = {
        "/": {"file": "index.web", "name": "home"},
        "/login": {"file": "login.web", "name": "login"},
        "/admin": {"file": "admin/index.web", "name": "admin"},
        "/game/{game_id}": {"file": "game/detail.web", "name": "game_detail"},
    }

Los destinos de ROUTES son relativos a ./web. Los destinos de API_ROUTES
son relativos a la raíz del proyecto y deben apuntar a scripts Python.
Si auto_discover web está activado, /perfil también encuentra web/perfil.web.
Los endpoints API no se publican por estructura de carpetas: se declaran aquí.
"""

import importlib.util
import os
import re
import sys
import threading


ROUTES = {
    "/": {
        "file": "ogin.web",
        "name": "home"
    },
    "/login": {
        "file": "login.web",
        "name": "login"
    },
    "/register": {
        "file": "register.web",
        "name": "register"
    },
    # Ejemplos para después:
    # "/admin": {"file": "admin/index.web", "name": "admin"},
    # "/admin/maps": {"file": "admin/maps.web", "name": "admin_maps"},
    # "/game/{game_id}": {"file": "game/detail.web", "name": "game_detail"},
}


# Las URLs públicas de la API se declaran aquí, no se deducen
# automáticamente de la estructura de carpetas.
# "file" es relativo a la raíz del proyecto (donde está server.py).
API_ROUTES = {
    "/api/auth/register": {
        "file": "api/auth/register.py",
        "methods": ["POST"],
        "name": "auth.register"
    },
    # Ejemplos para añadir cuando existan sus scripts:
    # "/api/auth/login": {
    #     "file": "api/auth/login.py",
    #     "methods": ["POST"],
    #     "name": "auth.login"
    # },
    # "/api/maps/{map_id}": {
    #     "file": "api/maps/get.py",
    #     "methods": ["GET"],
    #     "name": "maps.get"
    # },
}


class RouteManager:
    """Carga routes.py, resuelve rutas explícitas y opcionalmente auto-descubre .web."""

    def __init__(
        self,
        document_root,
        routes_file,
        extension=".web",
        index_name="index.web",
        auto_discover=True,
        legacy_web_prefix_redirect=True
    ):
        self.document_root = os.path.abspath(document_root)
        self.routes_file = os.path.abspath(routes_file)
        self.extension = extension
        self.index_name = index_name
        self.auto_discover = bool(auto_discover)
        self.legacy_web_prefix_redirect = bool(legacy_web_prefix_redirect)

        self.routes = {}
        self.api_routes = {}
        self.routes_mtime = None
        self.lock = threading.RLock()
        self.last_load_error = None
        self._load_routes(force=True)

    @staticmethod
    def _safe_path(root, target):
        try:
            root = os.path.abspath(root)
            target = os.path.abspath(target)
            return os.path.commonpath([root, target]) == root
        except (ValueError, OSError):
            return False

    @staticmethod
    def _normalize_path(path):
        if not isinstance(path, str) or "\x00" in path:
            return None

        if not path.startswith("/"):
            path = "/" + path

        # Canonicalizar repetición de separadores y barra final.
        path = re.sub(r"/{2,}", "/", path)
        if path != "/":
            path = path.rstrip("/")

        segments = path.split("/")
        if any(segment in (".", "..") for segment in segments):
            return None

        return path

    def _load_routes(self, force=False):
        try:
            mtime = os.path.getmtime(self.routes_file)
        except OSError:
            mtime = None

        if not force and mtime == self.routes_mtime:
            return

        with self.lock:
            if not force and mtime == self.routes_mtime:
                return

            if mtime is None:
                self.routes = {}
                self.api_routes = {}
                self.routes_mtime = None
                self.last_load_error = None
                return

            module_name = "rpg_web_routes_config"
            try:
                sys.modules.pop(module_name, None)
                spec = importlib.util.spec_from_file_location(
                    module_name,
                    self.routes_file
                )
                if spec is None or spec.loader is None:
                    raise ImportError("No se pudo cargar routes.py")

                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)

                loaded_routes = getattr(module, "ROUTES", {})
                loaded_api_routes = getattr(module, "API_ROUTES", {})

                if not isinstance(loaded_routes, dict):
                    raise TypeError("ROUTES debe ser un diccionario")
                if not isinstance(loaded_api_routes, dict):
                    raise TypeError("API_ROUTES debe ser un diccionario")

                self.routes = loaded_routes
                self.api_routes = loaded_api_routes
                self.routes_mtime = mtime
                self.last_load_error = None

            except Exception as exc:
                # No se cae el servidor si routes.py tiene un error.
                # Las rutas auto-descubiertas pueden seguir funcionando.
                self.routes = {}
                self.api_routes = {}
                self.routes_mtime = mtime
                self.last_load_error = str(exc)

    def get_api_routes(self):
        """Devuelve el mapa API_ROUTES actualizado desde routes.py."""
        self._load_routes()
        return dict(self.api_routes)

    @staticmethod
    def _template_match(template, path):
        """Admite parámetros nombrados con la sintaxis /game/{game_id}."""
        if not isinstance(template, str):
            return None

        template = RouteManager._normalize_path(template)
        if template is None:
            return None

        names = re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", template)
        pattern = re.escape(template)

        for name in names:
            pattern = pattern.replace(
                re.escape("{" + name + "}"),
                rf"(?P<{name}>[^/]+)"
            )

        try:
            match = re.fullmatch(pattern, path)
        except re.error:
            return None

        if not match:
            return None

        return match.groupdict()

    def _match_explicit_route(self, path):
        # Primero rutas exactas, luego las que tienen parámetros.
        for route_template, entry in sorted(
            self.routes.items(),
            key=lambda item: ("{" in str(item[0]), -len(str(item[0])))
        ):
            normalized_template = self._normalize_path(route_template)
            if normalized_template is None:
                continue

            params = self._template_match(normalized_template, path)
            if params is None:
                continue

            if isinstance(entry, str):
                definition = {"file": entry}
            elif isinstance(entry, dict):
                definition = entry
            else:
                continue

            relative_file = definition.get("file")
            if not isinstance(relative_file, str) or not relative_file.strip():
                continue

            # Los destinos son relativos a document_root; no aceptar rutas absolutas.
            if os.path.isabs(relative_file):
                continue

            target = os.path.abspath(
                os.path.join(self.document_root, relative_file)
            )
            if not self._safe_path(self.document_root, target):
                continue

            if not target.endswith(self.extension):
                target += self.extension

            if not os.path.isfile(target):
                # Una ruta explícita a un archivo inexistente no se publica.
                continue

            return {
                "file": target,
                "params": params,
                "name": definition.get("name"),
                "methods": definition.get("methods")
            }

        return None

    def _auto_discover(self, path):
        if not self.auto_discover:
            return None

        # No publicar archivos ocultos a través del sistema automático.
        relative = path.lstrip("/")
        if relative and any(
            segment.startswith(".") for segment in relative.split("/")
        ):
            return None

        requested = os.path.abspath(
            os.path.join(self.document_root, relative)
        )
        if not self._safe_path(self.document_root, requested):
            return None

        # /admin -> web/admin/index.web si admin es una carpeta.
        if os.path.isdir(requested):
            index_path = os.path.abspath(
                os.path.join(requested, self.index_name)
            )
            if (
                self._safe_path(self.document_root, index_path)
                and os.path.isfile(index_path)
            ):
                return {
                    "file": index_path,
                    "params": {},
                    "name": None,
                    "methods": None
                }

        # /login -> web/login.web
        candidate = requested + self.extension
        if (
            self._safe_path(self.document_root, candidate)
            and os.path.isfile(candidate)
        ):
            return {
                "file": candidate,
                "params": {},
                "name": None,
                "methods": None
            }

        return None

    def resolve(self, requested_path):
        self._load_routes()
        path = self._normalize_path(requested_path)
        if path is None:
            return None

        # Migración de URLs antiguas: /web/login -> /login.
        if self.legacy_web_prefix_redirect and (
            path == "/web" or path.startswith("/web/")
        ):
            target = path[len("/web"):]
            if not target:
                target = "/"
            return {"redirect": target}

        # La extensión ya no debe formar parte de la URL pública.
        if path.lower().endswith(self.extension.lower()):
            clean_path = path[:-len(self.extension)]
            clean_match = self._match_explicit_route(clean_path)
            if clean_match is None:
                clean_match = self._auto_discover(clean_path)
            if clean_match is not None:
                return {"redirect": clean_path}

        explicit = self._match_explicit_route(path)
        if explicit is not None:
            return explicit

        return self._auto_discover(path)
