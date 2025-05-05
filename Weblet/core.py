import socket
import ssl
import asyncio
from threading import Thread
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlparse
import json
import os

# Для шаблонов
try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
except ImportError:
    Environment = None

class SimpleServer:
    def __init__(
        self,
        host='127.0.0.1',
        port=8080,
        db_type='sqlite',
        db_config=None,
        use_https=False,
        certfile=None,
        keyfile=None,
        template_folder='templates'
    ):
        self.host = host
        self.port = port
        self.routes = {}
        self.db_type = db_type
        self.db_config = db_config or {}
        self.use_https = use_https
        self.certfile = certfile
        self.keyfile = keyfile
        self.middlewares = []
        # Jinja2 шаблоны
        if Environment and os.path.isdir(template_folder):
            self.template_env = Environment(
                loader=FileSystemLoader(template_folder),
                autoescape=select_autoescape(['html', 'xml'])
            )
        else:
            self.template_env = None

    # --- ROUTING ---
    def route(self, path, methods=['GET']):
        def decorator(func):
            for method in methods:
                self.routes[(path, method.upper())] = func
            return func
        return decorator

    # --- DATABASE ---
    def db(self):
        if self.db_type == 'sqlite':
            import sqlite3
            db_file = self.db_config.get('db_file', '')
            if not db_file:
                raise Exception("No SQLite database file specified")
            return sqlite3.connect(db_file)
        elif self.db_type == 'mysql':
            import mysql.connector
            return mysql.connector.connect(
                host=self.db_config.get('host', 'localhost'),
                user=self.db_config.get('user', ''),
                password=self.db_config.get('password', ''),
                database=self.db_config.get('database', '')
            )
        else:
            raise Exception(f"Unknown db_type: {self.db_type}")

    # --- TEMPLATES ---
    def render_template(self, template_name, **context):
        if not self.template_env:
            raise Exception("Jinja2 is not installed or template folder not found")
        template = self.template_env.get_template(template_name)
        return template.render(**context)

    # --- MIDDLEWARE ---
    def add_middleware(self, func):
        self.middlewares.append(func)

    # --- SERVER START ---
    def start(self):
        if asyncio.iscoroutinefunction(self.handle_client):
            # Асинхронный режим
            asyncio.run(self._start_async())
        else:
            # Синхронный режим
            print(f"Server running on http{'s' if self.use_https else ''}://{self.host}:{self.port}")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((self.host, self.port))
                s.listen(5)
                if self.use_https:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
                    s = context.wrap_socket(s, server_side=True)
                while True:
                    client, _ = s.accept()
                    Thread(target=self.handle_client, args=(client,)).start()

    async def _start_async(self):
        server = await asyncio.start_server(self.handle_client, self.host, self.port, ssl=self._ssl_context() if self.use_https else None)
        print(f"Async server running on http{'s' if self.use_https else ''}://{self.host}:{self.port}")
        async with server:
            await server.serve_forever()

    def _ssl_context(self):
        if not self.certfile or not self.keyfile:
            raise Exception("certfile and keyfile required for HTTPS")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        return context

    # --- REQUEST HANDLING ---
    def parse_request(self, request):
        head, _, body = request.partition('\r\n\r\n')
        headers = head.split('\r\n') if head else []
        return headers, body

    def parse_headers(self, headers):
        return {k.lower(): v for k, v in (h.split(': ', 1) for h in headers if ': ' in h)}

    def parse_cookies(self, headers):
        cookies = SimpleCookie()
        for h in headers:
            if h.lower().startswith('cookie:'):
                cookies.load(h[7:].strip())
        return {k: v.value for k, v in cookies.items()}

    def parse_body(self, body, headers):
        for h in headers:
            if h.lower().startswith('content-type:'):
                if 'application/json' in h.lower():
                    try:
                        return json.loads(body)
                    except Exception:
                        return {}
        return body

    def find_handler(self, path, method):
        return self.routes.get((path, method.upper()))

    def allowed_methods(self, path):
        return [method for (route, method) in self.routes if route == path]

    # --- MIDDLEWARE DISPATCH (sync) ---
    def _run_middlewares(self, req):
        for mw in self.middlewares:
            result = mw(req)
            if result is not None:
                return result
        return None

    # --- MIDDLEWARE DISPATCH (async) ---
    async def _run_middlewares_async(self, req):
        for mw in self.middlewares:
            if asyncio.iscoroutinefunction(mw):
                result = await mw(req)
            else:
                result = mw(req)
            if result is not None:
                return result
        return None

    # --- SYNC REQUEST HANDLER ---
    def handle_client(self, client):
        with client:
            request = client.recv(4096)
            if not request:
                return
            try:
                request = request.decode('utf-8', errors='replace')
            except Exception:
                request = request.decode('latin1', errors='replace')
            headers, body = self.parse_request(request)
            if not headers:
                self.send_response(client, 400, 'Bad Request', {}, 'text/plain')
                return
            try:
                method, path, _ = headers[0].split()
            except Exception:
                self.send_response(client, 400, 'Bad Request', {}, 'text/plain')
                return
            method = method.upper()
            parsed_path = urlparse(path)
            req = {
                'method': method,
                'path': parsed_path.path,
                'query': parse_qs(parsed_path.query),
                'headers': self.parse_headers(headers[1:]),
                'cookies': self.parse_cookies(headers[1:]),
                'body': self.parse_body(body, headers)
            }

            # Middleware
            mw_result = self._run_middlewares(req)
            if mw_result is not None:
                status, content, extra_headers = mw_result[:3]
                content_type = mw_result[3] if len(mw_result) == 4 else 'text/html'
                self.send_response(client, status, content, extra_headers, content_type)
                return

            handler = self.find_handler(parsed_path.path, method)
            if handler:
                try:
                    result = handler(req)
                    if isinstance(result, tuple) and len(result) in (3, 4):
                        status, content, extra_headers = result[:3]
                        content_type = result[3] if len(result) == 4 else 'text/html'
                        self.send_response(client, status, content, extra_headers, content_type)
                    else:
                        self.send_response(client, 500, 'Handler error', {}, 'text/plain')
                except Exception as e:
                    self.send_response(client, 500, {'error': str(e)}, {}, 'application/json')
            else:
                allowed = self.allowed_methods(parsed_path.path)
                if allowed:
                    self.send_response(client, 405, {'error': 'Method Not Allowed'}, {'Allow': ', '.join(allowed)}, 'application/json')
                else:
                    self.send_response(client, 404, {'error': 'Not Found'}, {}, 'application/json')

    # --- ASYNC REQUEST HANDLER ---
    async def handle_client(self, reader, writer):
        data = await reader.read(4096)
        if not data:
            writer.close()
            await writer.wait_closed()
            return
        try:
            request = data.decode('utf-8', errors='replace')
        except Exception:
            request = data.decode('latin1', errors='replace')
        headers, body = self.parse_request(request)
        if not headers:
            await self.send_response(writer, 400, 'Bad Request', {}, 'text/plain')
            return
        try:
            method, path, _ = headers[0].split()
        except Exception:
            await self.send_response(writer, 400, 'Bad Request', {}, 'text/plain')
            return
        method = method.upper()
        parsed_path = urlparse(path)
        req = {
            'method': method,
            'path': parsed_path.path,
            'query': parse_qs(parsed_path.query),
            'headers': self.parse_headers(headers[1:]),
            'cookies': self.parse_cookies(headers[1:]),
            'body': self.parse_body(body, headers)
        }

        # Middleware (async)
        mw_result = await self._run_middlewares_async(req)
        if mw_result is not None:
            status, content, extra_headers = mw_result[:3]
            content_type = mw_result[3] if len(mw_result) == 4 else 'text/html'
            await self.send_response(writer, status, content, extra_headers, content_type)
            return

        handler = self.find_handler(parsed_path.path, method)
        if handler:
            try:
                if asyncio.iscoroutinefunction(handler):
                    result = await handler(req)
                else:
                    result = handler(req)
                if isinstance(result, tuple) and len(result) in (3, 4):
                    status, content, extra_headers = result[:3]
                    content_type = result[3] if len(result) == 4 else 'text/html'
                    await self.send_response(writer, status, content, extra_headers, content_type)
                else:
                    await self.send_response(writer, 500, 'Handler error', {}, 'text/plain')
            except Exception as e:
                await self.send_response(writer, 500, {'error': str(e)}, {}, 'application/json')
        else:
            allowed = self.allowed_methods(parsed_path.path)
            if allowed:
                await self.send_response(writer, 405, {'error': 'Method Not Allowed'}, {'Allow': ', '.join(allowed)}, 'application/json')
            else:
                await self.send_response(writer, 404, {'error': 'Not Found'}, {}, 'application/json')

    # --- RESPONSE ---
    def send_response(self, client, status_code, content, extra_headers, content_type='text/html'):
        response = (
            f"HTTP/1.1 {status_code} {self.status_text(status_code)}\r\n"
            f"Content-Type: {content_type}\r\n"
            "Access-Control-Allow-Origin: *\r\n"
        )
        for k, v in extra_headers.items():
            response += f"{k}: {v}\r\n"
        response += "\r\n"

        if isinstance(content, bytes):
            response = response.encode('utf-8') + content
        else:
            if content_type.startswith('application/json') and not isinstance(content, str):
                response += json.dumps(content)
            else:
                response += content if isinstance(content, str) else str(content)
            response = response.encode('utf-8')
        client.sendall(response)

    async def send_response(self, writer, status_code, content, extra_headers, content_type='text/html'):
        response = (
            f"HTTP/1.1 {status_code} {self.status_text(status_code)}\r\n"
            f"Content-Type: {content_type}\r\n"
            "Access-Control-Allow-Origin: *\r\n"
        )
        for k, v in extra_headers.items():
            response += f"{k}: {v}\r\n"
        response += "\r\n"

        if isinstance(content, bytes):
            response = response.encode('utf-8') + content
        else:
            if content_type.startswith('application/json') and not isinstance(content, str):
                response += json.dumps(content)
            else:
                response += content if isinstance(content, str) else str(content)
            response = response.encode('utf-8')
        writer.write(response)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    # --- RESPONSE HELPERS ---
    def response(self, content, status=200, content_type='text/html', headers=None, encoding='utf-8'):
        if headers is None:
            headers = {}
        headers = dict(headers)
        if isinstance(content, dict) and content_type.startswith('application/json'):
            body = json.dumps(content)
        elif isinstance(content, bytes):
            body = content
        else:
            body = str(content)
        if 'charset' not in content_type and not content_type.startswith('image/'):
            content_type = f"{content_type}; charset={encoding}"
        return status, body, headers, content_type

    def redirect(self, location, status=302, headers=None):
        if headers is None:
            headers = {}
        headers = dict(headers)
        headers['Location'] = location
        return status, '', headers, 'text/plain'

    # --- UTILS ---
    @staticmethod
    def get_query_param(req, name, default=None):
        values = req.get('query', {}).get(name)
        if values:
            return values[0]
        return default

    @staticmethod
    def status_text(code):
        return {
            100: 'Continue',
            101: 'Switching Protocols',
            102: 'Processing',
            103: 'Early Hints',
            200: 'OK',
            201: 'Created',
            202: 'Accepted',
            203: 'Non-Authoritative Information',
            204: 'No Content',
            205: 'Reset Content',
            206: 'Partial Content',
            207: 'Multi-Status',
            208: 'Already Reported',
            226: 'IM Used',
            300: 'Multiple Choices',
            301: 'Moved Permanently',
            302: 'Found',
            303: 'See Other',
            304: 'Not Modified',
            305: 'Use Proxy',
            306: 'Switch Proxy',
            307: 'Temporary Redirect',
            308: 'Permanent Redirect',
            400: 'Bad Request',
            401: 'Unauthorized',
            402: 'Payment Required',
            403: 'Forbidden',
            404: 'Not Found',
            405: 'Method Not Allowed',
            406: 'Not Acceptable',
            407: 'Proxy Authentication Required',
            408: 'Request Timeout',
            409: 'Conflict',
            410: 'Gone',
            411: 'Length Required',
            412: 'Precondition Failed',
            413: 'Payload Too Large',
            414: 'URI Too Long',
            415: 'Unsupported Media Type',
            416: 'Range Not Satisfiable',
            417: 'Expectation Failed',
            418: "I'm a teapot",
            421: 'Misdirected Request',
            422: 'Unprocessable Entity',
            423: 'Locked',
            424: 'Failed Dependency',
            425: 'Too Early',
            426: 'Upgrade Required',
            428: 'Precondition Required',
            429: 'Too Many Requests',
            431: 'Request Header Fields Too Large',
            451: 'Unavailable For Legal Reasons',
            500: 'Internal Server Error',
            501: 'Not Implemented',
            502: 'Bad Gateway',
            503: 'Service Unavailable',
            504: 'Gateway Timeout',
            505: 'HTTP Version Not Supported',
            506: 'Variant Also Negotiates',
            507: 'Insufficient Storage',
            508: 'Loop Detected',
            510: 'Not Extended',
            511: 'Network Authentication Required',
        }.get(code, 'Unknown Status')
