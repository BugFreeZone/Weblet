import socket
import ssl
import asyncio
from threading import Thread
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlparse, unquote_plus
import json
import os
import signal
import sys
import traceback
import time
import logging

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
except ImportError:
    Environment = None

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    Observer = None

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
        template_folder='templates',
        debug=False,
        rate_limit=30,
        rate_period=60,
        max_request_size=1024 * 1024,
        max_header_line=8192,
        static_folder='static'
    ):
        self.host = host
        self.port = port
        self.routes = []
        self.db_type = db_type
        self.db_config = db_config or {}
        self.use_https = use_https
        self.certfile = certfile
        self.keyfile = keyfile
        self.middlewares = []
        self._server_socket = None
        self._should_stop = False
        self.debug = debug
        self.sessions = {}
        self.rate_limit_data = {}
        self.static_folder = static_folder
        self.rate_limit = rate_limit
        self.rate_period = rate_period
        self.max_request_size = max_request_size
        self.max_header_line = max_header_line
        if Environment and os.path.isdir(template_folder):
            self.template_env = Environment(
                loader=FileSystemLoader(template_folder),
                autoescape=select_autoescape(['html', 'xml'])
            )
        else:
            self.template_env = None
        logging.basicConfig(
            filename='server.log',
            filemode='a',
            format='%(asctime)s [%(levelname)s] %(message)s',
            level=logging.INFO
        )

    def _start_with_hot_reload(self, debug):
        if not Observer:
            print("Для hot reload требуется установить watchdog: pip install watchdog")
            sys.exit(1)
        print("Hot reload активирован. Следим за изменениями *.py")
        observer = Observer()
        event_handler = ReloadHandler()
        observer.schedule(event_handler, '.', recursive=True)
        observer.start()
        try:
            while True:
                if event_handler.should_reload:
                    print("Изменения в коде обнаружены. Перезапуск...")
                    os.execv(sys.executable, [sys.executable] + sys.argv)
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()

    def _debug_middleware(self, req):
        if self.debug:
            print("\n--- [REQUEST] ---")
            print(f"{req['method']} {req['path']}")
            print("Headers:", req['headers'])
            print("Query:", req['query'])
            print("Cookies:", req['cookies'])
            print("Body:", req['body'])
        return None

    def _rate_limit_middleware(self, req):
        ip = req.get('client_ip')
        now = time.time()
        timestamps = self.rate_limit_data.setdefault(ip, [])
        timestamps = [t for t in timestamps if now - t < self.rate_period]
        if len(timestamps) >= self.rate_limit:
            logging.warning(f"Rate limit exceeded for {ip}")
            return 429, "Too Many Requests", {}, "text/plain"
        timestamps.append(now)
        self.rate_limit_data[ip] = timestamps
        return None

    def _session_middleware(self, req):
        cookies = req.get('cookies', {})
        sid = cookies.get('session_id')
        if not sid or sid not in self.sessions:
            sid = os.urandom(16).hex()
            self.sessions[sid] = {}
            req['set_session_cookie'] = sid
        req['session'] = self.sessions[sid]
        req['session_id'] = sid
        return None

    def _static_handler(self, req):
        path = req['path']
        if path.startswith('/static/'):
            rel_path = os.path.normpath(path[len('/static/'):])
            if '..' in rel_path or rel_path.startswith('/'):
                return 403, 'Forbidden', {}, 'text/plain'
            file_path = os.path.join(self.static_folder, rel_path)
            if os.path.isfile(file_path):
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                    mime = self._guess_mime(file_path)
                    return 200, content, {}, mime
                except Exception:
                    return 500, 'Error reading file', {}, 'text/plain'
            else:
                return 404, 'Not found', {}, 'text/plain'
        return None

    def _guess_mime(self, filename):
        ext = filename.rsplit('.', 1)[-1].lower()
        return {
            'html': 'text/html',
            'htm': 'text/html',
            'css': 'text/css',
            'js': 'application/javascript',
            'png': 'image/png',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'gif': 'image/gif',
            'svg': 'image/svg+xml',
            'ico': 'image/x-icon',
            'json': 'application/json',
            'txt': 'text/plain',
        }.get(ext, 'application/octet-stream')

    def route(self, path, methods=['GET']):
        def decorator(func):
            self.routes.append((self._parse_route(path), methods, func))
            return func
        return decorator

    def _parse_route(self, path):
        return [segment for segment in path.strip('/').split('/')]

    def _match_route(self, req_path, method):
        req_segments = req_path.strip('/').split('/')
        for route_pattern, methods, func in self.routes:
            if method.upper() not in [m.upper() for m in methods]:
                continue
            if len(route_pattern) != len(req_segments):
                continue
            params = {}
            matched = True
            for pat, seg in zip(route_pattern, req_segments):
                if pat.startswith('<') and pat.endswith('>'):
                    params[pat[1:-1]] = seg
                elif pat != seg:
                    matched = False
                    break
            if matched:
                return func, params
        return None, {}

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

    def render_template(self, template_name, **context):
        if not self.template_env:
            raise Exception("Jinja2 is not installed or template folder not found")
        template = self.template_env.get_template(template_name)
        return template.render(**context)

    def add_middleware(self, func):
        self.middlewares.append(func)

    def start(self, debug=False, hot_reload=False):
        self.debug = debug
        self.middlewares = []
        if self.debug:
            self.middlewares.append(self._debug_middleware)
        self.middlewares.append(self._rate_limit_middleware)
        self.middlewares.append(self._session_middleware)
        self.middlewares.append(self._static_handler)
        if hot_reload and self.debug:
            self._start_with_hot_reload(debug)
            return
        if asyncio.iscoroutinefunction(self.handle_client):
            asyncio.run(self._start_async())
        else:
            def signal_handler(sig, frame):
                print("\nShutting down server...")
                self._should_stop = True
                if self._server_socket:
                    self._server_socket.close()
            signal.signal(signal.SIGINT, signal_handler)
            print(f"Server running on http{'s' if self.use_https else ''}://{self.host}:{self.port} (debug={self.debug})")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                self._server_socket = s
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((self.host, self.port))
                s.listen(5)
                if self.use_https:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
                    s = context.wrap_socket(s, server_side=True)
                while not self._should_stop:
                    try:
                        client, addr = s.accept()
                    except OSError:
                        break
                    Thread(target=self.handle_client, args=(client, addr)).start()
            print("Server stopped.")

    def parse_request(self, request):
        head, _, body = request.partition('\r\n\r\n')
        headers = head.split('\r\n') if head else []
        for h in headers:
            if len(h) > self.max_header_line:
                raise Exception("Header line too long")
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
        content_type = ''
        for h in headers:
            if h.lower().startswith('content-type:'):
                content_type = h.split(':',1)[1].strip().lower()
                break
        if 'application/json' in content_type:
            try:
                return json.loads(body)
            except Exception:
                return {}
        elif 'application/x-www-form-urlencoded' in content_type:
            return {k: v[0] if len(v)==1 else v for k, v in parse_qs(body).items()}
        elif 'multipart/form-data' in content_type:
            boundary = content_type.split('boundary=')[-1]
            parts = body.split('--' + boundary)
            data = {}
            for part in parts:
                if not part or part == '--\r\n':
                    continue
                headers_part, _, value = part.partition('\r\n\r\n')
                if 'name="' in headers_part:
                    name = headers_part.split('name="')[1].split('"')[0]
                    data[name] = value.rstrip('\r\n')
            return data
        return body

    def handle_client(self, client, addr=None):
        try:
            client.settimeout(5)
            with client:
                try:
                    request = client.recv(self.max_request_size)
                except socket.timeout:
                    # Просто молча закрываем соединение при таймауте
                    return
                except Exception:
                    # Любая другая ошибка при чтении - тоже закрываем соединение
                    return
                if len(request) == self.max_request_size:
                    self.send_response(client, 413, 'Payload Too Large', {}, 'text/plain')
                    return
                try:
                    request = request.decode('utf-8', errors='replace')
                except Exception:
                    request = request.decode('latin1', errors='replace')
                try:
                    headers, body = self.parse_request(request)
                except Exception:
                    self.send_response(client, 400, 'Header Too Long', {}, 'text/plain')
                    return
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
                    'body': self.parse_body(body, headers),
                    'client_ip': addr[0] if addr else 'unknown'
                }

                # Middleware
                for mw in self.middlewares:
                    result = mw(req)
                    if result is not None:
                        status, content, extra_headers = result[:3]
                        content_type = result[3] if len(result) == 4 else 'text/html'
                        if req.get('set_session_cookie'):
                            extra_headers = dict(extra_headers)
                            extra_headers['Set-Cookie'] = f'session_id={req["set_session_cookie"]}; Path=/; HttpOnly'
                        self.send_response(client, status, content, extra_headers, content_type)
                        return

                handler, params = self._match_route(parsed_path.path, method)
                if handler:
                    try:
                        req['params'] = params
                        result = handler(req)
                        if isinstance(result, tuple) and len(result) in (3, 4):
                            status, content, extra_headers = result[:3]
                            content_type = result[3] if len(result) == 4 else 'text/html'
                            if req.get('set_session_cookie'):
                                extra_headers = dict(extra_headers)
                                extra_headers['Set-Cookie'] = f'session_id={req["set_session_cookie"]}; Path=/; HttpOnly'
                            self.send_response(client, status, content, extra_headers, content_type)
                        else:
                            self.send_response(client, 500, 'Handler error', {}, 'text/plain')
                    except Exception as e:
                        if self.debug:
                            print("\n--- [EXCEPTION] ---")
                            traceback.print_exc()
                        logging.error(traceback.format_exc())
                        self.send_response(client, 500, {'error': str(e)}, {}, 'application/json')
                else:
                    self.send_response(client, 404, {'error': 'Not Found'}, {}, 'application/json')
        except Exception:
            # Любая ошибка вне чтения - тоже молча закрываем соединение
            return

    def send_response(self, client, status_code, content, extra_headers, content_type='text/html'):
        if self.debug:
            print("\n--- [RESPONSE] ---")
            print(f"Status: {status_code}")
            print("Headers:", extra_headers)
            print("Content-Type:", content_type)
            print("Body:", content)
        logging.info(f"Response {status_code} {content_type}")
        response = (
            f"HTTP/1.1 {status_code} {self.status_text(status_code)}\r\n"
            f"Content-Type: {content_type}\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "X-Content-Type-Options: nosniff\r\n"
            "X-Frame-Options: DENY\r\n"
            "X-XSS-Protection: 1; mode=block\r\n"
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

class ReloadHandler(FileSystemEventHandler):
    def __init__(self):
        self.should_reload = False
    def on_modified(self, event):
        if event.src_path.endswith('.py'):
            self.should_reload = True
    def on_created(self, event):
        if event.src_path.endswith('.py'):
            self.should_reload = True
