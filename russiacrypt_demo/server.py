#!/usr/bin/env python3
"""RUSSIACRYPT — local-only educational crypto dashboard simulator.
No real payments, exchange connectivity, or payouts are implemented.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
import hashlib
import json
import os
import re
import secrets
import sqlite3
import time

BASE = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", str(BASE)))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.environ.get("DB_PATH", str(DATA_DIR / "russiacrypt.db")))
HOST = os.environ.get("HOST", "127.0.0.1")  # Hosting platforms must set HOST=0.0.0.0.
PORT = int(os.environ.get("PORT", "8080"))
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "").lower() in {"1", "true", "yes"}
COOKIE_SECURE_ATTR = "; Secure" if COOKIE_SECURE else ""
SESSION_SECONDS = 7 * 24 * 60 * 60
PRICE_EUR_CENTS_PER_COIN = 15000  # Fictional reference price: €150.00 per RUCOIN.
MOSCOW = timezone(timedelta(hours=3))  # Moscow is UTC+3.


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        if conn.in_transaction:
            conn.commit()
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.close()


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 240_000)
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, digest_hex: str) -> bool:
    _, candidate = hash_password(password, bytes.fromhex(salt_hex))
    return secrets.compare_digest(candidate, digest_hex)


def init_db():
    with db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                eur_cents INTEGER NOT NULL DEFAULT 0,
                rucoin_cents INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                csrf TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                kind TEXT NOT NULL,
                eur_delta INTEGER NOT NULL DEFAULT 0,
                rucoin_delta INTEGER NOT NULL DEFAULT 0,
                description TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS withdrawal_caps (
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                hour_key TEXT NOT NULL,
                starting_balance_cents INTEGER NOT NULL,
                withdrawn_cents INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (user_id, hour_key)
            );            CREATE TABLE IF NOT EXISTS market_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                price_cents INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS market_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                price_cents INTEGER NOT NULL,
                side TEXT NOT NULL,
                amount_units INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
        """)        conn.execute(
            "INSERT OR IGNORE INTO market_state(id, price_cents, updated_at) VALUES(1, ?, ?)",
            (PRICE_EUR_CENTS_PER_COIN, now_text())
        )

        market = conn.execute(
            "SELECT price_cents FROM market_state WHERE id=1"
        ).fetchone()

        history_exists = conn.execute(
            "SELECT id FROM market_history LIMIT 1"
        ).fetchone()

        if not history_exists:
            conn.execute(
                "INSERT INTO market_history(price_cents, side, amount_units, created_at) VALUES(?, ?, ?, ?)",
                (market["price_cents"], "initial", 0, now_text())
            
        admin = conn.execute("SELECT id, username FROM users WHERE role='admin' LIMIT 1").fetchone()
        configured_password = "cryptoadmin"
        configured_username = "owner"
        

        if admin:
            # When ADMIN_PASSWORD is configured in the hosting dashboard, make it
            # the known password for the existing admin account on every restart.
            # The secret itself is never printed to the logs.
            if configured_password:
                username = (configured_username or admin["username"]).strip() or admin["username"]
                conflict = conn.execute(
                    "SELECT id FROM users WHERE username=? COLLATE NOCASE AND id<>?",
                    (username, admin["id"])
                ).fetchone()
                if conflict:
                    raise RuntimeError("ADMIN_USERNAME уже занят другим аккаунтом. Укажите другое имя администратора в переменных Render.")
                salt, digest = hash_password(configured_password)
                conn.execute(
                    "UPDATE users SET username=?, salt=?, password_hash=? WHERE id=?",
                    (username, salt, digest, admin["id"])
                )
                print("[RUSSIACRYPT] Пароль существующего администратора обновлён из переменной ADMIN_PASSWORD.")
                print(f"Логин администратора: {username}")
        else:
            username = (configured_username or "owner").strip() or "owner"
            password = configured_password
            generated = not bool(password)
            if not password:
                password = secrets.token_urlsafe(18)
            salt, digest = hash_password(password)
            try:
                conn.execute(
                    "INSERT INTO users(username,salt,password_hash,role,eur_cents,rucoin_cents,created_at) VALUES(?,?,?,?,?,?,?)",
                    (username, salt, digest, "admin", 0, 0, datetime.now(timezone.utc).isoformat())
                )
                print("\n[RUSSIACRYPT] Создана админ-учётная запись.")
                print(f"Логин: {username}")
                if generated:
                    print("Пароль создан случайно и не будет показан повторно. Задайте ADMIN_PASSWORD в настройках Render, чтобы установить известный пароль.")
                else:
                    print("Пароль установлен через переменную окружения ADMIN_PASSWORD.")
            except sqlite3.IntegrityError:
                raise RuntimeError("Имя ADMIN_USERNAME уже занято обычным аккаунтом. Укажите другое имя ADMIN_USERNAME в настройках Render.")


def money_to_units(value, field="amount") -> int:
    try:
        amount = Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError(f"Некорректное значение поля {field}.")
    if not amount.is_finite() or amount <= 0 or amount > Decimal("100000000"):
        raise ValueError("Сумма должна быть больше нуля и находиться в допустимом диапазоне.")
    return int(amount * 100)


def now_text():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AppHandler(BaseHTTPRequestHandler):
    server_version = "RUSSIACRYPT-Demo/1.0"

    def log_message(self, fmt, *args):
        print("[HTTP] " + (fmt % args))

    def send_json(self, data, status=200, extra_headers=None):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.security_headers()
        if extra_headers:
            for key, value in extra_headers:
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 64_000:
            raise ValueError("Слишком большой запрос.")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("Некорректный JSON-запрос.")
        if not isinstance(data, dict):
            raise ValueError("Ожидался объект с полями запроса.")
        return data

    def cookie_token(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("rc_session="):
                return part.split("=", 1)[1]
        return None

    def current_session(self):
        token = self.cookie_token()
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with db() as conn:
            row = conn.execute("""
                SELECT s.csrf, s.expires_at, u.id, u.username, u.role, u.eur_cents, u.rucoin_cents
                FROM sessions s JOIN users u ON u.id=s.user_id
                WHERE s.token_hash=?
            """, (token_hash,)).fetchone()
            if not row:  
                return None
            if row["expires_at"] < int(time.time()):
                conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
                return None
            return dict(row)

    def require_auth(self):
        user = self.current_session()
        if not user:
            self.send_json({"ok": False, "error": "Сначала войдите в аккаунт."}, 401)
            return None
        return user

    def require_csrf(self, user):
        supplied = self.headers.get("X-CSRF-Token", "")
        if not secrets.compare_digest(supplied, user["csrf"]):
            self.send_json({"ok": False, "error": "Проверка запроса не пройдена. Обновите страницу."}, 403)
            return False
        return True

    def create_session(self, user_id):
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        expires = int(time.time()) + SESSION_SECONDS
        with db() as conn:
            conn.execute("INSERT INTO sessions(token_hash,user_id,csrf,expires_at) VALUES(?,?,?,?)", (token_hash, user_id, csrf, expires))
        cookie = f"rc_session={token}; HttpOnly{COOKIE_SECURE_ATTR}; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}"
        return csrf, cookie

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/me":
            user = self.current_session()
            if not user:
                self.send_json({"authenticated": False})
                return
            self.send_json({"authenticated": True, "csrf": user["csrf"], "user": self.public_user(user)})
            return
        if path == "/api/ledger":
            user = self.require_auth()
            if not user:
                return
            with db() as conn:
                rows = conn.execute("SELECT id,kind,eur_delta,rucoin_delta,description,created_at FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 100", (user["id"],)).fetchall()
            self.send_json({"items": [dict(r) for r in rows]})
            return
        if path == "/api/admin/users":
            user = self.require_auth()
            if not user:
                return
            if user["role"] != "admin":
                self.send_json({"ok": False, "error": "Доступ только для администратора."}, 403)
                return
            with db() as conn:
                rows = conn.execute("SELECT id,username,role,eur_cents,rucoin_cents,created_at FROM users ORDER BY id").fetchall()
            self.send_json({"items": [dict(r) for r in rows]})
            return
        if path == "/api/admin/ledger":
            user = self.require_auth()
            if not user:
                return
            if user["role"] != "admin":
                self.send_json({"ok": False, "error": "Доступ только для администратора."}, 403)
                return
            with db() as conn:
                rows = conn.execute("""
                    SELECT l.id,l.user_id,u.username,l.kind,l.eur_delta,l.rucoin_delta,l.description,l.created_at
                    FROM ledger l JOIN users u ON u.id=l.user_id ORDER BY l.id DESC LIMIT 100
                """).fetchall()
            self.send_json({"items": [dict(r) for r in rows]})
            return
        if path in ("/", "/index.html", "/style.css", "/app.js", "/favicon.svg"):
            self.serve_static(path)
            return
        self.send_json({"ok": False, "error": "Страница не найдена."}, 404)

    def public_user(self, user):
        return {
            "id": user["id"], "username": user["username"], "role": user["role"],
            "eur_cents": user["eur_cents"], "rucoin_cents": user["rucoin_cents"]
        }

    def serve_static(self, path):
        name = "index.html" if path in ("/", "/index.html") else path.lstrip("/")
        allowed = {"index.html": "text/html; charset=utf-8", "style.css": "text/css; charset=utf-8", "app.js": "text/javascript; charset=utf-8", "favicon.svg": "image/svg+xml"}
        if name not in allowed:
            self.send_json({"error": "Not found"}, 404)
            return
        payload = (BASE / name).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", allowed[name])
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-cache")
        self.security_headers()
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            data = self.read_json()
            if path == "/api/register":
                self.register(data)
            elif path == "/api/login":
                self.login(data)
            elif path == "/api/logout":
                user = self.require_auth()
                if not user or not self.require_csrf(user):
                    return
                token = self.cookie_token()
                token_hash = hashlib.sha256(token.encode()).hexdigest()
                with db() as conn:
                    conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
                self.send_json({"ok": True}, extra_headers=[("Set-Cookie", f"rc_session=; HttpOnly{COOKIE_SECURE_ATTR}; SameSite=Strict; Path=/; Max-Age=0")])
            else:
                user = self.require_auth()
                if not user or not self.require_csrf(user):
                    return
                if path == "/api/deposit":
                    self.deposit(user, data)
                elif path == "/api/trade":
                    self.trade(user, data)
                elif path == "/api/withdraw":
                    self.withdraw(user, data)
                elif path == "/api/admin/adjust":
                    self.admin_adjust(user, data)
                else:
                    self.send_json({"ok": False, "error": "Неизвестное действие."}, 404)
        except ValueError as exc:
            self.send_json({"ok": False, "error": str(exc)}, 400)
        except Exception as exc:
            print("[ERROR]", repr(exc))
            self.send_json({"ok": False, "error": "Внутренняя ошибка сервера."}, 500)

    def register(self, data):
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", username):
            raise ValueError("Логин: 3–20 символов, латинские буквы, цифры и _.")
        if len(password) < 10 or len(password) > 128:
            raise ValueError("Пароль должен содержать от 10 до 128 символов.")
        salt, digest = hash_password(password)
        try:
            with db() as conn:
                cur = conn.execute("INSERT INTO users(username,salt,password_hash,role,created_at) VALUES(?,?,?,?,?)", (username, salt, digest, "user", now_text()))
                user_id = cur.lastrowid
                conn.execute("INSERT INTO ledger(user_id,kind,description,created_at) VALUES(?,?,?,?)", (user_id, "account", "Создан демонстрационный аккаунт", now_text()))
        except sqlite3.IntegrityError:
            raise ValueError("Такой логин уже занят.")
        csrf, cookie = self.create_session(user_id)
        self.send_json({"ok": True, "csrf": csrf}, extra_headers=[("Set-Cookie", cookie)])

    def login(self, data):
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        with db() as conn:
            row = conn.execute("SELECT id,salt,password_hash FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone()
        if not row or not verify_password(password, row["salt"], row["password_hash"]):
            raise ValueError("Неверный логин или пароль.")
        csrf, cookie = self.create_session(row["id"])
        self.send_json({"ok": True, "csrf": csrf}, extra_headers=[("Set-Cookie", cookie)])

    def deposit(self, user, data):
        amount = money_to_units(data.get("amount"), "amount")
        if amount not in (10000, 25000, 50000, 100000):
            raise ValueError("Выберите один из тестовых пакетов: €100, €250, €500 или €1 000.")
        with db() as conn:
            conn.execute("UPDATE users SET eur_cents=eur_cents+? WHERE id=?", (amount, user["id"]))
            conn.execute("INSERT INTO ledger(user_id,kind,eur_delta,description,created_at) VALUES(?,?,?,?,?)", (user["id"], "demo_topup", amount, "Тестовое пополнение — виртуальные EUR, не платёж", now_text()))
        self.send_json({"ok": True, "message": "Тестовый баланс пополнен."})

    def trade(self, user, data):
        side = str(data.get("side", ""))
        coin_units = money_to_units(data.get("amount"), "amount")
        eur_cents = coin_units * 150  # €150.00 per 1.00 RUCOIN, represented in cents.
        with db() as conn:
            current = conn.execute("SELECT eur_cents,rucoin_cents FROM users WHERE id=?", (user["id"],)).fetchone()
            if side == "buy":
                if current["eur_cents"] < eur_cents:
                    raise ValueError("Недостаточно тестовых EUR. Откройте вкладку «Пополнение».")
                conn.execute("UPDATE users SET eur_cents=eur_cents-?,rucoin_cents=rucoin_cents+? WHERE id=?", (eur_cents, coin_units, user["id"]))
                conn.execute("INSERT INTO ledger(user_id,kind,eur_delta,rucoin_delta,description,created_at) VALUES(?,?,?,?,?,?)", (user["id"], "buy", -eur_cents, coin_units, f"Демо-покупка {coin_units/100:.2f} RUCOIN по €150.00", now_text()))
            elif side == "sell":
                if current["rucoin_cents"] < coin_units:
                    raise ValueError("Недостаточно RUCOIN на демонстрационном балансе.")
                conn.execute("UPDATE users SET eur_cents=eur_cents+?,rucoin_cents=rucoin_cents-? WHERE id=?", (eur_cents, coin_units, user["id"]))
                conn.execute("INSERT INTO ledger(user_id,kind,eur_delta,rucoin_delta,description,created_at) VALUES(?,?,?,?,?,?)", (user["id"], "sell", eur_cents, -coin_units, f"Демо-продажа {coin_units/100:.2f} RUCOIN по €150.00", now_text()))
            else:
                raise ValueError("Выберите покупку или продажу.")
        self.send_json({"ok": True, "message": "Демо-сделка выполнена."})

    def withdraw(self, user, data):
        amount = money_to_units(data.get("amount"), "amount")
        now = datetime.now(MOSCOW)
        if not (now.hour == 16 and 30 <= now.minute < 60):
            raise ValueError("Демо-заявки доступны ежедневно с 16:30 до 16:59 по московскому времени.")
        hour_key = now.strftime("%Y-%m-%d-%H")
        with db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = conn.execute("SELECT eur_cents FROM users WHERE id=?", (user["id"],)).fetchone()
            if amount > current["eur_cents"]:
                raise ValueError("Сумма больше доступного тестового EUR-баланса.")
            cap = conn.execute("SELECT starting_balance_cents,withdrawn_cents FROM withdrawal_caps WHERE user_id=? AND hour_key=?", (user["id"], hour_key)).fetchone()
            if not cap:
                conn.execute("INSERT INTO withdrawal_caps(user_id,hour_key,starting_balance_cents,withdrawn_cents) VALUES(?,?,?,0)", (user["id"], hour_key, current["eur_cents"]))
                starting_balance, withdrawn = current["eur_cents"], 0
            else:
                starting_balance, withdrawn = cap["starting_balance_cents"], cap["withdrawn_cents"]
            limit = starting_balance // 5
            if withdrawn + amount > limit:
                available = max(0, limit - withdrawn)
                raise ValueError(f"Лимит 20% за этот час: осталось не более €{available/100:.2f}.")
            conn.execute("UPDATE users SET eur_cents=eur_cents-? WHERE id=?", (amount, user["id"]))
            conn.execute("UPDATE withdrawal_caps SET withdrawn_cents=withdrawn_cents+? WHERE user_id=? AND hour_key=?", (amount, user["id"], hour_key))
            conn.execute("INSERT INTO ledger(user_id,kind,eur_delta,description,created_at) VALUES(?,?,?,?,?)", (user["id"], "demo_withdraw", -amount, "Имитация вывода — реальные деньги не переводились", now_text()))
        self.send_json({"ok": True, "message": "Демо-заявка обработана. Реальный перевод средств не выполнялся."})

    def admin_adjust(self, user, data):
        if user["role"] != "admin":
            self.send_json({"ok": False, "error": "Доступ только для администратора."}, 403)
            return
        try:
            target_id = int(data.get("user_id"))
        except (TypeError, ValueError):
            raise ValueError("Выберите аккаунт.")
        asset = str(data.get("asset", ""))
        action = str(data.get("action", ""))
        amount = money_to_units(data.get("amount"), "amount")
        reason = str(data.get("reason", "")).strip()[:120]
        if asset not in ("EUR", "RUCOIN") or action not in ("add", "subtract"):
            raise ValueError("Некорректный тип корректировки.")
        if not reason:
            raise ValueError("Укажите причину корректировки.")
        field = "eur_cents" if asset == "EUR" else "rucoin_cents"
        delta = amount if action == "add" else -amount
        with db() as conn:
            current = conn.execute(f"SELECT {field} FROM users WHERE id=?", (target_id,)).fetchone()
            if not current:
                raise ValueError("Аккаунт не найден.")
            if current[field] + delta < 0:
                raise ValueError("Нельзя уменьшить баланс ниже нуля.")
            conn.execute(f"UPDATE users SET {field}={field}+? WHERE id=?", (delta, target_id))
            eur_delta = delta if asset == "EUR" else 0
            coin_delta = delta if asset == "RUCOIN" else 0
            conn.execute("INSERT INTO ledger(user_id,kind,eur_delta,rucoin_delta,description,created_at) VALUES(?,?,?,?,?,?)", (target_id, "admin_adjust", eur_delta, coin_delta, f"Админ-корректировка: {reason}", now_text()))
        self.send_json({"ok": True, "message": "Демо-баланс аккаунта обновлён."})


def main():
    init_db()
    httpd = ThreadingHTTPServer((HOST, PORT), AppHandler)
    print("=" * 58)
    print(" RUSSIACRYPT — учебный симулятор виртуальных активов")
    print(" Реальные платежи и выплаты отключены.")
    print(f" Локальный адрес: http://127.0.0.1:{PORT}")
    print(f" Адрес привязки сервера: {HOST}:{PORT}")
    print(" Для остановки нажмите Ctrl+C.")
    print("=" * 58)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nСервер остановлен.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
