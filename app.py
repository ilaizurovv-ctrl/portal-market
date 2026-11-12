import os, json, hmac, hashlib, sqlite3, time
from pathlib import Path
from urllib.parse import parse_qsl
from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

BASE = Path(__file__).parent
DB_PATH = os.getenv("DATABASE_PATH", str(BASE / "portal_market.db"))
BOT_TOKEN = os.getenv("SHUZAGRAM_BOT_TOKEN", "")
ADMIN_IDS = {int(x) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip()}
app = FastAPI(title="PORTALS.COM API")

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS products(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          title TEXT NOT NULL, description TEXT DEFAULT '',
          price INTEGER NOT NULL CHECK(price > 0),
          image_url TEXT DEFAULT '', stock INTEGER NOT NULL DEFAULT 1,
          active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS users(
          user_id INTEGER PRIMARY KEY, username TEXT DEFAULT '',
          balance INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS orders(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL, product_id INTEGER NOT NULL,
          price INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
          created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS withdrawal_requests(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL, username TEXT DEFAULT '',
          status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL
        );
        """)
        count = con.execute("SELECT COUNT(*) FROM products").fetchone()[0]
        if count == 0:
            con.executemany(
              "INSERT INTO products(title,description,price,image_url,stock) VALUES(?,?,?,?,?)",
              [
                ("Crystal", "Цифровой коллекционный предмет", 500, "", 3),
                ("Golden Gift", "Золотой коллекционный подарок", 750, "", 2),
                ("Purple Star", "Редкий предмет коллекции", 1200, "", 1),
              ])

def verify_init_data(init_data: str):
    if not BOT_TOKEN:
        raise HTTPException(503, "На сервере не задан SHUZAGRAM_BOT_TOKEN")
    try:
        pairs = dict(parse_qsl(init_data, keep_blank_values=True))
        received_hash = pairs.pop("hash")
        auth_date = int(pairs.get("auth_date", "0"))
        if time.time() - auth_date > 86400 or auth_date > time.time() + 60:
            raise ValueError("Срок авторизации истёк")
        data_check = "\n".join(f"{k}={v}" for k, v in sorted(pairs.items()))
        secret = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
        calculated = hmac.new(secret, data_check.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calculated, received_hash):
            raise ValueError("Неверная подпись")
        return json.loads(pairs["user"])
    except Exception:
        raise HTTPException(401, "Не удалось подтвердить пользователя через Web App")

def current_user(x_telegram_init_data: str = Header(default="")):
    if not x_telegram_init_data:
        raise HTTPException(401, "Откройте магазин из кнопки в боте")
    return verify_init_data(x_telegram_init_data)

def admin_user(user=Depends(current_user)):
    if int(user["id"]) not in ADMIN_IDS:
        raise HTTPException(403, "Доступ только для администратора")
    return user

class ProductIn(BaseModel):
    title: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=1000)
    price: int = Field(gt=0, le=100000000)
    image_url: str = Field(default="", max_length=1000)
    stock: int = Field(default=1, ge=0, le=100000)

@app.on_event("startup")
def startup():
    init_db()
    register_shuzagram_webhook()



# ShuzaGram Bot API integration. Keep this token separate from SHUZA_TOKEN,
# which is used to validate Telegram WebApp initData.
import urllib.request
import urllib.error

SHUZAGRAM_BOT_TOKEN = os.getenv("SHUZAGRAM_BOT_TOKEN", "")

def register_shuzagram_webhook():
    public_url = os.getenv("RENDER_EXTERNAL_URL", "").rstrip("/")
    if SHUZAGRAM_BOT_TOKEN and public_url:
        try:
            shuzagram_bot_call("setWebhook", {"url": public_url + "/shuzagram/webhook"})
        except Exception:
            # Keep the app available; webhook can be retried after fixing bot configuration.
            pass

@app.post("/shuzagram/webhook")
async def shuzagram_webhook(request: Request):
    update = await request.json()
    message = update.get("message") or {}
    callback = update.get("callback_query") or {}

    # Inline-button actions
    if callback:
        data = callback.get("data", "")
        sender = callback.get("from") or {}
        chat = (callback.get("message") or {}).get("chat") or {}
        chat_id = chat.get("id") or sender.get("id")
        if data == "withdraw_request" and chat_id:
            user_id = int(sender.get("id") or chat_id)
            username = sender.get("username") or sender.get("first_name") or "без имени"
            with db() as con:
                cur = con.execute(
                    "INSERT INTO withdrawal_requests(user_id,username,created_at) VALUES(?,?,?)",
                    (user_id, username, int(time.time()))
                )
                request_id = cur.lastrowid
            shuzagram_bot_call("answerCallbackQuery", {
                "callback_query_id": callback.get("id"),
                "text": "Заявка создана"
            })
            shuzagram_bot_call("sendMessage", {
                "chat_id": chat_id,
                "text": f"✅ Заявка на вывод №{request_id} отправлена администрации. Мы свяжемся с вами."
            })
            admin_text = (
                f"💸 Новая заявка на вывод №{request_id}\n"
                f"Пользователь: @{username} (ID: {user_id})\n"
                f"Статус: ожидает рассмотрения"
            )
            for admin_id in ADMIN_IDS:
                shuzagram_bot_call("sendMessage", {"chat_id": admin_id, "text": admin_text})
        return {"ok": True}

    chat = message.get("chat") or {}
    text_value = (message.get("text") or "").strip()
    if chat.get("id") and text_value.split(" ", 1)[0].split("@", 1)[0] == "/start":
        shuzagram_bot_call("sendMessage", {
            "chat_id": chat["id"],
            "text": "Добро пожаловать в PORTALS.COM! 🎁\nВыберите действие:",
            "reply_markup": {
                "inline_keyboard": [
                    [{"text": "🚀 Открыть PORTALS.COM", "url": "https://portal-market.onrender.com"}],
                    [{"text": "➕ Пополнить", "url": "https://shuzagram.com/PortalsPlayer"}],
                    [{"text": "💸 Вывести", "callback_data": "withdraw_request"}],
                    [{"text": "🛟 Поддержка", "url": "https://t.me/supportPotral"}]
                ]
            }
        })
    return {"ok": True}


def shuzagram_bot_call(method: str, params=None):
    if not SHUZAGRAM_BOT_TOKEN:
        raise HTTPException(503, "На сервере не задан SHUZAGRAM_BOT_TOKEN")
    url = f"https://api.shuzagram.com/bot{SHUZAGRAM_BOT_TOKEN}/{method}"
    data = json.dumps(params).encode("utf-8") if params else None
    request = urllib.request.Request(
        url, data=data, method="POST" if data else "GET",
        headers={"Content-Type": "application/json"} if data else {}
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8"))
            raise HTTPException(exc.code, payload.get("description", "Ошибка ShuzaGram API"))
        except json.JSONDecodeError:
            raise HTTPException(502, "ShuzaGram API вернул ошибку")
    except Exception:
        raise HTTPException(502, "Не удалось связаться с ShuzaGram API")
    if not payload.get("ok"):
        raise HTTPException(502, payload.get("description", "Ошибка ShuzaGram API"))
    return payload.get("result")

@app.get("/api/shuzagram/bot")
def shuzagram_bot_info(user=Depends(admin_user)):
    return shuzagram_bot_call("getMe")

@app.get("/api/shuzagram/gifts")
def shuzagram_available_gifts(user=Depends(current_user)):
    # This is the bot's available-gifts catalog, not the user's personal NFT inventory.
    return shuzagram_bot_call("getAvailableGifts")

@app.get("/health")
def health():
    return {"ok": True, "service": "PORTALS.COM"}

@app.get("/api/products")
def products():
    with db() as con:
        rows = con.execute("SELECT * FROM products WHERE active=1 AND stock>0 ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]

@app.get("/api/me")
def me(user=Depends(current_user)):
    uid = int(user["id"])
    with db() as con:
        con.execute("INSERT OR IGNORE INTO users(user_id,username) VALUES(?,?)",
                    (uid, user.get("username", "")))
        row = con.execute("SELECT * FROM users WHERE user_id=?", (uid,)).fetchone()
        return {"user_id": uid, "username": user.get("username", ""), "balance": row["balance"]}

@app.get("/api/orders")
def orders(user=Depends(current_user)):
    with db() as con:
        rows = con.execute("""
          SELECT o.id,o.price,o.status,o.created_at,p.title
          FROM orders o JOIN products p ON p.id=o.product_id
          WHERE o.user_id=? ORDER BY o.id DESC LIMIT 50
        """, (int(user["id"]),)).fetchall()
        return [dict(r) for r in rows]

@app.post("/api/orders/{product_id}")
def create_order(product_id: int, user=Depends(current_user)):
    uid = int(user["id"])
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        product = con.execute(
          "SELECT * FROM products WHERE id=? AND active=1 AND stock>0",
          (product_id,)).fetchone()
        if not product:
            raise HTTPException(404, "Товар уже недоступен")
        con.execute("UPDATE products SET stock=stock-1 WHERE id=? AND stock>0", (product_id,))
        cur = con.execute(
          "INSERT INTO orders(user_id,product_id,price,status,created_at) VALUES(?,?,?,?,?)",
          (uid, product_id, product["price"], "pending", int(time.time())))
        return {"order_id": cur.lastrowid, "status": "pending",
                "message": "Заявка создана. Оплата пока не подключена."}

@app.get("/api/admin/products")
def admin_products(user=Depends(admin_user)):
    with db() as con:
        return [dict(r) for r in con.execute("SELECT * FROM products ORDER BY id DESC").fetchall()]

@app.post("/api/admin/products")
def add_product(item: ProductIn, user=Depends(admin_user)):
    with db() as con:
        cur = con.execute(
          "INSERT INTO products(title,description,price,image_url,stock) VALUES(?,?,?,?,?)",
          (item.title,item.description,item.price,item.image_url,item.stock))
        return {"id": cur.lastrowid, "ok": True}

@app.patch("/api/admin/products/{product_id}")
def update_product(product_id: int, item: ProductIn, user=Depends(admin_user)):
    with db() as con:
        cur = con.execute(
          "UPDATE products SET title=?,description=?,price=?,image_url=?,stock=? WHERE id=?",
          (item.title,item.description,item.price,item.image_url,item.stock,product_id))
        if cur.rowcount == 0:
            raise HTTPException(404, "Товар не найден")
        return {"ok": True}

@app.delete("/api/admin/products/{product_id}")
def delete_product(product_id: int, user=Depends(admin_user)):
    with db() as con:
        cur = con.execute("UPDATE products SET active=0 WHERE id=?", (product_id,))
        if cur.rowcount == 0:
            raise HTTPException(404, "Товар не найден")
        return {"ok": True}

@app.get("/")
def index():
    return FileResponse(BASE / "index.html")
