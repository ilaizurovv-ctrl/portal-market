import os, json, hmac, hashlib, sqlite3, time
from pathlib import Path
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE = Path(__file__).parent
DB_PATH = os.getenv("DATABASE_PATH", str(BASE / "portal_market.db"))
BOT_TOKEN = os.getenv("SHUZA_TOKEN", "")
ADMIN_IDS = {int(x) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip()}
app = FastAPI(title="Portal Market API")

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
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
        raise HTTPException(503, "На сервере не задан SHUZA_TOKEN")
    try:
        pairs = dict(item.split("=", 1) for item in init_data.split("&") if "=" in item)
        received_hash = pairs.pop("hash")
        auth_date = int(pairs.get("auth_date", "0"))
        if abs(time.time() - auth_date) > 86400:
            raise ValueError("Срок авторизации истёк")
        data_check = "\n".join(f"{k}={v}" for k, v in sorted(pairs.items()))
        secret = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
        calculated = hmac.new(secret, data_check.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calculated, received_hash):
            raise ValueError("Неверная подпись")
        user = json.loads(pairs["user"])
        return user
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
        # Заказ создаётся как ожидающий оплаты/подтверждения.
        # Баланс не списывается: платёжный провайдер ещё не подключён.
        con.execute("UPDATE products SET stock=stock-1 WHERE id=? AND stock>0", (product_id,))
        cur = con.execute(
          "INSERT INTO orders(user_id,product_id,price,status,created_at) VALUES(?,?,?,?,?)",
          (uid, product_id, product["price"], "pending", int(time.time())))
        return {"order_id": cur.lastrowid, "status": "pending",
                "message": "Заявка создана. Ожидает подтверждения оплаты."}

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

app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")

@app.get("/")
def index():
    return FileResponse(BASE / "static" / "index.html")
