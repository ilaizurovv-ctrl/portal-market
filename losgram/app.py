import os, sqlite3, hashlib, hmac, secrets, time
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE=Path(__file__).parent
DB=os.getenv("LOS_GRAM_DB","/tmp/losgram.db")
SECRET=os.getenv("LOS_GRAM_SECRET","")
app=FastAPI(title="Losgram API")
app.mount("/static",StaticFiles(directory=BASE/"static"),name="static")
def db():
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; c.execute("PRAGMA foreign_keys=ON"); return c
with db() as c:
 c.executescript("""CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,display_name TEXT NOT NULL,created_at INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY,sender_id INTEGER NOT NULL REFERENCES users(id),recipient_id INTEGER NOT NULL REFERENCES users(id),body TEXT NOT NULL,created_at INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS msg_pair ON messages(sender_id,recipient_id,id);""")
def hp(p,s=None):
 s=s or secrets.token_bytes(16); return s.hex()+"$"+hashlib.pbkdf2_hmac("sha256",p.encode(),s,210000).hex()
def check(p,v):
 try:
  s,d=v.split("$",1); return hmac.compare_digest(hp(p,bytes.fromhex(s)).split("$",1)[1],d)
 except: return False
def token(uid):
 p=f"{uid}:{int(time.time())}"; return p+":"+hmac.new(SECRET.encode(),p.encode(),hashlib.sha256).hexdigest()
def uid(t):
 try:
  a,b,s=t.split(":"); p=a+":"+b
  if not SECRET or not hmac.compare_digest(s,hmac.new(SECRET.encode(),p.encode(),hashlib.sha256).hexdigest()) or int(b)<time.time()-2592000:return None
  return int(a)
 except:return None
def user(auth):
 i=uid(auth.removeprefix("Bearer ").strip() if auth else "")
 if not i: raise HTTPException(401,"Войдите в Losgram")
 with db() as c:r=c.execute("SELECT id,username,display_name FROM users WHERE id=?",(i,)).fetchone()
 if not r: raise HTTPException(401,"Пользователь не найден")
 return dict(r)
class Auth(BaseModel):
 username:str=Field(min_length=3,max_length=24,pattern=r"^[a-zA-Z0-9_]+$")
 password:str=Field(min_length=8,max_length=128)
 display_name:str=Field(default="",max_length=40)
class Msg(BaseModel):
 recipient:str=Field(min_length=3,max_length=24)
 body:str=Field(min_length=1,max_length=4000)
@app.get("/")
def home():return FileResponse(BASE/"static"/"index.html")
@app.get("/health")
def health():return {"ok":True,"service":"Losgram"}
@app.post("/api/register")
def register(x:Auth):
 n=x.username.lower(); name=x.display_name.strip() or n
 try:
  with db() as c:i=c.execute("INSERT INTO users(username,password_hash,display_name,created_at) VALUES(?,?,?,?)",(n,hp(x.password),name,int(time.time()))).lastrowid
 except sqlite3.IntegrityError:raise HTTPException(409,"Имя пользователя уже занято")
 return {"token":token(i),"user":{"id":i,"username":n,"display_name":name}}
@app.post("/api/login")
def login(x:Auth):
 with db() as c:r=c.execute("SELECT * FROM users WHERE username=?",(x.username.lower(),)).fetchone()
 if not r or not check(x.password,r["password_hash"]):raise HTTPException(401,"Неверный логин или пароль")
 return {"token":token(r["id"]),"user":{"id":r["id"],"username":r["username"],"display_name":r["display_name"]}}
@app.get("/api/me")
def me(authorization:Optional[str]=Header(default=None)):return user(authorization)
@app.get("/api/users")
def users(authorization:Optional[str]=Header(default=None)):
 u=user(authorization)
 with db() as c:r=c.execute("SELECT id,username,display_name FROM users WHERE id<>? ORDER BY display_name LIMIT 100",(u["id"],)).fetchall()
 return [dict(x) for x in r]
@app.get("/api/messages/{name}")
def messages(name:str,after:int=0,authorization:Optional[str]=Header(default=None)):
 u=user(authorization)
 with db() as c:
  o=c.execute("SELECT id FROM users WHERE username=?",(name.lower(),)).fetchone()
  if not o:raise HTTPException(404,"Пользователь не найден")
  r=c.execute("""SELECT m.id,m.sender_id,m.recipient_id,m.body,m.created_at FROM messages m
  WHERE ((m.sender_id=? AND m.recipient_id=?) OR (m.sender_id=? AND m.recipient_id=?)) AND m.id>? ORDER BY m.id LIMIT 300""",(u["id"],o["id"],o["id"],u["id"],after)).fetchall()
 return [dict(x) for x in r]
@app.post("/api/messages")
def send(x:Msg,authorization:Optional[str]=Header(default=None)):
 u=user(authorization)
 with db() as c:
  o=c.execute("SELECT id FROM users WHERE username=?",(x.recipient.lower(),)).fetchone()
  if not o:raise HTTPException(404,"Пользователь не найден")
  i=c.execute("INSERT INTO messages(sender_id,recipient_id,body,created_at) VALUES(?,?,?,?)",(u["id"],o["id"],x.body.strip(),int(time.time()))).lastrowid
 return {"id":i,"ok":True}
