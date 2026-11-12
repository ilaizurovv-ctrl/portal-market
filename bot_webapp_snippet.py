# Добавь этот фрагмент в существующего ShuzaGram-бота.
# URL замени на публичный HTTPS-адрес после публикации сайта.
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo

WEBAPP_URL = "https://YOUR-PUBLIC-DOMAIN/"

async def open_market(update, context):
    keyboard = [[InlineKeyboardButton(
        "🌌 Открыть PORTALS.COM",
        web_app=WebAppInfo(url=WEBAPP_URL)
    )]]
    await update.message.reply_text(
        "Добро пожаловать в PORTALS.COM!",
        reply_markup=InlineKeyboardMarkup(keyboard)
    )

# В Application:
# app.add_handler(CommandHandler("market", open_market))
