from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, CallbackContext
import re
import requests
import base64

# 🔹 Enter your bot token
TOKEN = "7845587638:AAEhiDbzhQRZihnZ4Rir3evj7CCmwmr-Qhw"

# ✅ API Keys
VIRUSTOTAL_API_KEY = "e030dd65b186e3e9b654855622136d25883defda1cf6a590d4eb035db341b4b7"
URLSCAN_API_KEY = "0195a83b-a9f4-799f-a918-9bb361466241"

# 🔹 URL pattern detection
URL_PATTERN = r"(https?://[^\s]+)"

# 🔹 Function to check if a link is phishing
def is_phishing_link(url):
    phishing_keywords = ["login", "verify", "secure", "account", "bank", "update", "free", "password"]

    for keyword in phishing_keywords:
        if keyword in url.lower():
            return True

    # ✅ Check with VirusTotal API
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    # Encode the URL in Base64
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{encoded_url}", headers=headers)
    
    if response.status_code == 200:
        result = response.json()
        malicious_count = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        if malicious_count > 0:
            return True

    return False

# 🔹 Function to get URL details from URLScan.io
def get_urlscan_report(url):
    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json"
    }
    
    data = {"url": url, "visibility": "public"}
    response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data)

    if response.status_code == 200:
        scan_result = response.json()
        return scan_result.get("result", "URLScan report not found.")
    
    return "Failed to retrieve URLScan report."

# 🔹 /start command
async def start(update: Update, context: CallbackContext):
    await update.message.reply_text(
        "👋 Hello! I am your **Cyber Security Bot**.\n"
        "🔍 I can detect phishing links and verify domain legitimacy.\n"
        "⚠️ To check a suspicious link, just send it in this chat.\n"
        "📢 To report a link, use the `/report <URL>` command."
    )

# 🔹 Link handling (phishing detection & verification)
async def handle_message(update: Update, context: CallbackContext):
    text = update.message.text
    match = re.search(URL_PATTERN, text)

    if match:
        url = match.group(0)
        
        is_suspicious = is_phishing_link(url)
        urlscan_report = get_urlscan_report(url)

        if is_suspicious:
            await update.message.reply_text(
                f"⚠️ This link seems suspicious! Please be cautious before opening.\n"
                f"🔎 URLScan Report: {urlscan_report}"
            )
        else:
            await update.message.reply_text(
                f"✅ This link appears to be safe.\n"
                f"🔎 URLScan Report: {urlscan_report}"
            )
    else:
        await update.message.reply_text(f"📩 You said: {text}")

# 🔹 Reporting function
async def report_link(update: Update, context: CallbackContext):
    if context.args:
        reported_link = context.args[0]
        with open("reported_links.txt", "a") as file:
            file.write(reported_link + "\n")
        await update.message.reply_text(f"✅ Thank you! The link **{reported_link}** has been reported.")
    else:
        await update.message.reply_text("⚠️ Please use a valid link with the command. Example: `/report https://example.com`")

# 🔹 Main function to start the bot
def main():
    application = Application.builder().token(TOKEN).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("report", report_link))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    print("🤖 Bot is starting...")
    application.run_polling()

if __name__ == "__main__":
    main()
