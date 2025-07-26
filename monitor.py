import requests
import time
from config import TELEGRAM_BOT_TOKEN, TELEGRAM_USER_ID, CHECK_INTERVAL, VT_API_KEY
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOMAINS_PATH = os.path.join(BASE_DIR, "domains.txt")


print("Скрипт запущен!")

def send_telegram(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_USER_ID,
        "text": message,
        "parse_mode": "HTML"
    }
    try:
        requests.post(url, data=payload, timeout=10)
    except Exception as e:
        print(f"Ошибка отправки в Telegram: {e}")

def is_malicious_virustotal(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "x-apikey": VT_API_KEY
    }
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        data = resp.json()
        print(f"VirusTotal для {domain}: {data}")
        # Анализируем результаты
        last_analysis_stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        last_analysis_results = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
        malicious = last_analysis_stats.get("malicious", 0)
        suspicious = last_analysis_stats.get("suspicious", 0)
        reason = []
        engines = []
        for engine, result in last_analysis_results.items():
            if result.get("category") in ("malicious", "suspicious"):
                reason.append(f"{engine}: {result.get('result')}")
                engines.append(engine)
        is_bad = malicious > 0 or suspicious > 0
        reason_str = "; ".join(reason) if reason else "-"
        bad_url = domain if is_bad else "-"
        return is_bad, reason_str, bad_url
    except Exception as e:
        print(f"Ошибка VirusTotal для {domain}: {e}")
        return False, "ошибка запроса", "-"

def main():
    with open(DOMAINS_PATH, "r") as f:
        domains = [line.strip() for line in f if line.strip()]
    already_blocked = set()
    while True:
        for domain in domains:
            blocked, reason, bad_url = is_malicious_virustotal(domain)
            status = "ОПАСЕН" if blocked else "чистый"
            print(f"{domain}: {status}; Причина: {reason}; Страница: {bad_url}")
            if blocked and domain not in already_blocked:
                send_telegram(f"❗ <b>{domain}</b> — ОПАСЕН! Причина: {reason}; Страница: {bad_url}")
                already_blocked.add(domain)
            elif not blocked and domain in already_blocked:
                send_telegram(f"✅ <b>{domain}</b> снова считается чистым по данным VirusTotal.")
                already_blocked.remove(domain)
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
