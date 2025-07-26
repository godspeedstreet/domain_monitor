import requests
import time
import os
import logging
from datetime import datetime
from typing import Tuple, List, Set

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('domain_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

try:
    from config import TELEGRAM_BOT_TOKEN, TELEGRAM_USER_ID, CHECK_INTERVAL, VT_API_KEY
except ImportError:
    logger.error("Файл config.py не найден! Создайте его на основе config.example.py")
    exit(1)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOMAINS_PATH = os.path.join(BASE_DIR, "domains.txt")

logger.info("Domain Monitor запущен!")

def send_telegram(message: str) -> bool:
    """
    Отправляет сообщение в Telegram.
    
    Args:
        message: Текст сообщения для отправки
        
    Returns:
        bool: True если сообщение отправлено успешно, False в противном случае
    """
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_USER_ID,
        "text": message,
        "parse_mode": "HTML"
    }
    try:
        response = requests.post(url, data=payload, timeout=10)
        response.raise_for_status()
        logger.info(f"Сообщение отправлено в Telegram: {message[:50]}...")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка отправки в Telegram: {e}")
        return False

def is_malicious_virustotal(domain: str) -> Tuple[bool, str, str]:
    """
    Проверяет домен через VirusTotal API.
    
    Args:
        domain: Домен для проверки
        
    Returns:
        Tuple[bool, str, str]: (является_вредоносным, причина, плохой_url)
    """
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "x-apikey": VT_API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        logger.debug(f"VirusTotal ответ для {domain}: {data}")
        
        # Анализируем результаты
        attributes = data.get("data", {}).get("attributes", {})
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        last_analysis_results = attributes.get("last_analysis_results", {})
        
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
        
        logger.info(f"Проверка {domain}: {'ОПАСЕН' if is_bad else 'чистый'} "
                   f"(malicious: {malicious}, suspicious: {suspicious})")
        
        return is_bad, reason_str, bad_url
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка VirusTotal для {domain}: {e}")
        return False, "ошибка запроса", "-"
    except (KeyError, ValueError) as e:
        logger.error(f"Ошибка парсинга ответа VirusTotal для {domain}: {e}")
        return False, "ошибка парсинга", "-"

def load_domains() -> List[str]:
    """
    Загружает список доменов из файла.
    
    Returns:
        List[str]: Список доменов для мониторинга
    """
    if not os.path.exists(DOMAINS_PATH):
        logger.error(f"Файл {DOMAINS_PATH} не найден!")
        return []
    
    try:
        with open(DOMAINS_PATH, "r", encoding='utf-8') as f:
            domains = []
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line and not line.startswith('#'):
                    domains.append(line)
                elif line.startswith('#'):
                    logger.debug(f"Пропущена строка {line_num}: комментарий")
            
        logger.info(f"Загружено {len(domains)} доменов для мониторинга")
        return domains
        
    except Exception as e:
        logger.error(f"Ошибка чтения файла доменов: {e}")
        return []

def main():
    """Основная функция мониторинга."""
    domains = load_domains()
    if not domains:
        logger.error("Нет доменов для мониторинга. Проверьте файл domains.txt")
        return
    
    already_blocked: Set[str] = set()
    check_count = 0
    
    logger.info(f"Начинаем мониторинг {len(domains)} доменов с интервалом {CHECK_INTERVAL} секунд")
    
    while True:
        check_count += 1
        logger.info(f"=== Проверка #{check_count} ===")
        
        for domain in domains:
            try:
                blocked, reason, bad_url = is_malicious_virustotal(domain)
                status = "ОПАСЕН" if blocked else "чистый"
                
                logger.info(f"{domain}: {status}; Причина: {reason}; Страница: {bad_url}")
                
                if blocked and domain not in already_blocked:
                    message = f"❗ <b>{domain}</b> — ОПАСЕН!\nПричина: {reason}\nСтраница: {bad_url}"
                    if send_telegram(message):
                        already_blocked.add(domain)
                        logger.info(f"Домен {domain} добавлен в список заблокированных")
                
                elif not blocked and domain in already_blocked:
                    message = f"✅ <b>{domain}</b> снова считается чистым по данным VirusTotal."
                    if send_telegram(message):
                        already_blocked.remove(domain)
                        logger.info(f"Домен {domain} удален из списка заблокированных")
                
                # Небольшая пауза между запросами к API
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Ошибка при проверке домена {domain}: {e}")
                continue
        
        logger.info(f"Проверка завершена. Заблокированных доменов: {len(already_blocked)}")
        logger.info(f"Следующая проверка через {CHECK_INTERVAL} секунд...")
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Мониторинг остановлен пользователем")
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}")
        exit(1) 