# Domain Monitor - Мониторинг безопасности доменов

🔍 **Domain Monitor** - это Python-скрипт для автоматического мониторинга доменов на предмет вредоносной активности с использованием VirusTotal API и отправки уведомлений в Telegram.

## 🚀 Возможности

- ✅ Автоматическая проверка доменов через VirusTotal API
- ✅ Отправка уведомлений в Telegram при обнаружении угроз
- ✅ Отслеживание изменений статуса доменов (опасный ↔ безопасный)
- ✅ Настраиваемый интервал проверки
- ✅ Подробная информация о причинах блокировки
- ✅ Логирование результатов проверок

## 📋 Требования

- Python 3.7+
- VirusTotal API ключ
- Telegram Bot Token
- Telegram User ID

## 🛠️ Установка

1. Клонируйте репозиторий:
```bash
git clone https://github.com/godspeedstreet/domain_monitor.git
cd domain_monitor
```

2. Установите зависимости:
```bash
pip install -r requirements.txt
```

3. Настройте конфигурацию:
   - Откройте файл `config.py`
   - Заполните необходимые параметры:
     - `TELEGRAM_BOT_TOKEN` - токен вашего Telegram бота
     - `TELEGRAM_USER_ID` - ваш Telegram ID
     - `VT_API_KEY` - API ключ VirusTotal
     - `CHECK_INTERVAL` - интервал проверки в секундах

4. Добавьте домены для мониторинга в файл `domains.txt` (по одному домену на строку)

## 🚀 Запуск

```bash
python monitor.py
```

## 📁 Структура проекта

```
domain_monitor/
├── monitor.py          # Основной скрипт мониторинга
├── config.py           # Конфигурация
├── domains.txt         # Список доменов для мониторинга
├── requirements.txt    # Зависимости Python
├── README.md          # Документация
└── .gitignore         # Исключения Git
```

## ⚙️ Конфигурация

### config.py
```python
TELEGRAM_BOT_TOKEN = "your_bot_token_here"
TELEGRAM_USER_ID = 123456789
CHECK_INTERVAL = 60  # секунд между проверками
VT_API_KEY = "your_virustotal_api_key"
```

### domains.txt
```
example.com
malicious-site.com
suspicious-domain.org
```

## 📊 Примеры уведомлений

### Обнаружение угрозы:
```
❗ malicious-site.com — ОПАСЕН! 
Причина: Kaspersky: phishing; ESET: malware; 
Страница: malicious-site.com
```

### Домен стал безопасным:
```
✅ malicious-site.com снова считается чистым по данным VirusTotal.
```

## 🔧 Получение API ключей

### VirusTotal API
1. Зарегистрируйтесь на [VirusTotal](https://www.virustotal.com/)
2. Перейдите в раздел API
3. Получите ваш API ключ

### Telegram Bot
1. Найдите [@BotFather](https://t.me/botfather) в Telegram
2. Создайте нового бота командой `/newbot`
3. Получите токен бота
4. Узнайте ваш User ID через [@userinfobot](https://t.me/userinfobot)

## 🛡️ Безопасность

- Никогда не публикуйте ваши API ключи в открытом доступе
- Используйте переменные окружения для хранения чувствительных данных
- Регулярно обновляйте зависимости

## 📝 Логирование

Скрипт выводит информацию о проверках в консоль:
```
Скрипт запущен!
example.com: чистый; Причина: -; Страница: -
malicious-site.com: ОПАСЕН; Причина: Kaspersky: phishing; Страница: malicious-site.com
```

## ⚠️ Отказ от ответственности

Этот инструмент предназначен только для образовательных целей и мониторинга собственных доменов. Используйте его ответственно и в соответствии с условиями использования VirusTotal API.


---
