
# IOC Log Enricher

Небольшой SOC-инструмент для извлечения публичных IPv4-адресов из логов, подсчёта повторов и базового triage по контексту событий.

Проект сделан как учебный портфолио-кейс для практики Junior SOC Analyst навыков: работа с логами, IOC extraction, фильтрация внутренних IP, базовая классификация подозрительной активности и генерация CSV-отчёта.

## Возможности

- Извлекает IPv4-адреса из лог-файла
- Проверяет валидность IP через `ipaddress`
- Отфильтровывает private/local/reserved адреса
- Считает количество повторов каждого публичного IP
- Анализирует контекст строк лога
- Присваивает базовый verdict:
  - `HIGH`
  - `SUSPICIOUS`
  - `CHECK`
  - `INFO`
- Сохраняет результат в CSV
- Добавляет evidence:
  - номера строк
  - пример строки из лога
  - причину verdict

## Структура проекта

```text
ioc-log-enricher/
├── cases/
├── logs/
│   └── sample.log
├── reports/
│   └── ip_report.csv
├── src/
│   └── extractor.py
├── .gitignore
└── README.md

Пример тестового лога

Файл:

logs/sample.log

Пример событий:

May 18 10:01:12 server sshd[1201]: Failed password for invalid user admin from 185.220.101.1 port 54321 ssh2
May 18 10:01:15 server sshd[1202]: Failed password for root from 185.220.101.1 port 54322 ssh2
May 18 10:02:01 server sshd[1203]: Accepted password for sergey from 192.168.1.15 port 55555 ssh2
May 18 10:03:44 server sshd[1204]: Failed password for invalid user test from 45.155.205.233 port 61211 ssh2
May 18 10:04:02 server sshd[1205]: Failed password for invalid user oracle from 45.155.205.233 port 61212 ssh2
May 18 10:04:45 server sshd[1206]: Failed password for invalid user postgres from 45.155.205.233 port 61213 ssh2
May 18 10:05:22 server app[900]: Connection from 127.0.0.1 accepted
May 18 10:06:10 server nginx[333]: GET /login from 8.8.8.8 status 200

Запуск

Из корня проекта:

python src/extractor.py logs/sample.log -o reports/ip_report.csv

Проверка синтаксиса

python -m py_compile src/extractor.py

Пример вывода

[OK] Public IP indicators: 3
[OK] Report saved to: reports/ip_report.csv

Поля CSV-отчёта
Поле	Описание
ip	Публичный IPv4-адрес
count	Количество повторов IP в логе
verdict	Базовый аналитический verdict
reason	Причина классификации
line_numbers	Номера строк, где найден IP
sample_line	Пример строки-доказательства
Пример результата

45.155.205.233 -> HIGH
185.220.101.1  -> SUSPICIOUS
8.8.8.8        -> CHECK

Private/local адреса вроде 192.168.1.15 и 127.0.0.1 не попадают в отчёт, потому что скрипт оставляет только публичные IP, пригодные для дальнейшего enrichment.
Логика triage

Примерная логика:

    HIGH: несколько событий с failed password, invalid user или похожим атакующим контекстом

    SUSPICIOUS: найден подозрительный контекст, но повторов меньше

    CHECK: есть слабый подозрительный контекст или повторяющаяся активность

    INFO: публичный IP найден, но явных признаков атаки нет

Что демонстрирует проект

Этот проект показывает базовые навыки SOC-аналитика:

    чтение и парсинг логов

    извлечение IOC

    фильтрация нерелевантных адресов

    первичная классификация событий

    работа с evidence

    генерация отчёта для дальнейшего анализа

Следующие улучшения

Планируемые доработки:

    enrichment через AbuseIPDB или VirusTotal

    добавление severity score

    экспорт в JSON

    сохранение case report

    поддержка нескольких лог-файлов

    более точная классификация web/auth событий
