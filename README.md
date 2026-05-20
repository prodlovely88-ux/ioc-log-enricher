# IOC Log Enricher

## RU

Небольшой SOC-инструмент на Python для извлечения публичных IPv4 из логов, базового triage по контексту и опционального enrichment через AbuseIPDB.

Проект сделан как портфолио-кейс для Junior SOC Analyst.

## EN

A small Python SOC tool for extracting public IPv4 indicators from logs, applying basic contextual triage, and optionally enriching results with AbuseIPDB.

Built as a Junior SOC Analyst portfolio project.

---

## Features / Возможности

- Extract public IPv4 indicators from logs
- Filter private, local and reserved IP addresses
- Count IP occurrences
- Analyze local log context
- Assign verdict: `HIGH`, `SUSPICIOUS`, `CHECK`, `INFO`
- Add evidence: line numbers, reason, sample log line
- Optional AbuseIPDB enrichment
- Readable console report
- CSV export

---

## Project structure / Структура

```text
ioc-log-enricher/
├── cases/
├── logs/
│   └── sample.log
├── reports/
├── src/
│   └── extractor.py
├── .env.example
├── .gitignore
├── README.md
└── requirements.txt
```

Main script / Основной файл:

```text
src/extractor.py
```

---

## Install / Установка

```bash
git clone https://github.com/prodlovely88-ux/ioc-log-enricher.git
cd ioc-log-enricher

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

---

## AbuseIPDB setup / Настройка AbuseIPDB

The tool works without an API key, but enrichment is enabled when `.env` is configured.

Скрипт работает и без API-ключа, но enrichment включается через `.env`.

```bash
cp .env.example .env
```

Example `.env`:

```env
ABUSEIPDB_API_KEY=your_api_key_here
ABUSEIPDB_MAX_AGE_DAYS=90
```

Security note / Важно:

```text
.env must not be committed.
.env нельзя коммитить.
```

---

## Usage / Запуск

Basic run / Базовый запуск:

```bash
python src/extractor.py logs/sample.log
```

Run with CSV export / Запуск с CSV-отчётом:

```bash
python src/extractor.py logs/sample.log -o reports/ip_report.csv
```

Help / Справка:

```bash
python src/extractor.py --help
```

Syntax check / Проверка синтаксиса:

```bash
python -m py_compile src/extractor.py
```

---

## Example output / Пример вывода

```text
=== IOC Enrichment Report ===
Total indicators: 3

[1] 45.155.205.233
    Verdict: HIGH
    Count: 3
    Reason: Multiple failed login or invalid user events
    AbuseIPDB: score=7, reports=3, country=RU
    Source: abuseipdb

[2] 185.220.101.1
    Verdict: SUSPICIOUS
    Count: 2
    Reason: Failed login or invalid user context
    AbuseIPDB: score=100, reports=141, country=DE
    Source: abuseipdb

[3] 8.8.8.8
    Verdict: CHECK
    Count: 1
    Reason: Suspicious keyword found, check surrounding log context
    AbuseIPDB: score=0, reports=92, country=US
    Source: abuseipdb

[OK] CSV report saved to: reports/ip_report.csv
```

---

## CSV fields / Поля CSV

```text
ip
count
verdict
reason
line_numbers
sample_line
abuse_confidence_score
abuse_total_reports
abuse_country
abuse_usage_type
abuse_isp
abuse_domain
enrichment_source
```

---

## Verdict logic / Логика verdict

| Verdict | RU | EN |
|---|---|---|
| `HIGH` | Повторяющиеся явно подозрительные события | Repeated clearly suspicious activity |
| `SUSPICIOUS` | Есть подозрительный контекст | Suspicious context found |
| `CHECK` | Нужно проверить вручную | Needs manual review |
| `INFO` | Публичный IP без явных признаков атаки | Public IP without clear attack signs |

Important / Важно:

```text
AbuseIPDB score=0 does not mean "no data".
score=0 не равно "данных нет".
```

---

## Case reports / Кейсы

- [SSH Bruteforce IOC Enrichment](cases/ssh-bruteforce-ioc-enrichment/case_report.md)

---

## Skills demonstrated / Что показывает проект

- Python scripting
- log parsing
- IOC extraction
- public/private IP filtering
- contextual triage
- AbuseIPDB enrichment
- evidence-based analysis
- CSV reporting
- basic SOC investigation thinking

---

## Current status / Текущий статус

```text
Version: v0.3
Main script: src/extractor.py
Status: working portfolio project
```
