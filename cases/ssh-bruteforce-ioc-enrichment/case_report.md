# Case Report: SSH Bruteforce IOC Enrichment

## RU

Короткий SOC-кейс по анализу sample log.

Цель: извлечь публичные IP из логов, отфильтровать локальные адреса, оценить контекст событий и обогатить IOC через AbuseIPDB.

## EN

Short SOC case based on a sample log.

Goal: extract public IP indicators from logs, filter local addresses, review event context, and enrich IOCs with AbuseIPDB.

---

## Data source / Источник данных

```text
logs/sample.log
```

---

## Result summary / Итог

| IP | Verdict | Evidence / Доказательства | AbuseIPDB | Note / Вывод |
|---|---|---|---|---|
| `45.155.205.233` | `HIGH` | 3 failed SSH login events, invalid users | score=7, reports=3, RU | Repeated suspicious authentication activity |
| `185.220.101.1` | `SUSPICIOUS` | 2 failed SSH login events | score=100, reports=141, DE | Strong external reputation, suspicious local context |
| `8.8.8.8` | `CHECK` | Web login-related event | score=0, reports=92, US | Needs context review, not automatically malicious |

---

## Analyst notes / Заметки аналитика

### 45.155.205.233

RU: IP несколько раз встречается в failed SSH login событиях с invalid users. Это основной кандидат на высокий приоритет.

EN: The IP appears in repeated failed SSH login events with invalid users. This is the main high-priority finding.

### 185.220.101.1

RU: Локальных событий меньше, но AbuseIPDB показывает высокий score. Нужно проверить успешные входы и появление IP на других хостах.

EN: Local event count is lower, but AbuseIPDB reputation is high. Successful logins and activity on other hosts should be checked.

### 8.8.8.8

RU: AbuseIPDB score равен 0, но IP встречается в login-related web event. Это не incident, а повод проверить контекст.

EN: AbuseIPDB score is 0, but the IP appears in a login-related web event. This is not an incident by itself, but it needs context review.

---

## Final conclusion / Финальный вывод

RU:

Найдены 3 публичных IP. Самый важный IOC - `45.155.205.233`, потому что он связан с повторяющимися failed SSH login событиями.  
`185.220.101.1` требует внимания из-за сильной внешней репутации.  
`8.8.8.8` оставлен как `CHECK`, потому что reputation score равен 0, но локальный контекст всё равно нужно проверить.

EN:

3 public IP indicators were found. The most important IOC is `45.155.205.233` because it is linked to repeated failed SSH login events.  
`185.220.101.1` needs attention because of strong external reputation data.  
`8.8.8.8` remains `CHECK` because its reputation score is 0, but local context still needs review.

---

## Skills shown / Показанные навыки

- IOC extraction
- log context analysis
- public/private IP filtering
- AbuseIPDB enrichment
- verdict assignment
- evidence-based triage
- short SOC case reporting

