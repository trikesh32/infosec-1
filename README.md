# Лаба 1. Защищённый REST API

API для заметок на Flask + SQLite. Можно войти, создать заметку и получить свои заметки.

## Запуск

Нужен Python 3.14. Из папки проекта:

```bash
python3.14 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
flask --app app create-user alice
flask --app app run
```

При создании пользователя вводится пароль от 12 до 128 символов. База создаётся сама.

## API

| Метод | Что делает | JSON запроса |
| --- | --- | --- |
| `POST /auth/login` | Выдаёт JWT | `{"username":"alice","password":"YOUR_PASSWORD"}` |
| `POST /api/data` | Создаёт заметку | `{"text":"Текст заметки"}` |
| `GET /api/data` | Возвращает свои заметки | Не нужен |

Пример входа, вместо `YOUR_PASSWORD` нужно поставить свой пароль:

```bash
curl http://127.0.0.1:5000/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"YOUR_PASSWORD"}'
```

Для `/api/data` нужен заголовок `Authorization: Bearer <access_token>` с токеном из ответа. Для POST ещё нужен `Content-Type: application/json`. Без токена будет 401.

## Защита

- SQLi: значения передаются через параметры `?`, а не склеиваются с SQL.
- XSS: текст заметок экранируется через `markupsafe.escape()` при выдаче в JSON.
- Пароли хранятся как scrypt-хэши с солью.
- JWT подписан HS256 и живёт 15 минут. Проверяются подпись, срок, issuer и audience. Секрет берётся из окружения.
- ID владельца берётся из токена. Пользователь видит только свои заметки.
- Вход ограничен 5 запросами в минуту с IP.

## Проверки

```bash
pip install -r requirements-dev.txt
pytest -q
```

На push и PR запускаются тесты, Bandit, pip-audit и OWASP Dependency-Check. Dependency-Check роняет сборку при CVSS от 7. Для Python включён экспериментальный анализатор.

[Запуски CI и отчёты](https://github.com/trikesh32/infosec-1/actions/workflows/ci.yml). Отчёты лежат в артефактах `security-results` и `dependency-check-results`, хранятся 14 дней.

[Одно исключение](.github/dependency-check-suppressions.xml): сканер перепутал PyJWT с PHP-библиотекой и выдал чужую CVE-2025-45770.

## Отчёт

[PDF](docs/report.pdf) · [DOCX](docs/report.docx). Описание API и мер защиты, скриншоты проверок и ссылка на запуск CI внутри.
