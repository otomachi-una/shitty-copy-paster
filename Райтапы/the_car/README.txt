the_car — Attack-Defence сервис для ForcAD
==========================================

ЧТО ЭТО
-------
Виртуальный автомобиль (ВАЗ-2106) как CTF-сервис: шесть эмулируемых ECU
обмениваются кадрами по внутренней CAN-шине, физика крутится на 20 Гц,
состояние отдаётся в веб-интерфейс с 3D-моделью. Шесть мест под флаги
соответствуют шести независимым уязвимостям в разных ECU.

Стек: Python 3.12, FastAPI, asyncio, один Docker-контейнер.

ТРИ ТОЧКИ ВХОДА
---------------
  8080   основной HTTP: состояние, трек, WebSocket, медиа, чёрный ящик
  8888   HTTP автопилота: аккаунты, JWT-сессии, маршруты, миссии
  31337  TCP диагностический CLI, построчный текст

ECU: engine (тяга, зажигание), abs (тормоз + эмулируемая память),
autopilot (руль, поворотник), telemetry (бикон скорости, чёрный ящик),
infotainment (медиа, ID3), physics (велосипедная модель).

ФУНКЦИОНАЛ
----------
8080:
  GET  /api/health                       живость всех ECU
  GET  /api/state  /api/track            снапшот, трек; WS /ws/state (5 Гц)
  POST /api/media/register  /upload      аккаунт и загрузка MP3; флаг -> ID3 COMM
  GET  /api/media/flag/{track_id}        отдаёт COMM только владельцу
  POST /api/media/albumart               арифметика над обложкой (Pillow)
  POST /api/media/pack                   распаковка tar с медиа
  POST /api/blackbox/register  /store    аккаунт и запись флага в чёрный ящик
  GET  /api/blackbox/get/{id}            расшифровка только владельцу
  GET  /api/blackbox/raw/{id}            nonce+ciphertext в base64, БЕЗ авторизации

8888:
  POST /register  /login                 аккаунт, RS256 JWT на 1 час
  POST /api/route/save                   секрет маршрута по ключу
  GET  /api/route/load?key=              чтение своего маршрута
  POST /api/route/export                 выгрузка метаданных маршрута в exports
  GET  /api/route/export?path=           чтение файла из каталога exports
  POST /api/adminsecret  GET то же       хранилище админского секрета
  POST /api/mission                      приём YAML-миссии
  POST /api/checker/challenge  /admin/provision   выдача admin по подписи чекера
  GET  /api/jwks                         публичный ключ JWT

31337: help, ping <ecu>, challenge, diag_auth <sig>, diag_store, diag_fetch,
can_send <id> <hex>, can_recv, can_sniff, store_abs, write_abs, read_abs.

Доверие чекеру: Ed25519. Команда получает только TEAM_ID и CHECKER_PUBKEY,
приватный ключ остаётся у жюри. Challenge одноразовый, живёт 30 с, привязан
к team_id, действию и TCP-сессии — реплей и подделка невозможны.

УЯЗВИМОСТИ (6 мест, все проверены эксплойтами на живом сервисе)
--------------------------------------------------------------
1. Path traversal в экспорте маршрутов (8888)
   read_export() склеивает путь без канонизации.
   GET /api/route/export?path=../route_store/<key>   -> флаг места 1
   GET /api/route/export?path=../admin_store/<user>  -> ещё и флаг места 6
   Флаг лежит в route_store/, НЕ в routes/. Без авторизации вообще.

2. Утечка диагностической шины (31337)
   Кадры 0x7DF с флагом зеркалятся в публичное кольцо истории.
   can_sniff без diag_auth -> собрать чанки (seq-байт + 7 байт флага).

3. Отсутствие проверки токена чтения в ABS (31337)
   LEGACY_READ_COMPAT: пустой/отсутствующий токен обходит привязку,
   а длина чтения не ограничена окном.
   read_abs <addr> 200   -> дамп 512 байт региона 0x2000..0x4000.

4. Три дыры в infotainment (8080) — все дают RCE от root
   a) Pillow 10.1.0, ImageMath.eval с именами окружения от клиента.
      Голый PoC из CVE-2023-50447 НЕ работает: scan() требует, чтобы каждое
      имя было в окружении. Обход — объявить дандеры ключами values:
        values = {"expression": "a.__class__.__init__.__globals__"
                                "['__builtins__']['__import__']('os').system(CMD)",
                  "__class__":0, "__init__":0, "__globals__":0, "system":0}
   b) tarfile.extractall без filter (CVE-2007-4559): запись в любой путь.
   c) native/id3parse: strcpy в буфер char[64], собран с -fno-stack-protector.
      PIE и NX на месте, канарейки нет. COMM длиннее 63 байт -> SIGSEGV,
      дальше нужен обход ASLR. Парсер запускается от root.

5. Статический ключ чёрного ящика (8080)
   DEFAULT_TELE_KEY = b"CarHack-telemetry-aes-key-v1-32b" одинаков во всех образах,
   а /api/blackbox/raw/{id} отдаёт nonce+ciphertext без авторизации.
   AES-GCM, AAD = b"carhack:blackbox:v1" -> расшифровка офлайн.

6. Секрет сервисных токенов выведен из публичного ключа (8888)
   Кроме RS256-сессий decode() принимает HS256 "сервисные" токены, а их
   общий секрет берётся как sha256(SERVICE_SECRET_LABEL + публичный ключ в DER),
   то есть целиком вычисляется из того, что сервис сам раздаёт в /api/jwks.
   Взять n/e из /api/jwks, собрать DER, вывести секрет, подписать HS256-токен
   с role=admin и sub=<логин из attack data> -> GET /api/adminsecret.
   Доменная метка обязательна: без неё HMAC не сойдётся.
   Рядом: POST /api/mission зовёт yaml.load(Loader=yaml.Loader) на PyYAML
   5.3.1 -> !!python/object/apply:os.system, RCE от ecu_autopilot.

SLA-атака (не флаг, бьёт по доступности)
   PEDAL_SENSOR_AUTHORITY: свежий кадр датчика педали 0x101 перебивает команду
   тяги 0x100. Флуд can_send 101 00 роняет скорость 7.2 -> 0.28 за 18 с.

src_fix закрывает всё перечисленное: канонизация пути, record_in_ring=False
плюс гейт кольца, обязательный непустой токен ABS, memcpy с границей и
полный набор митигаций компилятора, ключ из TELE_KEY, RS256-only, yaml.safe_load,
filter="data", фильтр выражений album-art, Pillow 10.2.0 / PyJWT 2.8.0 /
PyYAML 6.0.1, PEDAL_SENSOR_AUTHORITY=False, сервисные HS256-токены
убраны целиком.

ЗАПУСК
------
Пошаговый деплой и раскладка файлов по машинам — DEPLOY.txt.
Раздача ключей командам — deploy/keys/README.txt.
Эталонные сплойты на все шесть мест — sploit/, см. sploit/README.txt.

Коротко: команда получает один team-NN.env, кладёт его в src/.env и делает
docker compose up -d --build. Жюри кладёт checker/ на хост ForcAD и
checker-keys.json в /etc/forcad/carhack/.

Проверено на ForcAD 192.168.1.8: src и src_fix проходят check/put/get по всем
шести местам (101/OK), все эксплойты выше работают на src и блокируются
в src_fix.

ЧТО ЗНАТЬ ПЕРЕД ИГРОЙ
---------------------
* CLI на 31337 не аутентифицирован для can_send. Три пакета
  (can_send 100 00, can_send 123 ff, can_send 123 00) выставляют скорость
  ровно в 0.0 навсегда — состояние не восстанавливается, CHECK даёт MUMBLE
  каждый раунд. Работает и на src_fix. Командам придётся закрывать это самим:
  чекеру нужен только can_send 201 01, остальные control-ID можно запретить.
* Сборка тянет three.js с unpkg.com. Без интернета на вулнбоксе пересборка
  после патча не пройдёт — заранее положите vendor-файлы в образ.
* Главный процесс идёт от root, UID сбрасывается только для автопилота.
  RCE через место 4 даёт весь бокс, а не один флаг.
* CHECK каждый раунд проверяет album-art, media/pack, mission, blackbox/raw,
  can_sniff и round-trip route/export, а также отказ diag_auth на битой
  подписи и отказ read_abs на неверном токене. Удаление любого из этих
  эндпоинтов даёт MUMBLE, то есть срезать поверхность атаки не выйдет.
* service.yaml и forcad_config.yml стоят на puts:1/gets:1, а на стенде
  puts:6/gets:6. ForcAD выбирает место случайно (secrets.choice(1..places)),
  поэтому при puts:1 пять мест из шести большую часть раундов пустуют.
  Для шести мест ставьте puts:6/gets:6 везде.
* checker/checker.py должен лежать с LF: ForcAD запускает его напрямую, и
  shebang с CR даёт код 127. Файл нормализован, .gitattributes нет —
  следите при копировании с Windows.
