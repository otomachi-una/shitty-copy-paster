# Local ground-truth checklist (AML)

This file is for post-run manual benchmarking. It is not included in prompts sent to chat sessions.

- [ ] **AML-1: Почему поиск дубликатов процитировал чужую заметку** — Хранилище: Place 1 · `CaseNote.body`; Поле утечки: `candidate.match_explanation`; files: internal/casework/matching_evidence.go, internal/httpapi/dedup_merge_preview.go
- [ ] **AML-2: Как признак `Redacted` повысил уровень доступа в ленте** — Хранилище: Place 1 · `CaseNote.body`; Поле утечки: `activities[].activity_narrative`; files: internal/audit/activity_hydration.go, internal/httpapi/activity_views.go
- [ ] **AML-3: Одна своя запись открыла чужие заключения в графе связей** — Хранилище: Place 2 · `EDDRecord.confidential_comment`; Поле утечки: `summaries[].assessment_summary`; files: internal/graph/repository_entity_summaries.go
- [ ] **AML-4: Связанное дело оказалось «корневым» при сборке экспорта** — Хранилище: Place 1 · `CaseNote.body`; Поле утечки: `bundle.linked_evidence[]`; files: internal/exporting/export_linked_evidence.go, internal/exporting/redaction.go
- [ ] **AML-5: Комната расследований поверила содержимому блока, но проигнорировала его политику** — Хранилище: Place 1 и Place 2 · `CaseNote.body` / `EDDRecord.confidential_comment`; files: internal/networkroom/dossier_context.go
