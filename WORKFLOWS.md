# Chat audit workflows

The default `audit` mode remains one full-service conversation per provider. Granular review is opt-in.

## Whole-service discovery

```bash
python3 manual_chat_contexts.py audit --folder /path/to/task --provider qwen --structured-findings
```

`--structured-findings` asks the same chat to turn confirmed findings into JSON after its report. A valid JSON response is also saved beside the audit trace.

## Granular discovery

```bash
python3 manual_chat_contexts.py audit --folder /path/to/task --provider qwen --granulize=5 --parallel-sessions=2
```

Each session loads the complete source context and its map, then reviews up to five files individually with each target file resent. `--granulize=1` creates one focused file review per session. Without `--granulize`, the ordinary whole-service audit runs.

`--parallel-sessions` limits how many granular sessions run at once. Each session has its own browser context; finished browser windows remain open. Increase `--granulize` or lower parallelism to reduce the number of windows active at once. `prepare` accepts the same `--granulize=N` option and writes prompt plans without opening browsers.

## Continue in the discovery chat

Use the profile printed after `audit`; append the provider folder, such as `.../qwen-1`:

```bash
python3 manual_chat_contexts.py continue --task task-name --provider qwen \
  --attach-profile /path/to/chataudit-chat-contexts/task-name/run-id/qwen-1
```

This sends a follow-up in that existing conversation and asks for both a solver and a patch per confirmed finding. Use `--scope solver` or `--scope patch` to request only one deliverable. Supplying `--findings-json FILE` adds structured findings to the follow-up.

## One new context per finding

```bash
python3 manual_chat_contexts.py solve --folder /path/to/task --provider qwen
```

Paste the findings JSON at the prompt and finish with Ctrl-D. The CLI validates it, creates one independent full-context chat per finding, and asks each chat for that finding's solver and patch. `--findings-json FILE` reads from a file instead. `--parallel-sessions` controls concurrent finding chats.

## Prefill a free discussion context

```bash
python3 manual_chat_contexts.py context --folder /path/to/task --provider qwen
```

The script loads the source into a chat, confirms the context is ready, and leaves the browser open for follow-up questions.

Ground-truth directories and spoiler files are excluded from source collection. Review `SKIPPED_FILES.md` in each generated output directory to see what was omitted.
