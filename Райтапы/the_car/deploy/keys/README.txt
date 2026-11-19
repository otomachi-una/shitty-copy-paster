ГОТОВЫЕ КЛЮЧИ НА 20 КОМАНД — the_car
====================================

Сгенерировано заранее штатным checker/generate_team_keys.py.
Во время соревнования НИЧЕГО генерировать не нужно — только раздать.

СОДЕРЖИМОЕ
----------
  teams.csv                манифест team_id,host, из которого всё сделано
  env/team-01.env ... -20  ПУБЛИЧНО. Выдаётся командам. TEAM_ID + CHECKER_PUBKEY
  private/checker-keys.json ПРИВАТНО. Только жюри, только на хост ForcAD

Схема адресов в teams.csv: команда NN -> 192.168.1.(8+NN),
то есть team 01 = 192.168.1.9 ... team 20 = 192.168.1.28.
192.168.1.8 — сам ForcAD, он в манифесте не участвует.

ЖЮРИ: ПОДКЛЮЧИТЬ КЛЮЧИ К ForcAD
-------------------------------
  scp private/checker-keys.json forcad@192.168.1.8:/tmp/
  ssh forcad@192.168.1.8
  sudo install -d -m 700 -o forcad -g forcad /etc/forcad/carhack
  install -m 600 /tmp/checker-keys.json /etc/forcad/carhack/checker-keys.json
  rm /tmp/checker-keys.json

Воркер ForcAD уже смонтирован на /etc/forcad/carhack (ro) и читает
CHECKER_KEYS_FILE=/run/secrets/carhack/checker-keys.json. После замены файла:
  cd /opt/forcad && docker compose restart celery

Полная раскладка файлов по машинам — DEPLOY.txt в корне репозитория.

В /opt/forcad/config.yml секция teams должна содержать ровно те же 20 хостов,
что и teams.csv. Хост без записи в checker-keys.json даёт CHECKER_ERROR
каждый раунд (см. текущий Team 2 / 10.0.0.12).

КОМАНДЕ
-------
Выдать ровно один файл team-NN.env — он кладётся рядом с docker-compose.yaml
как .env. Публичный ключ не секрет; приватный у команды отсутствует, поэтому
подделать вызовы чекера (diag_auth, admin_provision) она не может.

  cp team-05.env src/.env
  echo "TELE_KEY=$(openssl rand -hex 32)" >> src/.env    # обязательно для src_fix
  docker compose up -d --build

ЕСЛИ АДРЕС КОМАНДЫ ДРУГОЙ
-------------------------
Ключ привязан к хосту только внутри checker-keys.json. Сервис проверяет
лишь TEAM_ID и CHECKER_PUBKEY, поэтому перегенерация НЕ нужна — достаточно
переименовать ключ-хост в JSON:

  python3 - <<'EOF'
  import json
  p = "/etc/forcad/carhack/checker-keys.json"
  d = json.load(open(p))
  d["10.60.5.9"] = d.pop("192.168.1.9")      # старый адрес -> новый
  json.dump(d, open(p, "w"), indent=2, sort_keys=True)
  EOF

Тот же адрес обязательно поправить и в /opt/forcad/config.yml, затем
restart celery. Файл team-NN.env при этом не меняется.

ПРОВЕРКА ПЕРЕД ИГРОЙ
--------------------
  docker exec forcad-celery-1 \
    python /checkers/the_car/smoke_checker.py 192.168.1.9 \
    --checker /checkers/the_car/checker.py
Ожидаемый вывод — 14 строк со 101 и ALL_OK.

ВАЖНО
-----
private/checker-keys.json — это 20 приватных подписных ключей. Утечка даёт
любой команде право ходить как чекер на все боксы. Не коммитить, не
выкладывать в раздачу игрокам, держать 600 и только на хосте жюри.
Этот комплект заменяет текущий одиночный ключ на стенде (team_id=1).
