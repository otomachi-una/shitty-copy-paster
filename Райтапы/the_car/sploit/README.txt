Эталонные сплойты the_car — по одному на уязвимость
==================================================

Только для жюри. Командам не раздавать.

  pip install -r requirements.txt
  ./sploit_N.py <host> <attack_data>

Флаг идёт в stdout, ошибки в stderr, код возврата 0 = флаг получен.
attack_data — это публичная строка, которую put вернул ForcAD.

  N  attack_data        уязвимость
  1  route key          path traversal в /api/route/export (8888)
  2  base_seq:chunks    кадры 0x7DF в публичном кольце, can_sniff без diag_auth
  3  hex-адрес          read_abs без токена (31337)
  4  track_id           Pillow 10.1.0 ImageMath -> RCE от root (8080)
  5  record_id          статический AES-ключ + публичный /api/blackbox/raw
  6  логин              секрет HS256 выведен из публичного ключа (8888)

sploit_4 ничего не пишет в чужой бокс: выражение возвращает объект, чей
атрибут mode равен содержимому флага, и album-art отдаёт его в ответе.
sploit_5 и sploit_6 требуют cryptography, остальные — только stdlib.

Альтернативные пути к тем же флагам, сплойтов под них нет:
  место 1 и 6  tarfile без filter в /api/media/pack -> запись от root
  место 1 и 6  yaml.load на PyYAML 5.3.1 в /api/mission -> RCE от ecu_autopilot
  место 6      тот же traversal: /api/route/export?path=../admin_store/<логин>
  место 4      strcpy в char[64] в native/id3parse, нет канарейки
               (PIE и NX на месте, нужен обход ASLR; проверен только SIGSEGV)

Проверено на ForcAD 192.168.1.8: все шесть забирают флаг на src и все шесть
возвращают FAIL на src_fix.
