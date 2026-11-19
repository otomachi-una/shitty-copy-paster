# Sanitized chat network trace

No prompt, response, cookie, authorization header, or WebSocket payload contents are stored.

## qwen-1: instructions-source-part-001

- Prompt characters: 120775
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| requestWillBeSent | chat.qwen.ai | /api/v2/configs/setting-config | GET |  | False |  |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/tts/config | GET |  | False |  |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/users/status | POST |  | True | 222 |  |  |
| requestWillBeSent | auth.qwen.ai | /api/v2/auths/refresh | GET |  | False |  |  |  |
| requestWillBeSent | auth.qwen.ai | /api/v2/auths/refresh | OPTIONS |  | False |  |  |  |
| responseReceived | chat.qwen.ai | /api/v2/configs/setting-config | GET | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/configs/setting-config | GET |  |  |  | 1252 |  |
| responseReceived | chat.qwen.ai | /api/v2/tts/config | GET | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/tts/config | GET |  |  |  | 17171 |  |
| responseReceived | auth.qwen.ai | /api/v2/auths/refresh | OPTIONS | 204 |  |  |  |  |
| loadingFinished | auth.qwen.ai | /api/v2/auths/refresh | OPTIONS |  |  |  | 0 |  |
| responseReceived | chat.qwen.ai | /api/v2/users/status | POST | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/users/status | POST |  |  |  | 412 |  |
| responseReceived | auth.qwen.ai | /api/v2/auths/refresh | GET | 200 |  |  |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/configs/ | GET |  | False |  |  |  |
| loadingFinished | auth.qwen.ai | /api/v2/auths/refresh | GET |  |  |  | 628 |  |
| responseReceived | chat.qwen.ai | /api/v2/configs/ | GET | 200 |  |  |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/models/ | GET |  | False |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/configs/ | GET |  |  |  | 1671 |  |
| responseReceived | chat.qwen.ai | /api/v2/models/ | GET | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/models/ | GET |  |  |  | 1360 |  |
| requestWillBeSent | auth.qwen.ai | /api/v2/auths/ | GET |  | False |  |  |  |
| requestWillBeSent | auth.qwen.ai | /api/v2/auths/ | OPTIONS |  | False |  |  |  |
| responseReceived | auth.qwen.ai | /api/v2/auths/ | OPTIONS | 204 |  |  |  |  |
| loadingFinished | auth.qwen.ai | /api/v2/auths/ | OPTIONS |  |  |  | 0 |  |
| responseReceived | auth.qwen.ai | /api/v2/auths/ | GET | 200 |  |  |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/users/status | POST |  | True | 519 |  |  |
| loadingFinished | auth.qwen.ai | /api/v2/auths/ | GET |  |  |  | 505 |  |
| responseReceived | chat.qwen.ai | /api/v2/users/status | POST | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/users/status | POST |  |  |  | 412 |  |

## qwen-1: instructions-source-part-001

- Prompt characters: 120775
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| requestWillBeSent | chat.qwen.ai | /api/v2/users/status | POST |  | True | 539 |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/chats/new | POST |  | True | 119 |  |  |

## qwen-1: instructions-source-part-001

- Prompt characters: 120775
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| responseReceived | chat.qwen.ai | /api/v2/users/status | POST | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/users/status | POST |  |  |  | 411 |  |
| responseReceived | chat.qwen.ai | /api/v2/chats/new | POST | 200 |  |  |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/users/status | POST |  | True | 569 |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions | POST |  | True | 130664 |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/chats/new | POST |  |  |  | 471 |  |

## qwen-1: instructions-source-part-001

- Prompt characters: 120775
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| responseReceived | chat.qwen.ai | /api/v2/chat/completions | POST | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions | POST |  |  |  | 896 |  |
| requestWillBeSent | aplus.qwen.ai | /tongyi-sg.qwen_chat.showBaxiaCaptchaModal | GET |  | False |  |  |  |
| responseReceived | aplus.qwen.ai | /tongyi-sg.qwen_chat.showBaxiaCaptchaModal | GET | 200 |  |  |  |  |
| loadingFinished | aplus.qwen.ai | /tongyi-sg.qwen_chat.showBaxiaCaptchaModal | GET |  |  |  | 629 |  |
| responseReceived | chat.qwen.ai | /api/v2/users/status | POST | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/users/status | POST |  |  |  | 412 |  |
| requestWillBeSent | g.alicdn.com | /AWSC/CAPTCHA/0.0.1/awsc.js | GET |  | False |  |  |  |
| responseReceived | g.alicdn.com | /AWSC/CAPTCHA/0.0.1/awsc.js | GET | 200 |  |  |  |  |
| loadingFinished | g.alicdn.com | /AWSC/CAPTCHA/0.0.1/awsc.js | GET |  |  |  | 3834 |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/punishTextFetch | GET |  | False |  |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET |  | False |  |  |  |

## qwen-1: instructions-source-part-001

- Prompt characters: 120775
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| requestWillBeSent | o.alicdn.com | /secdev/storage-br/secaptcha/362f987b88325959.js | GET |  | False |  |  |  |
| responseReceived | o.alicdn.com | /secdev/storage-br/secaptcha/362f987b88325959.js | GET | 200 |  |  |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET |  | False |  |  |  |
| loadingFinished | o.alicdn.com | /secdev/storage-br/secaptcha/362f987b88325959.js | GET |  |  |  | 34538 |  |
| responseReceived | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/punishTextFetch | GET | 200 |  |  |  |  |
| requestWillBeSent | g.alicdn.com | /bsop-static/scratch-captcha/0.0.59/index.js | GET |  | False |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/punishTextFetch | GET |  |  |  | 1132 |  |
| responseReceived | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET |  |  |  | 220 |  |
| responseReceived | g.alicdn.com | /bsop-static/scratch-captcha/0.0.59/index.js | GET | 200 |  |  |  |  |
| loadingFinished | g.alicdn.com | /bsop-static/scratch-captcha/0.0.59/index.js | GET |  |  |  | 98507 |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET |  | False |  |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET |  | False |  |  |  |
| responseReceived | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET | 200 |  |  |  |  |

## qwen-1: instructions-source-part-001

- Prompt characters: 120775
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET |  |  |  | 193 |  |
| responseReceived | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET |  |  |  | 193 |  |
| responseReceived | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET |  |  |  | 193 |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET |  | False |  |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/puzzleCaptchaGet | GET |  | False |  |  |  |

## qwen-1: instructions-source-part-001

- Prompt characters: 120775
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| responseReceived | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET |  |  |  | 193 |  |
| responseReceived | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/puzzleCaptchaGet | GET | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/puzzleCaptchaGet | GET |  |  |  | 13764 |  |

## qwen-1: instructions-source-part-001

- Prompt characters: 120775
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/puzzleCaptchaValidate | GET |  | False |  |  |  |

## qwen-1: instructions-source-part-001

- Prompt characters: 120775
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| responseReceived | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/puzzleCaptchaValidate | GET | 200 |  |  |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET |  | False |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/puzzleCaptchaValidate | GET |  |  |  | 678 |  |
| responseReceived | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET |  |  |  | 193 |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions | POST |  | True | 130664 |  |  |
| requestWillBeSent | aplus.qwen.ai | /tongyi-sg.qwen_chat.hideBaxiaCaptchaModal | GET |  | False |  |  |  |
| responseReceived | aplus.qwen.ai | /tongyi-sg.qwen_chat.hideBaxiaCaptchaModal | GET | 200 |  |  |  |  |
| loadingFinished | aplus.qwen.ai | /tongyi-sg.qwen_chat.hideBaxiaCaptchaModal | GET |  |  |  | 629 |  |

## qwen-1: instructions-source-part-001

- Prompt characters: 120775
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| responseReceived | chat.qwen.ai | /api/v2/chat/completions | POST | 200 |  |  |  |  |

## qwen-1: instructions-source-part-001

- Prompt characters: 120775
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions | POST |  |  |  | 1012 |  |

## qwen-1: instructions-source-part-001

- Prompt characters: 120775
- UI settled: True
- No Network-domain events observed in this interval.

## qwen-1: source-part-002

- Prompt characters: 50306
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions | POST |  | True | 55084 |  |  |

## qwen-1: source-part-002

- Prompt characters: 50306
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| responseReceived | chat.qwen.ai | /api/v2/chat/completions | POST | 200 |  |  |  |  |

## qwen-1: source-part-002

- Prompt characters: 50306
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions | POST |  |  |  | 1005 |  |

## qwen-1: source-part-002

- Prompt characters: 50306
- UI settled: True
- No Network-domain events observed in this interval.

## qwen-1: source-part-003

- Prompt characters: 130306
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions | POST |  | True | 141244 |  |  |

## qwen-1: source-part-003

- Prompt characters: 130306
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| responseReceived | chat.qwen.ai | /api/v2/chat/completions | POST | 200 |  |  |  |  |

## qwen-1: source-part-003

- Prompt characters: 130306
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions | POST |  |  |  | 1004 |  |

## qwen-1: source-part-003

- Prompt characters: 130306
- UI settled: True
- No Network-domain events observed in this interval.

## qwen-1: source-part-004

- Prompt characters: 52963
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions | POST |  | True | 57020 |  |  |

## qwen-1: source-part-004

- Prompt characters: 52963
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| responseReceived | chat.qwen.ai | /api/v2/chat/completions | POST | 200 |  |  |  |  |

## qwen-1: source-part-004

- Prompt characters: 52963
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions | POST |  |  |  | 1017 |  |

## qwen-1: source-part-004

- Prompt characters: 52963
- UI settled: True
- No Network-domain events observed in this interval.

## qwen-1: surface-map

- Prompt characters: 1746
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions | POST |  | True | 2662 |  |  |

## qwen-1: surface-map

- Prompt characters: 1746
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| responseReceived | chat.qwen.ai | /api/v2/chat/completions | POST | 200 |  |  |  |  |

## qwen-1: surface-map

- Prompt characters: 1746
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions | POST |  |  |  | 36295 |  |

## qwen-1: surface-map

- Prompt characters: 1746
- UI settled: True
- No Network-domain events observed in this interval.

## qwen-1: final-findings

- Prompt characters: 5196
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions | POST |  | True | 6153 |  |  |

## qwen-1: final-findings

- Prompt characters: 5196
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| responseReceived | chat.qwen.ai | /api/v2/chat/completions | POST | 200 |  |  |  |  |

## qwen-1: final-findings

- Prompt characters: 5196
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions | POST |  |  |  | 62524 |  |

## qwen-1: final-findings

- Prompt characters: 5196
- UI settled: True
- No Network-domain events observed in this interval.
