# Sanitized chat network trace

No prompt, response, cookie, authorization header, or WebSocket payload contents are stored.

## qwen-1: review-material-1

- Prompt characters: 128913
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| requestWillBeSent | chat.qwen.ai | /api/v2/configs/setting-config | GET |  | False |  |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/tts/config | GET |  | False |  |  |  |
| requestWillBeSent | auth.qwen.ai | /api/v2/auths/refresh | GET |  | False |  |  |  |
| requestWillBeSent | auth.qwen.ai | /api/v2/auths/refresh | OPTIONS |  | False |  |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/users/status | POST |  | True | 222 |  |  |
| responseReceived | chat.qwen.ai | /api/v2/configs/setting-config | GET | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/configs/setting-config | GET |  |  |  | 1265 |  |
| responseReceived | chat.qwen.ai | /api/v2/tts/config | GET | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/tts/config | GET |  |  |  | 17190 |  |
| responseReceived | chat.qwen.ai | /api/v2/users/status | POST | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/users/status | POST |  |  |  | 412 |  |
| responseReceived | auth.qwen.ai | /api/v2/auths/refresh | OPTIONS | 204 |  |  |  |  |
| loadingFinished | auth.qwen.ai | /api/v2/auths/refresh | OPTIONS |  |  |  | 0 |  |
| responseReceived | auth.qwen.ai | /api/v2/auths/refresh | GET | 200 |  |  |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/configs/ | GET |  | False |  |  |  |
| loadingFinished | auth.qwen.ai | /api/v2/auths/refresh | GET |  |  |  | 628 |  |
| responseReceived | chat.qwen.ai | /api/v2/configs/ | GET | 200 |  |  |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/models/ | GET |  | False |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/configs/ | GET |  |  |  | 1670 |  |
| responseReceived | chat.qwen.ai | /api/v2/models/ | GET | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/models/ | GET |  |  |  | 1357 |  |
| requestWillBeSent | auth.qwen.ai | /api/v2/auths/ | OPTIONS |  | False |  |  |  |
| requestWillBeSent | auth.qwen.ai | /api/v2/auths/ | GET |  | False |  |  |  |
| responseReceived | auth.qwen.ai | /api/v2/auths/ | OPTIONS | 204 |  |  |  |  |
| loadingFinished | auth.qwen.ai | /api/v2/auths/ | OPTIONS |  |  |  | 0 |  |
| responseReceived | auth.qwen.ai | /api/v2/auths/ | GET | 200 |  |  |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/users/status | POST |  | True | 519 |  |  |
| loadingFinished | auth.qwen.ai | /api/v2/auths/ | GET |  |  |  | 504 |  |
| responseReceived | chat.qwen.ai | /api/v2/users/status | POST | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/users/status | POST |  |  |  | 412 |  |

## qwen-1: review-material-1

- Prompt characters: 128913
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| requestWillBeSent | chat.qwen.ai | /api/v2/users/status | POST |  | True | 539 |  |  |

## qwen-1: review-material-1

- Prompt characters: 128913
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| requestWillBeSent | chat.qwen.ai | /api/v2/chats/new | POST |  | True | 118 |  |  |
| responseReceived | chat.qwen.ai | /api/v2/users/status | POST | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/users/status | POST |  |  |  | 412 |  |
| responseReceived | chat.qwen.ai | /api/v2/chats/new | POST | 200 |  |  |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/users/status | POST |  | True | 569 |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions | POST |  | True | 135356 |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/chats/new | POST |  |  |  | 471 |  |

## qwen-1: review-material-1

- Prompt characters: 128913
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| responseReceived | chat.qwen.ai | /api/v2/users/status | POST | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/users/status | POST |  |  |  | 412 |  |
| responseReceived | chat.qwen.ai | /api/v2/chat/completions | POST | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions | POST |  |  |  | 896 |  |
| requestWillBeSent | aplus.qwen.ai | /tongyi-sg.qwen_chat.showBaxiaCaptchaModal | GET |  | False |  |  |  |
| responseReceived | aplus.qwen.ai | /tongyi-sg.qwen_chat.showBaxiaCaptchaModal | GET | 200 |  |  |  |  |
| loadingFinished | aplus.qwen.ai | /tongyi-sg.qwen_chat.showBaxiaCaptchaModal | GET |  |  |  | 629 |  |

## qwen-1: review-material-1

- Prompt characters: 128913
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| requestWillBeSent | g.alicdn.com | /AWSC/CAPTCHA/0.0.1/awsc.js | GET |  | False |  |  |  |
| responseReceived | g.alicdn.com | /AWSC/CAPTCHA/0.0.1/awsc.js | GET | 200 |  |  |  |  |
| loadingFinished | g.alicdn.com | /AWSC/CAPTCHA/0.0.1/awsc.js | GET |  |  |  | 3335 |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/punishTextFetch | GET |  | False |  |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET |  | False |  |  |  |
| requestWillBeSent | o.alicdn.com | /secdev/storage-br/secaptcha/362f987b88325959.js | GET |  | False |  |  |  |
| responseReceived | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/punishTextFetch | GET | 200 |  |  |  |  |
| requestWillBeSent | g.alicdn.com | /bsop-static/scratch-captcha/0.0.59/index.js | GET |  | False |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/punishTextFetch | GET |  |  |  | 1132 |  |
| responseReceived | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET |  |  |  | 220 |  |

## qwen-1: review-material-1

- Prompt characters: 128913
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| responseReceived | g.alicdn.com | /bsop-static/scratch-captcha/0.0.59/index.js | GET | 200 |  |  |  |  |
| loadingFinished | g.alicdn.com | /bsop-static/scratch-captcha/0.0.59/index.js | GET |  |  |  | 97981 |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET |  | False |  |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET |  | False |  |  |  |
| responseReceived | o.alicdn.com | /secdev/storage-br/secaptcha/362f987b88325959.js | GET | 200 |  |  |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET |  | False |  |  |  |
| loadingFinished | o.alicdn.com | /secdev/storage-br/secaptcha/362f987b88325959.js | GET |  |  |  | 34548 |  |
| responseReceived | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET |  |  |  | 193 |  |
| responseReceived | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET |  |  |  | 193 |  |

## qwen-1: review-material-1

- Prompt characters: 128913
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| responseReceived | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET |  |  |  | 193 |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET |  | False |  |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/puzzleCaptchaGet | GET |  | False |  |  |  |

## qwen-1: review-material-1

- Prompt characters: 128913
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| responseReceived | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET |  |  |  | 193 |  |
| responseReceived | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/puzzleCaptchaGet | GET | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/puzzleCaptchaGet | GET |  |  |  | 13270 |  |

## qwen-1: review-material-1

- Prompt characters: 128913
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/puzzleCaptchaValidate | GET |  | False |  |  |  |

## qwen-1: review-material-1

- Prompt characters: 128913
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| responseReceived | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/puzzleCaptchaValidate | GET | 200 |  |  |  |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET |  | False |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/puzzleCaptchaValidate | GET |  |  |  | 680 |  |

## qwen-1: review-material-1

- Prompt characters: 128913
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| responseReceived | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET | 200 |  |  |  |  |
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions/_____tmd_____/report | GET |  |  |  | 193 |  |
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions | POST |  | True | 135356 |  |  |
| requestWillBeSent | aplus.qwen.ai | /tongyi-sg.qwen_chat.hideBaxiaCaptchaModal | GET |  | False |  |  |  |
| responseReceived | aplus.qwen.ai | /tongyi-sg.qwen_chat.hideBaxiaCaptchaModal | GET | 200 |  |  |  |  |
| loadingFinished | aplus.qwen.ai | /tongyi-sg.qwen_chat.hideBaxiaCaptchaModal | GET |  |  |  | 629 |  |

## qwen-1: review-material-1

- Prompt characters: 128913
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| responseReceived | chat.qwen.ai | /api/v2/chat/completions | POST | 200 |  |  |  |  |

## qwen-1: review-material-1

- Prompt characters: 128913
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions | POST |  |  |  | 1018 |  |

## qwen-1: review-material-1

- Prompt characters: 128913
- UI settled: True
- No Network-domain events observed in this interval.

## qwen-1: review-material-2

- Prompt characters: 128913
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions | POST |  | True | 134825 |  |  |

## qwen-1: review-material-2

- Prompt characters: 128913
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| responseReceived | chat.qwen.ai | /api/v2/chat/completions | POST | 200 |  |  |  |  |

## qwen-1: review-material-2

- Prompt characters: 128913
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions | POST |  |  |  | 1008 |  |

## qwen-1: review-material-2

- Prompt characters: 128913
- UI settled: True
- No Network-domain events observed in this interval.

## qwen-1: review-material-3

- Prompt characters: 128913
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions | POST |  | True | 144867 |  |  |

## qwen-1: review-material-3

- Prompt characters: 128913
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| responseReceived | chat.qwen.ai | /api/v2/chat/completions | POST | 200 |  |  |  |  |

## qwen-1: review-material-3

- Prompt characters: 128913
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions | POST |  |  |  | 1031 |  |

## qwen-1: review-material-3

- Prompt characters: 128913
- UI settled: True
- No Network-domain events observed in this interval.

## qwen-1: final-findings

- Prompt characters: 32846
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| requestWillBeSent | chat.qwen.ai | /api/v2/chat/completions | POST |  | True | 34805 |  |  |

## qwen-1: final-findings

- Prompt characters: 32846
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| responseReceived | chat.qwen.ai | /api/v2/chat/completions | POST | 200 |  |  |  |  |

## qwen-1: final-findings

- Prompt characters: 32846
- UI settled: in progress

| Event | Host | Path | Method | Status | Has body | Request bytes | Response/frame bytes | Error |
|---|---|---|---|---:|---|---:|---:|---|
| loadingFinished | chat.qwen.ai | /api/v2/chat/completions | POST |  |  |  | 15695 |  |

## qwen-1: final-findings

- Prompt characters: 32846
- UI settled: True
- No Network-domain events observed in this interval.
