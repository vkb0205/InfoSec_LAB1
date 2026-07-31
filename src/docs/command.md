# Mini Vault — full client commands (Windows PowerShell)

Repo: `D:\Uni_Project\InfoSec\InfoSec_LAB1`

Copy-paste only. No variables. Strings always quoted.

Demo values used below:

- Master passphrase: `Str0ng!Passphrase123`
- User email: `vkb0205@gmail.com`
- User passphrase: `Vukh@cb!nh0205@`
- KV path: `secret/vkb0205@gmail.com/demo`

After **login**, copy the `token` value from the response and replace every `PASTE_TOKEN_HERE` below.

URL must be `http://` (two slashes). Unlock/init/register/login are **POST**, not GET.

---

## 0) Start server (separate terminal)

```powershell
python main.py serve
```

Ctrl+C stops server (vault locks; all tokens die).

---

## 1) Feature 0.1 — vault

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/v1/status"
```

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/v1/init" -Method POST -ContentType "application/json" -Body '{"passphrase":"Str0ng!Passphrase123"}'
```

(Skip init if already initialized → `ALREADY_INITIALIZED`.)

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/v1/unlock" -Method POST -ContentType "application/json" -Body '{"passphrase":"Str0ng!Passphrase123"}'
```

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/v1/status"
```

Expect: `unlocked`.

---

## 2) Feature 0.2 — auth

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/v1/auth/register" -Method POST -ContentType "application/json" -Body '{"email":"vkb0205@gmail.com","passphrase":"Vukh@cb!nh0205@","confirmation":"Vukh@cb!nh0205@"}'
```

(Skip if already registered → `DUPLICATE_USER`.)

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/v1/auth/login" -Method POST -ContentType "application/json" -Body '{"email":"vkb0205@gmail.com","passphrase":"Vukh@cb!nh0205@"}'
```

Response example: `token` = long string. Copy it. Replace `PASTE_TOKEN_HERE` in every command below.

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/v1/auth/session" -Headers @{ Authorization = "Bearer PASTE_TOKEN_HERE" }
```

Expect: email `vkb0205@gmail.com`.

---

## 3) Feature 1 — KV write / read / delete

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/v1/kv/write" -Method POST -Headers @{ Authorization = "Bearer xAGLCeEDRZFmY90g2pqHg4FEbqU5JXAMTN2kl42aOa4" } -ContentType "application/json" -Body '{"path":"secret/vkb0205@gmail.com/demo","data":"my-secret"}'
```

Expect: `version`, `created_at`, `updated_at`.

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/v1/kv/read?path=secret/vkb0205@gmail.com/demo" -Headers @{ Authorization = "Bearer xAGLCeEDRZFmY90g2pqHg4FEbqU5JXAMTN2kl42aOa4" }
```

Expect: `data` = `my-secret`.

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/v1/kv/delete?path=secret/vkb0205@gmail.com/demo" -Method DELETE -Headers @{ Authorization = "Bearer xAGLCeEDRZFmY90g2pqHg4FEbqU5JXAMTN2kl42aOa4" }
```

Expect: `result` = `DELETED_SUCCESSFULLY`.

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/v1/kv/read?path=secret/vkb0205@gmail.com/demo" -Headers @{ Authorization = "Bearer PASTE_TOKEN_HERE" }
```

Expect error: `NOT_FOUND`.

---

## 4) Feature 1.2 — path owner ACL

Wrong owner path → `PERMISSION_DENIED`:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/v1/kv/write" -Method POST -Headers @{ Authorization = "Bearer PASTE_TOKEN_HERE" } -ContentType "application/json" -Body '{"path":"secret/other@example.com/demo","data":"x"}'
```

---

## 5) Negative checks

No Bearer → `UNAUTHENTICATED`:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/v1/kv/read?path=secret/vkb0205@gmail.com/demo"
```

Restart server, do **not** unlock, reuse old token → `VAULT_LOCKED` or `UNAUTHENTICATED`:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/v1/kv/write" -Method POST -Headers @{ Authorization = "Bearer PASTE_TOKEN_HERE" } -ContentType "application/json" -Body '{"path":"secret/vkb0205@gmail.com/demo","data":"x"}'
```

---

## 6) Same flow with curl.exe

```powershell
curl.exe -s "http://127.0.0.1:8000/v1/status"
```

```powershell
curl.exe -s -X POST "http://127.0.0.1:8000/v1/init" -H "Content-Type: application/json" -d "{\"passphrase\":\"Str0ng!Passphrase123\"}"
```

```powershell
curl.exe -s -X POST "http://127.0.0.1:8000/v1/unlock" -H "Content-Type: application/json" -d "{\"passphrase\":\"Str0ng!Passphrase123\"}"
```

```powershell
curl.exe -s -X POST "http://127.0.0.1:8000/v1/auth/register" -H "Content-Type: application/json" -d "{\"email\":\"vkb0205@gmail.com\",\"passphrase\":\"Vukh@cb!nh0205@\",\"confirmation\":\"Vukh@cb!nh0205@\"}"
```

```powershell
curl.exe -s -X POST "http://127.0.0.1:8000/v1/auth/login" -H "Content-Type: application/json" -d "{\"email\":\"vkb0205@gmail.com\",\"passphrase\":\"Vukh@cb!nh0205@\"}"
```

```powershell
curl.exe -s "http://127.0.0.1:8000/v1/auth/session" -H "Authorization: Bearer PASTE_TOKEN_HERE"
```

```powershell
curl.exe -s -X POST "http://127.0.0.1:8000/v1/kv/write" -H "Authorization: Bearer PASTE_TOKEN_HERE" -H "Content-Type: application/json" -d "{\"path\":\"secret/vkb0205@gmail.com/demo\",\"data\":\"my-secret\"}"
```

```powershell
curl.exe -s "http://127.0.0.1:8000/v1/kv/read?path=secret/vkb0205@gmail.com/demo" -H "Authorization: Bearer PASTE_TOKEN_HERE"
```

```powershell
curl.exe -s -X DELETE "http://127.0.0.1:8000/v1/kv/delete?path=secret/vkb0205@gmail.com/demo" -H "Authorization: Bearer PASTE_TOKEN_HERE"
```

---

## Route cheat sheet

| Method | Path | Body / header |
|--------|------|----------------|
| GET | `/v1/status` | — |
| POST | `/v1/init` | `{"passphrase":"..."}` |
| POST | `/v1/unlock` | `{"passphrase":"..."}` — not GET |
| POST | `/v1/auth/register` | `{"email","passphrase","confirmation"}` |
| POST | `/v1/auth/login` | `{"email","passphrase"}` → token |
| GET | `/v1/auth/session` | `Authorization: Bearer ...` |
| POST | `/v1/kv/write` | Bearer + `{"path","data"}` |
| GET | `/v1/kv/read?path=...` | Bearer |
| DELETE | `/v1/kv/delete?path=...` | Bearer |

`Invoke-RestMethod` throws on HTTP 4xx. To see `{"code":"..."}`:

```powershell
try {
  Invoke-RestMethod "http://127.0.0.1:8000/v1/unlock" -Method POST -ContentType "application/json" -Body '{"passphrase":"wrong"}'
} catch {
  $_.ErrorDetails.Message
}
```

---

## CLI interactive (no HTTP)

```powershell
python main.py
```

Menu: `2` init → `3` unlock → `4` register → `5` login → `6` kv write → `7` kv read → `8` kv delete.
