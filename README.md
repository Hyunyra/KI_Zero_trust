# Sistem Nilai — Zero Trust Security

Tugas Praktikum Individu · Keamanan Informasi (KP70065004) · Informatika Universitas Siliwangi

Sistem Nilai dengan **API Gateway sebagai Policy Enforcement Point (PEP)** yang terpisah dari service,
mengikuti arsitektur NIST SP 800-207. Prinsip yang diterapkan: *never trust, always verify*,
*least privilege*, dan *assume breach*.

**Stack:** Node.js 18+ · Express · http-proxy-middleware · jsonwebtoken (RS256) · bcryptjs · SQLite (better-sqlite3)

## Arsitektur

```
Client (Postman/curl)
   │  Authorization: Bearer <token>  +  X-Device-ID
   ▼
┌──────────────────────────────────────────────┐
│ API Gateway (PEP) :3000                      │──► Audit Log (tabel audit_log)
│  ├─ Policy Engine/Administrator (policy.js)  │
│  │    login, token, keputusan allow/deny     │◄── baca atribut dari Database
│  └─ /auth/*  /nilai/*  /kelas/*  /transkrip/*│
└───────┬───────────────────────┬──────────────┘
        │ + X-Gateway-Secret    │ + X-Gateway-Secret
        ▼                       ▼
  Service Nilai :3001     Service Transkrip :3002
  (verifikasi secret      (verifikasi secret
   + token ulang)          + token ulang)
        │   finalisasi → POST /transkrip/sinkron     ▲
        └──── lewat GATEWAY (token service) ─────────┘
                       Database SQLite bersama
```

| Komponen | Peran NIST SP 800-207 | File |
|---|---|---|
| API Gateway (3000) | PEP | `src/gateway/index.js` |
| Policy Engine / Administrator | PE / PA | `src/gateway/policy.js`, `authRoutes.js`, `tokens.js` |
| Service Nilai (3001) | Resource | `src/nilai/index.js` |
| Service Transkrip (3002) | Resource | `src/transkrip/index.js` |
| Database | Resource | `src/shared/db.js`, `scripts/setup.js` |
| Audit Log | Data source | `src/gateway/audit.js` (tabel `audit_log`) |

## Cara menjalankan

### A. Langsung (Node.js 18+)

```bash
npm install
npm run setup      # buat keypair RS256 + database + data awal
npm start          # gateway :3000, nilai :3001, transkrip :3002
```

Hanya gateway (`http://127.0.0.1:3000`) yang dipakai klien. Perintah lain:

```bash
npm run reset      # hapus database & seed ulang (hentikan server dulu)
npm run audit      # lihat audit log   (npm run audit -- deny  → hanya yang ditolak)
npm test           # uji otomatis 58 skenario (jalankan setelah `npm run reset` + `npm start`)
```

> Windows (Laragon/XAMPP): cukup Node.js 18+. SQLite tidak butuh server database.

### B. Docker Compose

```bash
docker compose up --build
```

Hanya port 3000 (gateway) yang dibuka ke host; service nilai & transkrip tidak punya `ports`.
Hanya gateway yang me-mount **private key**, service hanya mendapat **public key**.

## Frontend uji (tanpa Postman/Thunder Client)

Setelah `npm start`, buka **http://127.0.0.1:3000/** di browser. Halaman ini disajikan gateway dan
semua panggilannya tetap melewati PEP (login, refresh, logout, lihat/ubah nilai, finalisasi, transkrip).

- Klik chip akun (`admin`, `dosen1`, ...) untuk mengisi username, password, dan Device ID otomatis.
- Panel kanan menampilkan setiap request/response beserta status dan alasan penolakan.
- Bagian **Uji penolakan** berisi tombol serangan siap pakai (tanpa token, NIM orang lain, token palsu, dll.).
- Token hanya disimpan di memori halaman (tidak di localStorage); reload = harus login ulang.
- File: `public/index.html`. Hanya file statis yang dilayani tanpa token; semua endpoint API tetap default deny.

## Data awal (seed)

Password semua akun: **`password123`**

| Username | Role | NIM | Device ID terdaftar | Keterangan |
|---|---|---|---|---|
| `admin`  | admin | – | `DEV-ADMIN-01`  | |
| `dosen1` | dosen | – | `DEV-DOSEN1-01` | mengampu kelas 1 (Keamanan Informasi) |
| `dosen2` | dosen | – | `DEV-DOSEN2-01` | mengampu kelas 2 (Pemrograman Web) |
| `mhs1`   | mahasiswa | 2210001 | `DEV-MHS1-01` | |
| `mhs2`   | mahasiswa | 2210002 | `DEV-MHS2-01` | |
| `mhs3`   | mahasiswa | 2210003 | `DEV-MHS3-01` | |

Service Nilai memakai client `service-nilai` / `dev-service-nilai-secret` (bisa diganti lewat env
`SERVICE_CLIENT_ID`, `SERVICE_CLIENT_SECRET`). Gateway secret: env `GATEWAY_SECRET`.

## Contoh pemakaian (curl)

```bash
GW=http://127.0.0.1:3000

# 1. Login (kredensial + device terdaftar)
curl -s -X POST $GW/auth/login -H 'Content-Type: application/json' \
  -H 'X-Device-ID: DEV-DOSEN1-01' -d '{"username":"dosen1","password":"password123"}'
# → salin access_token ke $T dan refresh_token ke $R

# 2. Dosen melihat nilai kelasnya
curl -s $GW/nilai -H "Authorization: Bearer $T" -H 'X-Device-ID: DEV-DOSEN1-01'

# 3. Dosen mengubah nilai (kelas sendiri, belum final, dalam jam akses)
curl -s -X PUT $GW/nilai/1 -H "Authorization: Bearer $T" -H 'X-Device-ID: DEV-DOSEN1-01' \
  -H 'Content-Type: application/json' -d '{"nilai": 92}'

# 4. Finalisasi kelas → Service Nilai memanggil /transkrip/sinkron lewat gateway (token service)
curl -s -X POST $GW/kelas/1/finalisasi -H "Authorization: Bearer $T" -H 'X-Device-ID: DEV-DOSEN1-01'

# 5. Mahasiswa melihat transkrip sendiri (login mhs1 dulu → token $TM)
curl -s $GW/transkrip/2210001 -H "Authorization: Bearer $TM" -H 'X-Device-ID: DEV-MHS1-01'

# 6. Refresh & logout
curl -s -X POST $GW/auth/refresh -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$R\"}"
curl -s -X POST $GW/auth/logout  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$R\"}"

# 7. Serangan: akses service langsung (harus 403)
curl -i http://127.0.0.1:3001/nilai
```

### Mengubah jam akses saat demo

Edit `config/access-hours.json` — **dibaca ulang di setiap request, tanpa restart**:

```json
{ "start": "07:00", "end": "21:00", "timezone": "Asia/Jakarta" }
```

Untuk mendemokan penolakan, ubah rentang sehingga jam sekarang berada di luar rentang
(mis. `"start": "00:00", "end": "00:01"`), lalu coba `PUT /nilai/:id` → `403 ... di luar jam akses`.

## Pemetaan kebutuhan (bagian 4) → kode

| Kebutuhan | Penerapan | Lokasi |
|---|---|---|
| **4.1** Access token JWT 10 menit (`sub`, `role`), header Bearer | `signUser()` — RS256, `expiresIn: '10m'` | `src/gateway/tokens.js` |
| **4.1** Refresh token 1 hari, disimpan di DB, bisa dicabut; logout mencabut | Token acak, disimpan sebagai **hash SHA-256** di `refresh_tokens`; kolom `revoked` | `src/gateway/authRoutes.js` (`/login`, `/refresh`, `/logout`) |
| **4.1** Token service 5 menit, `role: service` | `POST /auth/service` (client ID + secret, bcrypt) | `authRoutes.js`, `tokens.js`, klien: `src/nilai/index.js` (`getServiceToken`) |
| **4.1** Gateway secret | Gateway menimpa `X-Gateway-Secret` di `proxyReq`; service menolak tanpa secret (perbandingan *timing-safe*) | `src/gateway/index.js` (`forward`), `src/shared/serviceGuard.js` |
| **4.1** Verifikasi ulang token di service | `guard()` memverifikasi tanda tangan RS256 + `exp` + issuer, walau secret benar | `src/shared/serviceGuard.js`, `src/shared/verify.js` |
| **4.2** Kebijakan akses (Tabel 3) | Tabel `rules` + atribut dari DB (kelas yang diampu, NIM milik sendiri, status final); **default deny** | `src/gateway/policy.js` |
| **4.3** Device terdaftar | `X-Device-ID` dicek terhadap tabel `devices` per user (login & setiap request) | `authRoutes.js`, `src/gateway/index.js` (`enforce`) |
| **4.3** Jam akses 07.00–21.00 (dapat dikonfigurasi) | `isWithinAccessHours()` membaca `config/access-hours.json` | `src/gateway/accessHours.js`, dipakai di `policy.js` |
| **4.4** Audit log | Setiap keputusan: waktu, subjek, endpoint, device, hasil, alasan | `src/gateway/audit.js`, `npm run audit` |

## Penerapan prinsip Zero Trust (nilai tambah di luar kebutuhan minimum)

- **Never trust, always verify** — setiap request diperiksa ulang: token, sesi, device, policy. Role di token dibandingkan dengan role di database.
- **Least privilege** — default deny; tiap role hanya mendapat endpoint & data yang diperlukan; token service hanya boleh `POST /transkrip/sinkron`.
- **Assume breach** — jika gateway secret bocor, service tetap menolak tanpa token valid. Service memegang **public key saja**, sehingga service yang diretas tidak bisa mencetak token. Role dan kepemilikan data diperiksa lagi di service.
- **Logout efektif seketika** — access token memuat `sid` (id sesi); gateway menolak token yang sesinya sudah dicabut, tanpa menunggu 10 menit.
- **Token terikat device** — refresh token menyimpan device saat login; jika `X-Device-ID` dikirim saat refresh/logout, harus cocok.
- **Anti-manipulasi path** — gateway memakai allowlist karakter path (menolak `../`, `//`, `%2e`), sehingga yang diperiksa policy sama dengan yang diteruskan.
- **Anti-enumerasi** — pesan login gagal seragam dan waktu respons disamakan (hash dummy).
- **Nilai draft disembunyikan** — mahasiswa hanya melihat nilai setelah kelas difinalisasi (sebelum itu `nilai: null`, disaring di Service Nilai). Dosen tetap melihat semua.
- **Finalisasi konsisten** — bila sinkron transkrip gagal, status final dibatalkan (rollback).

## Catatan & batasan

- Gateway secret, client secret, dan password seed adalah nilai **demo**; ganti lewat environment untuk penggunaan nyata.
- Komunikasi memakai HTTP biasa karena berjalan di satu komputer; di produksi gunakan TLS/mTLS antar-komponen.
- Belum ada rate limiting / penguncian akun terhadap brute force.
- Keputusan audit dicatat sebelum request diteruskan (yang dicatat adalah keputusan policy, bukan status HTTP akhir dari service).

## Struktur proyek

```
config/access-hours.json      jam akses (dapat diubah saat demo)
scripts/setup.js              keypair + skema DB + seed
scripts/start-all.js          menjalankan 3 komponen sekaligus
scripts/audit.js              menampilkan audit log
scripts/test-e2e.js           58 skenario uji otomatis
src/shared/                   config, db, verifikasi JWT, guard service
src/gateway/                  PEP: index, policy (PE), authRoutes (PA), tokens, audit, accessHours
src/nilai/                    Service Nilai
src/transkrip/                Service Transkrip
public/index.html             frontend uji (disajikan gateway di /)
docs/PANDUAN_VIDEO.md         skrip & rundown video demo 6–9 menit
Dockerfile, docker-compose.yml
```
