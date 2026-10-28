# Panduan Video Demo (6–9 menit)

Persiapan: `npm run reset && npm start`, buka Postman/terminal, buka VS Code di folder proyek,
dan satu terminal untuk `npm run audit`. Target: ±8 menit.

| Waktu | Bagian | Yang ditunjukkan (kode) | Yang didemokan |
|---|---|---|---|
| 0:00–0:45 | Pembukaan & arsitektur | README (diagram), struktur folder | Jelaskan PEP (gateway), PE/PA (`policy.js`, `authRoutes.js`), resource (2 service + DB), audit log |
| 0:45–2:00 | **4.1 Access & refresh token** | `tokens.js` (`signUser`, RS256, `10m`); `authRoutes.js` `/login` (hash refresh token, `expires_at` 1 hari) | Login `dosen1` → tunjukkan token di jwt.io (`sub`, `role`, `exp`). Logout → refresh lagi → 401. Access token sesudah logout → 401 |
| 2:00–3:00 | **4.1 Token service** | `authRoutes.js` `/service`; `nilai/index.js` `getServiceToken` | `POST /auth/service` → token 5 menit `role: service`; client secret salah → 401 |
| 3:00–4:15 | **4.1 Gateway secret + verifikasi ulang** | `index.js` `forward` (`proxyReq.setHeader`); `serviceGuard.js` (secret → token → role) | `curl :3001/nilai` → 403; secret benar tanpa token → 401; secret benar + token palsu → 401 |
| 4:15–6:00 | **4.2 Kebijakan akses** | `policy.js` tabel `rules` (default deny, baca DB); `enforce()` di `index.js` | mhs1 lihat nilai sendiri ✔, minta NIM lain ✘; dosen1 kelas 1 ✔, kelas 2 ✘; mhs lihat transkrip orang lain ✘, admin ✔; token dosen ke `/transkrip/sinkron` ✘ |
| 6:00–7:00 | **4.3 Device & jam akses** | `enforce()` langkah device; `accessHours.js`; `config/access-hours.json` | Device user lain → 403. Ubah jam akses → `PUT /nilai/1` → 403 "di luar jam akses" (tanpa restart) |
| 7:00–8:00 | **Finalisasi & antar-service** | `nilai/index.js` `/finalisasi` + `sinkronTranskrip` lewat gateway | Finalisasi kelas 1 → transkrip mhs1 terisi; ubah nilai final → 403; finalisasi ulang → 409 |
| 8:00–8:45 | **4.4 Audit log** | `audit.js`; tabel `audit_log` | `npm run audit` → baris allow/deny lengkap dengan alasan; `npm test` → 56 lulus |
| 8:45–9:00 | Penutup | – | Ringkas prinsip zero trust yang diterapkan |

Tips: kembalikan `config/access-hours.json` ke `07:00–21:00` setelah demo jam akses.
