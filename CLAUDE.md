Berikut adalah pembaruan dokumen **Product Requirements Document (PRD)** yang telah disesuaikan dengan arsitektur final, implementasi kode nyata, dan standar pedoman pengembangan aplikasi yang telah kita sepakati.

Dokumen ini sudah sangat siap untuk dipindahkan ke sistem manajemen proyek seperti Jira atau Trello untuk pelacakan tugas (WBS).

---

# 📄 Product Requirements Document (PRD): PhishGuard API (Backend)

## 1. Ringkasan Eksekutif

**Nama Proyek:** PhishGuard API
**Deskripsi:** Layanan *backend stateless* berbasis Flask yang berfungsi untuk mendeteksi tingkat keamanan sebuah URL. Sistem ini menggunakan strategi *Caching First* untuk mengoptimalkan penggunaan API eksternal dan mempercepat waktu respons.

## 2. Arsitektur & Lingkungan Teknologi (Tech Stack)

* **Bahasa Pemrograman:** Python 3.11
* **Framework:** Flask 3.x (menggunakan pola *Application Factory* dan *Blueprints*)
* **ORM & Driver Database:** Flask-SQLAlchemy & `psycopg2-binary` (atau `psycopg` v3)
* **Database:** PostgreSQL (Di-host di **Supabase**)
* **Integrasi Eksternal:** PhishTank API via modul `requests`
* **Environment & Deployment:** Docker Container, Gunicorn (Production Server), *Hosting* di **Render** / **Koyeb**.

## 3. Spesifikasi Koneksi & Skema Database

Sistem terhubung langsung ke layanan *cloud* Supabase menggunakan *Connection String* URI standar PostgreSQL. Koneksi ini bersifat privat dan diatur menggunakan *environment variable* `DATABASE_URL`.

**Tabel Penyimpanan: `scanned_urls**`
Tabel ini digunakan sebagai *cache layer* lokal.

| Kolom | Tipe Data | Deskripsi / Sifat |
| --- | --- | --- |
| `id` | UUID | Primary Key, di-generate otomatis menggunakan `uuid-ossp` |
| `url` | Text | Tautan yang dipindai (Di-index untuk kecepatan pencarian) |
| `status` | String(50) | Hasil pindai (contoh: `Aman`, `Phishing`) |
| `created_at` | TimestampTZ | Waktu pencatatan, menggunakan *timezone* UTC |

## 4. Kontrak Spesifikasi API (API Endpoints)

Semua respons dari API ini mengikuti standar JSON yang konsisten dengan *wrapper* `success` dan `data`/`message`.

### A. Endpoint Pemindaian Inti

* **Path:** `/api/v1/scan`
* **Metode:** `POST`
* **Fungsi:** Menerima URL, memvalidasinya melalui *database* lokal (Supabase) terlebih dahulu. Jika tidak ditemukan, akan memanggil PhishTank API, menyimpan hasilnya, dan mengembalikan status ke pengguna.
* **Request Body:**
```json
{
  "url": "http://contoh-link-mencurigakan.com"
}

```


* **Response Sukses (200 OK):**
```json
{
  "success": true,
  "data": {
    "url": "http://contoh-link-mencurigakan.com",
    "status": "Phishing",
    "source": "Local Database", 
    "checked_at": "2026-06-11T16:34:00Z"
  }
}

```



### B. Endpoint Statistik Platform

* **Path:** `/api/v1/stats`
* **Metode:** `GET`
* **Fungsi:** Mengambil agregasi data dari tabel `scanned_urls` untuk ditampilkan pada *dashboard* / *landing page frontend*.
* **Response Sukses (200 OK):**
```json
{
  "success": true,
  "data": {
    "total_scanned_urls": 1250,
    "total_phishing_detected": 142
  }
}

```



### C. Endpoint Health Check

* **Path:** `/api/health`
* **Metode:** `GET`
* **Fungsi:** Dimanfaatkan oleh platform *container* (Docker/Render) untuk memastikan *service* backend dan koneksi *database* berjalan dengan normal.
* **Response Sukses (200 OK):**
```json
{
  "database": "Connected",
  "status": "OK"
}

```



## 5. Work Breakdown Structure (WBS) & Sekuens Logis

Pengembangan proyek wajib mengikuti sekuens logis berikut, dengan aturan ketat bahwa **Sistem Aktivasi / Go-Live tidak boleh dilakukan sebelum seluruh proses pengujian komprehensif selesai dan tervalidasi**.

* **Tahap 1: Setup Lingkungan & Infrastruktur (Selesai)**
* Inisialisasi repositori Git dan *virtual environment*.
* Setup *Application Factory* di Flask.
* Pembuatan instans PostgreSQL di Supabase dan injeksi *environment variables*.


* **Tahap 2: Pengembangan Modul Utama (Selesai)**
* Implementasi struktur tabel menggunakan SQLAlchemy.
* Pembuatan *Service* PhishTank API.
* Pembuatan rute API (`/health`, `/v1/scan`, `/v1/stats`).


* **Tahap 3: Pengujian & Validasi Komprehensif (Prioritas Kritis)**
* Penyusunan skenario *Automated Testing* menggunakan `pytest`.
* Validasi logika pengecekan *cache* vs pemanggilan API eksternal.
* Uji respons sistem terhadap kegagalan API eksternal (*timeout handling*) dan validasi *error handling* (HTTP 400, 500, 502).


* **Tahap 4: Sistem Aktivasi & Deployment**
* Membangun *Docker Image* berdasarkan file `Dockerfile` final.
* *Deployment* versi *production* ke platform Render.
* Pemantauan stabilitas *endpoint* `/api/health` pasca-aktivasi.