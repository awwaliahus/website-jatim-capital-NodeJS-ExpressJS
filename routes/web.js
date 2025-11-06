const express = require('express');
const router = express.Router();
const passport = require('passport');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const db = require('../config/db');
const app = express();
const multer = require('multer');
const path = require('path');
const fs = require('fs');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// routes
app.use('/', router);
// === Multer storage: simpan file di /uploads/document_upload/:id ===
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const folderId = (req.params && req.params.id) ? String(req.params.id) : 'misc';
    const dest = path.join(__dirname, '..', 'uploads', 'document_upload', folderId);
    fs.mkdirSync(dest, { recursive: true });
    cb(null, dest);
  },
  filename: (req, file, cb) => {
    const safe = (file.originalname || 'file')
      .replace(/[^\w.\-]+/g, '_')         // aman untuk filesystem
      .replace(/_+/g, '_')
      .slice(-180);                       // batasi panjang
    const unique = `${Date.now()}_${Math.round(Math.random()*1e6)}_${safe}`;
    cb(null, unique);
  }
});
const upload = multer({ storage });
router.use('/uploads', express.static(path.join(__dirname, '..', 'uploads')));


// === Middleware: Cek Login ===
function isLoggedIn(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) {
    return next();
  }
  return res.redirect('/login');
}

// === DEFAULT ROUTE ===
router.get('/', (req, res) => {
  if (req.isAuthenticated && req.isAuthenticated()) {
    res.redirect('/home');
  } else {
    res.redirect('/home');
  }
});

// === LOGIN ===
router.get('/login', (req, res) => {
  res.render('auth/login', { message: req.flash('error') });
});

router.post('/login',
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: true
  })
);

// === SIGNUP (LIMIT 4 USERS) ===
router.get('/signup', (req, res) => {
  res.render('auth/signup');
});

router.post('/signup', async (req, res) => {
  const { firstName, lastName, username, email, password, confirmPassword, kode_khusus } = req.body;

  if (kode_khusus !== '111916') {
    return res.send(`
      <script>
        alert("Kode khusus salah! Hubungi admin untuk kode yang benar.");
        window.location.href = "/signup";
      </script>
    `);
  }

  if (password !== confirmPassword) {
    return res.send(`
      <script>
        alert("Password tidak sama!");
        window.location.href = "/signup";
      </script>
    `);
  }

  try {
    const countQuery = 'SELECT COUNT(*) AS total FROM users';
    db.query(countQuery, async (err, result) => {
      if (err) return res.send('Database error.');
      const totalUsers = result[0].total;

      if (totalUsers >= 4) {
        return res.send(`
          <script>
            alert("Maksimal 4 akun yang bisa didaftarkan.");
            window.location.href = "/login";
          </script>
        `);
      }

      const checkQuery = 'SELECT * FROM users WHERE username = ? OR email = ?';
      db.query(checkQuery, [username, email], async (err, result) => {
        if (err) return res.send('Database error.');
        if (result.length > 0) {
          return res.send(`
            <script>
              alert("Username atau email sudah digunakan.");
              window.location.href = "/signup";
            </script>
          `);
        }

        const hashed = await bcrypt.hash(password, 10);
        const insertQuery = `
          INSERT INTO users (first_name, last_name, username, email, password, created_at)
          VALUES (?, ?, ?, ?, ?, NOW())
        `;
        db.query(insertQuery, [firstName, lastName, username, email, hashed], (err) => {
          if (err) return res.send('Gagal menyimpan data user.');
          res.send(`
            <script>
              alert("Akun berhasil dibuat! Silakan login.");
              window.location.href = "/login";
            </script>
          `);
        });
      });
    });
  } catch (err) {
    console.error(err);
    res.send('Internal Server Error');
  }
});

// === DASHBOARD ===
router.get('/dashboard', isLoggedIn, (req, res) => {
  res.render('dashboard', { user: req.user });
});

// === LOGOUT ===
router.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/login'));
});

// === DELETE ACCOUNT ===
router.post('/delete-account', isLoggedIn, (req, res) => {
  const userId = req.user.id;
  const deleteQuery = 'DELETE FROM users WHERE id = ?';

  db.query(deleteQuery, [userId], (err, result) => {
    if (err) {
      console.error('Gagal menghapus akun:', err);
      return res.send(`
        <script>
          alert("Terjadi kesalahan saat menghapus akun Anda.");
          window.location.href = "/dashboard";
        </script>
      `);
    }

    if (result.affectedRows === 0) {
      return res.send(`
        <script>
          alert("Akun tidak ditemukan.");
          window.location.href = "/dashboard";
        </script>
      `);
    }

    req.logout(() => {
      req.session.destroy((destroyErr) => {
        if (destroyErr) console.error('Session destroy error:', destroyErr);
        res.clearCookie('connect.sid');
        res.send(`
          <script>
            alert("Akun Anda telah dihapus.");
            window.location.href = "/login";
          </script>
        `);
      });
    });
  });
});

// === FORGOT PASSWORD ===
router.get('/forgot-password', (req, res) => {
  res.render('auth/forgotpassword', { successMessage: null });
});

router.post('/forgot-password', (req, res) => {
  const { email } = req.body;
  const token = crypto.randomBytes(20).toString('hex');
  const expiry = new Date(Date.now() + 3600000); // 1 jam

  const updateQuery = `
    UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?
  `;
  db.query(updateQuery, [token, expiry, email], (err) => {
    if (err) {
      console.error(err);
      return res.render('auth/forgotpassword', { successMessage: null });
    }

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'viorciapp@gmail.com',
        pass: 'bddj udcj mhlw fyfz'
      }
    });

    const resetLink = `http://localhost:3000/reset-password/${token}`;
    const mailOptions = {
      from: 'viorciapp@gmail.com',
      to: email,
      subject: 'Reset Password',
      html: `
        <p>Kami menerima permintaan reset password.</p>
        <p>Klik link berikut untuk reset:</p>
        <a href="${resetLink}">${resetLink}</a>
        <p>Link berlaku 1 jam.</p>
      `
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error(error);
        return res.render('auth/forgotpassword', { successMessage: null });
      }
      res.render('auth/forgotpassword', {
        successMessage: 'Jika email valid, link reset telah dikirim.'
      });
    });
  });
});

// === RESET PASSWORD ===
router.get('/reset-password/:token', (req, res) => {
  const { token } = req.params;
  const now = new Date();

  const query = `SELECT * FROM users WHERE reset_token = ? AND reset_token_expiry > ?`;
  db.query(query, [token, now], (err, result) => {
    if (err || result.length === 0) {
      return res.send('Link tidak valid atau kadaluarsa.');
    }
    res.render('auth/resetpassword', { token });
  });
});

router.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;
  const hashed = await bcrypt.hash(password, 10);

  const updateQuery = `
    UPDATE users 
    SET password = ?, reset_token = NULL, reset_token_expiry = NULL
    WHERE reset_token = ?
  `;
  db.query(updateQuery, [hashed, token], (err, result) => {
    if (err) {
      console.error('DB Error:', err);
      return res.send('Gagal mengubah password.');
    }

    if (result.affectedRows === 0) {
      return res.send('Token tidak cocok atau sudah kadaluarsa.');
    }

    res.send(`
      <script>
        alert('Password berhasil diubah. Silakan login.');
        window.location.href = '/login';
      </script>
    `);
  });
});

// === DOCUMENT CHECKLIST PAGE ===
router.get('/document-checklist', isLoggedIn, (req, res) => {
  res.render('documentchecklist', { user: req.user });
});

// === SIMPAN DATA KE DATABASE ===
router.post('/document-checklist', (req, res) => {
  console.log('REQ BODY:', req.body);

  const {
    jenis_pemohon,
    nama,
    nama_perusahaan,
    bidang_usaha,
    keterangan,
    akte_pendirian_ptcv,
    akta_perubahan_ptcv,
    npwp_ptcv,
    sk_menkumham_ptcv,
    siup_nib,
    tdp,
    ktp_pengurus_ptcv,
    npwp_pengurus_ptcv,
    ktp_suami_istri,
    npwp_pribadi,
    kartu_keluarga,
    akta_nikah,
    laporan_keuangan,
    invoice_pelanggan_kontrak_kerja,
    sertifikat_shm_shgb,
    imb,
    pbb_terakhir,
    summary_kredit,
    hasil_resume_penilaian_kjpp,
    buku_appraisal
  } = req.body;

  // Pastikan data checkbox bernilai 1 , 0, atau -1
  const toInt = (val) => {
    if (val === undefined || val === null) return -1;
    if (val === '1' || val === 1) return 1;
    if (val === '0' || val === 0) return 0;
    return -1;
  };


  const query = `
    INSERT INTO document_checklist 
    (jenis_pemohon, nama, nama_perusahaan, bidang_usaha, keterangan, created_at,
      akte_pendirian_ptcv, akta_perubahan_ptcv, npwp_ptcv, sk_menkumham_ptcv,
      siup_nib, tdp, ktp_pengurus_ptcv, npwp_pengurus_ptcv, ktp_suami_istri,
      npwp_pribadi, kartu_keluarga, akta_nikah, laporan_keuangan,
      invoice_pelanggan_kontrak_kerja, sertifikat_shm_shgb, imb, pbb_terakhir,
      summary_kredit, hasil_resume_penilaian_kjpp, buku_appraisal)
    VALUES (?, ?, ?, ?, ?, NOW(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  const values = [
    jenis_pemohon,
    nama,
    nama_perusahaan,
    bidang_usaha,
    keterangan || '',
    toInt(akte_pendirian_ptcv),
    toInt(akta_perubahan_ptcv),
    toInt(npwp_ptcv),
    toInt(sk_menkumham_ptcv),
    toInt(siup_nib),
    toInt(tdp),
    toInt(ktp_pengurus_ptcv),
    toInt(npwp_pengurus_ptcv),
    toInt(ktp_suami_istri),
    toInt(npwp_pribadi),
    toInt(kartu_keluarga),
    toInt(akta_nikah),
    toInt(laporan_keuangan),
    toInt(invoice_pelanggan_kontrak_kerja),
    toInt(sertifikat_shm_shgb),
    toInt(imb),
    toInt(pbb_terakhir),
    toInt(summary_kredit),
    toInt(hasil_resume_penilaian_kjpp),
    toInt(buku_appraisal)
  ];

  db.query(query, values, (err, result) => {
    if (err) {
      console.error('DB ERROR:', err);
      return res.status(500).send('Gagal menyimpan ke database.');
    }
    console.log('Data berhasil disimpan:', result.insertId);
    res.status(200).send('Data berhasil disimpan.');
  });
});

// === LOG DATA PAGE ===
router.get('/log-data', isLoggedIn, (req, res) => {
  const query = 'SELECT id, jenis_pemohon, nama, nama_perusahaan, bidang_usaha, keterangan FROM document_checklist';

  db.query(query, (err, results) => {
    if (err) {
      console.error('Error mengambil data dari database:', err);
      return res.status(500).send('Terjadi kesalahan pada server.');
    }

    // render halaman dengan data dan user
    res.render('logdata', {
      user: req.user,
      records: results
    });
  });
});

// === TAMPIL HALAMAN EDIT ===
router.get('/document-checklist/:id/edit', isLoggedIn, (req, res) => {
  const { id } = req.params;
  const sql = 'SELECT * FROM document_checklist WHERE id = ?';

  db.query(sql, [id], (err, rows) => {
    if (err) {
      console.error('Error ambil data untuk edit:', err);
      return res.status(500).send('Gagal memuat data.');
    }
    if (!rows || rows.length === 0) {
      return res.status(404).send('Data tidak ditemukan.');
    }

    res.render('documentchecklist_edit', {
      user: req.user,
      data: rows[0]
    });
  });
});

// === UPDATE DATA ===
router.post('/document-checklist/:id/update', isLoggedIn, (req, res) => {
  const { id } = req.params;
  const { jenis_pemohon, nama, nama_perusahaan, bidang_usaha } = req.body;

  // Ambil keterangan aman (array atau string)
  let keteranganRaw = req.body.keterangan;
  let keterangan = '';
  if (Array.isArray(keteranganRaw)) {
    // ambil elemen terakhir yang truthy
    const lastNonEmpty = [...keteranganRaw].reverse().find(v => v && String(v).trim() !== '');
    keterangan = (lastNonEmpty || '').trim();
  } else {
    keterangan = (keteranganRaw || '').trim();
  }

  const toInt = (val) => {
    if (val === undefined || val === null || val === '') return -1;
    const n = parseInt(val, 10);
    return [1,0,-1].includes(n) ? n : -1;
  };

  const pick = (body, base) => {
    const raw = (base in body) ? body[base] : body[`${base}_hidden`];
    return toInt(raw);
  };

  const values = {
    jenis_pemohon,
    nama,
    nama_perusahaan,
    bidang_usaha,
    keterangan,

    // Perusahaan
    akte_pendirian_ptcv:             pick(req.body, 'akte_pendirian_ptcv'),
    akta_perubahan_ptcv:             pick(req.body, 'akta_perubahan_ptcv'),
    npwp_ptcv:                       pick(req.body, 'npwp_ptcv'),
    sk_menkumham_ptcv:               pick(req.body, 'sk_menkumham_ptcv'),
    siup_nib:                        pick(req.body, 'siup_nib'),
    tdp:                             pick(req.body, 'tdp'),
    ktp_pengurus_ptcv:               pick(req.body, 'ktp_pengurus_ptcv'),
    npwp_pengurus_ptcv:              pick(req.body, 'npwp_pengurus_ptcv'),
    laporan_keuangan:                pick(req.body, 'laporan_keuangan'),
    invoice_pelanggan_kontrak_kerja: pick(req.body, 'invoice_pelanggan_kontrak_kerja'),
    sertifikat_shm_shgb:             pick(req.body, 'sertifikat_shm_shgb'),
    imb:                             pick(req.body, 'imb'),
    pbb_terakhir:                    pick(req.body, 'pbb_terakhir'),
    summary_kredit:                  pick(req.body, 'summary_kredit'),
    hasil_resume_penilaian_kjpp:     pick(req.body, 'hasil_resume_penilaian_kjpp'),
    buku_appraisal:                  pick(req.body, 'buku_appraisal'),

    // Perorangan
    ktp_suami_istri:                 pick(req.body, 'ktp_suami_istri'),
    npwp_pribadi:                    pick(req.body, 'npwp_pribadi'),
    kartu_keluarga:                  pick(req.body, 'kartu_keluarga'),
    akta_nikah:                      pick(req.body, 'akta_nikah'),
  };

  const sql = `
    UPDATE document_checklist
    SET jenis_pemohon=?,
        nama=?,
        nama_perusahaan=?,
        bidang_usaha=?,
        keterangan=?,
        akte_pendirian_ptcv=?, akta_perubahan_ptcv=?, npwp_ptcv=?, sk_menkumham_ptcv=?,
        siup_nib=?, tdp=?, ktp_pengurus_ptcv=?, npwp_pengurus_ptcv=?,
        laporan_keuangan=?, invoice_pelanggan_kontrak_kerja=?,
        sertifikat_shm_shgb=?, imb=?, pbb_terakhir=?,
        summary_kredit=?, hasil_resume_penilaian_kjpp=?, buku_appraisal=?,
        ktp_suami_istri=?, npwp_pribadi=?, kartu_keluarga=?, akta_nikah=?
    WHERE id=?
  `;

  const params = [
    values.jenis_pemohon, values.nama, values.nama_perusahaan, values.bidang_usaha, values.keterangan,
    values.akte_pendirian_ptcv, values.akta_perubahan_ptcv, values.npwp_ptcv, values.sk_menkumham_ptcv,
    values.siup_nib, values.tdp, values.ktp_pengurus_ptcv, values.npwp_pengurus_ptcv,
    values.laporan_keuangan, values.invoice_pelanggan_kontrak_kerja,
    values.sertifikat_shm_shgb, values.imb, values.pbb_terakhir,
    values.summary_kredit, values.hasil_resume_penilaian_kjpp, values.buku_appraisal,
    values.ktp_suami_istri, values.npwp_pribadi, values.kartu_keluarga, values.akta_nikah,
    id
  ];

  db.query(sql, params, (err) => {
    if (err) {
      console.error('Gagal update data:', err.sqlMessage);
      return res.send(`<script>alert("Gagal update data: ${err.sqlMessage}"); window.location.href="/log-data";</script>`);
    }
    res.send(`<script>alert("Data berhasil diperbarui!"); window.location.href="/log-data";</script>`);
  });
});

// === HAPUS DATA (CHECKLIST) ===
router.post('/delete/:id', (req, res) => {
  const id = req.params.id;
  const query = 'DELETE FROM document_checklist WHERE id = ?';

  db.query(query, [id], (err, result) => {
    if (err) {
      console.error('Error menghapus data:', err);
      return res.status(500).send('Gagal menghapus data.');
    }

    if (result.affectedRows === 0) {
      return res.status(404).send('Data tidak ditemukan.');
    }

    console.log(`Data dengan ID ${id} berhasil dihapus.`);
    res.redirect('/log-data');
  });
});

// === DOCUMENT UPLOAD PAGE ===
router.get('/document-upload', isLoggedIn, (req, res) => {
  const PAGE_SIZE = 16; // 4 x 4
  const pageParam = parseInt(req.query.page, 10);
  const page = Number.isFinite(pageParam) && pageParam > 0 ? pageParam : 1;
  const offset = (page - 1) * PAGE_SIZE;

  const countSql = 'SELECT COUNT(*) AS total FROM document_upload';
  db.query(countSql, (errCount, countRows) => {
    if (errCount) {
      console.error('Count error:', errCount);
      return res.status(500).send('Terjadi kesalahan pada server.');
    }
    const total = (countRows && countRows[0] && countRows[0].total) ? countRows[0].total : 0;
    const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

    const listSql = `
      SELECT id, nama_folder
      FROM document_upload
      ORDER BY id DESC
      LIMIT ? OFFSET ?
    `;
    db.query(listSql, [PAGE_SIZE, offset], (errList, folders) => {
      if (errList) {
        console.error('List error:', errList);
        return res.status(500).send('Terjadi kesalahan pada server.');
      }
      res.render('documentupload', {
        user: req.user,
        folders: folders || [],
        page,
        totalPages
      });
    });
  });
});

// === DOCUMENT UPLOAD: FILES VIEW (max 4 per page) ===
router.get('/document-upload/:id/files', isLoggedIn, (req, res) => {
  const folderId = parseInt(req.params.id, 10);
  if (!Number.isFinite(folderId)) return res.status(400).send('Folder tidak valid.');

  const sqlFolder = 'SELECT * FROM document_upload WHERE id = ? LIMIT 1';
  db.query(sqlFolder, [folderId], (errF, rowsF) => {
    if (errF) return res.status(500).send('Terjadi kesalahan pada server.');
    if (!rowsF || rowsF.length === 0) return res.status(404).send('Folder tidak ditemukan.');

    const row = rowsF[0];

    const baseUrl = `${req.protocol}://${req.get('host')}`; // ⬅️ penting untuk Office Viewer

    // Kumpulkan kolom file1, file2, ...
    const files = Object.keys(row)
      .filter(k => /^file\d+$/.test(k))
      .map(k => ({ col: k, url: row[k] }))
      .filter(f => f.url && String(f.url).trim() !== '');

    // “enrich” untuk EJS
    const enriched = files.map(f => {
      const name = f.url.split('/').pop();
      const ext = (name.split('.').pop() || '').toLowerCase();
      return {
        ...f,
        name,
        ext,
        absUrl: `${baseUrl}${f.url}` // ⬅️ absolute URL untuk Office Viewer
      };
    });

    // PAGINATION max 4 per page (sesuai permintaan sebelumnya)
    const FILES_PER_PAGE = 4;
    const pageParam = parseInt(req.query.page, 10);
    const page = Number.isFinite(pageParam) && pageParam > 0 ? pageParam : 1;
    const totalPages = Math.max(1, Math.ceil(enriched.length / FILES_PER_PAGE));
    const start = (page - 1) * FILES_PER_PAGE;
    const filesPage = enriched.slice(start, start + FILES_PER_PAGE);

    res.render('documentupload_files', {
      user: req.user,
      folder: { id: row.id, nama_folder: row.nama_folder },
      filesPage,
      filesCurrentPage: page,
      filesTotalPages: totalPages
    });
  });
});

const mammoth = require('mammoth');
const XLSX = require('xlsx');

// bantu: ambil path file dari DB berdasarkan id folder & nama kolom (file1, file2, ...)
function getFileRecord(folderId, col, cb) {
  const q = 'SELECT ?? AS f FROM document_upload WHERE id = ? LIMIT 1';
  db.query(q, [col, folderId], (err, rows) => {
    if (err) return cb(err);
    if (!rows || rows.length === 0 || !rows[0].f) return cb(new Error('NOT_FOUND'));
    const publicUrl = rows[0].f; // ex: /uploads/document_upload/123/xxx.docx
    // ubah public URL ke path file system
    const fsPath = path.join(__dirname, '..', publicUrl.replace(/^\//, '')); 
    cb(null, { publicUrl, fsPath });
  });
}

/**
 * Preview file sebagai HTML yang bisa di-embed dalam <iframe>.
 * DOCX -> HTML (mammoth)
 * XLSX -> HTML tabel (XLSX)
 * IMG/PDF -> simple wrapper <img>/<embed>
 */
router.get('/document-upload/:id/files/preview', isLoggedIn, (req, res) => {
  const folderId = parseInt(req.params.id, 10);
  const col = (req.query.col || '').trim(); // file1, file2, ...
  if (!Number.isFinite(folderId) || !/^file\d+$/.test(col)) {
    return res.status(400).send('Bad request');
  }

  getFileRecord(folderId, col, (err, meta) => {
    if (err) return res.status(404).send('File tidak ditemukan.');
    const ext = (meta.fsPath.split('.').pop() || '').toLowerCase();

    // HTML shell
    const shell = (body) => `
      <!doctype html><html><head>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width,initial-scale=1"/>
        <style>
          body{margin:0;padding:10px;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial}
          .wrap{box-sizing:border-box;height:100vh}
          img{max-width:100%;height:auto;display:block}
          .pdf{width:100%;height:100%}
          table{border-collapse:collapse;width:100%;font-size:14px}
          th,td{border:1px solid #e5e7eb;padding:6px 8px}
          thead th{background:#f9fafb}
          .note{color:#6b7280;font-size:12px;margin:8px 0}
          pre{white-space:pre-wrap}
        </style>
      </head><body><div class="wrap">${body}</div></body></html>`;

    // Gambar langsung <img>
    if (['png','jpg','jpeg','gif','webp','bmp','svg'].includes(ext)) {
      return res.send(shell(`<img src="${meta.publicUrl}" alt="preview"/>`));
    }

    // PDF <embed>
    if (ext === 'pdf') {
      return res.send(shell(`<embed class="pdf" src="${meta.publicUrl}#toolbar=0" type="application/pdf"/>`));
    }

    // DOCX -> mammoth
    if (ext === 'docx') {
      fs.readFile(meta.fsPath, (rErr, buffer) => {
        if (rErr) return res.status(500).send('Gagal membaca file.');
        mammoth.convertToHtml({ buffer })
          .then(result => {
            const html = result.value || '<p>(Kosong)</p>';
            res.send(shell(`<div class="docx">${html}</div>`));
          })
          .catch(() => res.status(500).send('Gagal render DOCX.'));
      });
      return;
    }

    // XLS/XLSX -> tabel HTML (sheet pertama)
    if (ext === 'xlsx' || ext === 'xls') {
      try {
        const wb = XLSX.readFile(meta.fsPath, { cellDates: true });
        const sheetName = wb.SheetNames[0];
        const sheet = wb.Sheets[sheetName];
        const html = XLSX.utils.sheet_to_html(sheet, { header: `<h3>${sheetName}</h3>` });
        // sheet_to_html sudah mengandung <table>, bungkus saja
        return res.send(shell(`<div class="xlsx">${html}</div>`));
      } catch (e) {
        return res.status(500).send('Gagal render Excel.');
      }
    }

    // PPT/PPTX & DOC lama (.doc) tidak didukung di sini
    return res.send(shell(`
      <p>Preview untuk .${ext} belum didukung.</p>
      <p class="note">Silakan <a href="${meta.publicUrl}" target="_blank">download</a> untuk melihat file.</p>
    `));
  });
});


// === RENAME FILE (ubah nama file di disk + update kolom DB) ===
router.post('/document-upload/:id/files/rename', isLoggedIn, (req, res) => {
  const folderId = parseInt(req.params.id, 10);
  const col = (req.body.col || '').trim();           // ex: file3
  const newBase = (req.body.new_name || '').trim();  // tanpa ekstensi

  if (!Number.isFinite(folderId) || !/^file\d+$/.test(col) || !newBase) {
    return res.status(400).send('Bad request.');
  }

  // Ambil path lama
  const sql = 'SELECT ?? AS fileurl FROM document_upload WHERE id=?';
  db.query(sql, [col, folderId], (err, rows) => {
    if (err || !rows || rows.length === 0) return res.status(400).send('Data tidak ditemukan.');
    const oldUrl = rows[0].fileurl;
    if (!oldUrl) return res.status(400).send('File kosong.');

    const uploadsRoot = path.join(__dirname, '..', 'uploads', 'document_upload', String(folderId));
    const oldFilename = oldUrl.split('/').pop();               // di URL
    const oldExt = oldFilename.includes('.') ? '.' + oldFilename.split('.').pop() : '';
    const newFilename = `${newBase.replace(/[^\w.\-]+/g,'_')}${oldExt}`;
    const oldPath = path.join(uploadsRoot, oldFilename);
    const newPath = path.join(uploadsRoot, newFilename);
    const newUrl = `/uploads/document_upload/${folderId}/${newFilename}`;

    try {
      if (fs.existsSync(oldPath)) fs.renameSync(oldPath, newPath);
    } catch (e) {
      console.error('fs.rename error:', e);
      return res.status(500).send('Gagal mengganti nama file.');
    }

    const upd = 'UPDATE document_upload SET ?? = ? WHERE id = ?';
    db.query(upd, [col, newUrl, folderId], (err2) => {
      if (err2) { console.error(err2); return res.status(500).send('DB error.'); }
      res.send('ok');
    });
  });
});

// === DELETE FILE (hapus dari disk + kosongkan kolom) ===
router.post('/document-upload/:id/files/delete', isLoggedIn, (req, res) => {
  const folderId = parseInt(req.params.id, 10);
  const col = (req.body.col || '').trim();
  if (!Number.isFinite(folderId) || !/^file\d+$/.test(col)) {
    return res.status(400).send('Bad request.');
  }

  const sql = 'SELECT ?? AS fileurl FROM document_upload WHERE id=?';
  db.query(sql, [col, folderId], (err, rows) => {
    if (err || !rows || rows.length === 0) return res.status(400).send('Data tidak ditemukan.');
    const fileUrl = rows[0].fileurl;
    if (fileUrl) {
      const filename = fileUrl.split('/').pop();
      const fpath = path.join(__dirname, '..', 'uploads', 'document_upload', String(folderId), filename);
      try { if (fs.existsSync(fpath)) fs.unlinkSync(fpath); } catch(e){ console.error('unlink err:', e); }
    }
    const upd = 'UPDATE document_upload SET ?? = NULL WHERE id = ?';
    db.query(upd, [col, folderId], (e2) => {
      if (e2) { console.error(e2); return res.status(500).send('DB error.'); }
      res.redirect(`/document-upload/${folderId}/files`);
    });
  });
});

// === DOWNLOAD FILE ===
router.get('/document-upload/:id/files/download', isLoggedIn, (req, res) => {
  const folderId = parseInt(req.params.id, 10);
  const col = (req.query.col || '').trim();
  if (!Number.isFinite(folderId) || !/^file\d+$/.test(col)) {
    return res.status(400).send('Bad request.');
  }
  const sql = 'SELECT ?? AS fileurl FROM document_upload WHERE id=?';
  db.query(sql, [col, folderId], (err, rows) => {
    if (err || !rows || rows.length === 0) return res.status(404).send('File tidak ditemukan.');
    const fileUrl = rows[0].fileurl;
    if (!fileUrl) return res.status(404).send('File kosong.');
    const filename = fileUrl.split('/').pop();
    const fpath = path.join(__dirname, '..', 'uploads', 'document_upload', String(folderId), filename);
    if (!fs.existsSync(fpath)) return res.status(404).send('Berkas hilang di server.');
    res.download(fpath, filename);
  });
});


// === DOCUMENT UPLOAD: unggah file ke folder ===
router.post(
  '/document-upload/:id/files/upload',
  isLoggedIn,
  upload.array('files', 32),  // batasi maksimal 32 file sekali unggah (ubah sesuai kebutuhan)
  (req, res) => {
    const folderId = parseInt(req.params.id, 10);
    if (!Number.isFinite(folderId)) {
      return res.status(400).send('Folder tidak valid.');
    }

    const files = Array.isArray(req.files) ? req.files : [];
    if (files.length === 0) {
      return res.send(`
        <script>
          alert("Tidak ada file yang dipilih.");
          window.location.href = "/document-upload/${folderId}/files";
        </script>
      `);
    }

    // Path publik yang bisa diakses klien
    const publicPaths = files.map(f => {
      return `/uploads/document_upload/${folderId}/${f.filename}`;
    });

    // 1) Ambil daftar kolom file*
    getFileColumns((errCols, cols) => {
      if (errCols) {
        console.error('Gagal ambil daftar kolom file*:', errCols);
        return res.status(500).send('Gagal mengambil metadata kolom.');
      }

      // 2) Ambil baris folder agar tahu mana kolom yang kosong
      const selRow = 'SELECT * FROM document_upload WHERE id = ? LIMIT 1';
      db.query(selRow, [folderId], (errRow, rows) => {
        if (errRow) {
          console.error('Gagal ambil baris folder:', errRow);
          return res.status(500).send('Gagal mengambil data folder.');
        }
        if (!rows || rows.length === 0) {
          return res.status(404).send('Folder tidak ditemukan.');
        }

        const row = rows[0];

        // Pastikan minimal ada file1.. kalau belum ada satupun kolom file*, siapkan array kosong
        const existingCount = cols.length;

        // Cari kolom kosong yang tersedia sekarang
        const emptyCols = [];
        for (let i = 0; i < cols.length; i++) {
          const c = cols[i];
          if (row[c] == null || row[c] === '') emptyCols.push(c);
        }

        // Hitung kebutuhan kolom tambahan
        const need = Math.max(0, publicPaths.length - emptyCols.length);

        const ensureColumnsThenUpdate = () => {
          // Refresh daftar kolom jika barusan menambah
          const afterCols = need > 0 ? (() => {
            const fresh = [];
            for (let i = 1; i <= existingCount + need; i++) fresh.push(`file${i}`);
            return fresh;
          })() : cols;

          // Rekalkulasi slot kosong (kalau ada tambahan)
          const afterEmpty = [...emptyCols];
          if (need > 0) {
            for (let k = existingCount + 1; k <= existingCount + need; k++) {
              afterEmpty.push(`file${k}`);
            }
          }

          // Ambil sebanyak jumlah file, isi ke kolom kosong berurutan
          const assignments = [];
          const params = [];
          for (let i = 0; i < publicPaths.length; i++) {
            const col = afterEmpty[i];
            if (!col) break;
            assignments.push('`' + col + '` = ?');
            params.push(publicPaths[i]);
          }

          if (assignments.length === 0) {
            // (semestinya tidak terjadi karena sudah tambah kolom)
            return res.send(`
              <script>
                alert("Tidak ada slot kolom file yang tersedia.");
                window.location.href="/document-upload/${folderId}/files";
              </script>
            `);
          }

          const upd = `UPDATE document_upload SET ${assignments.join(', ')} WHERE id = ?`;
          params.push(folderId);

          db.query(upd, params, (errUpd) => {
            if (errUpd) {
              console.error('Gagal update kolom file*:', errUpd);
              return res.status(500).send('Gagal menyimpan path file ke database.');
            }

            return res.send(`
              <script>
                alert("Berhasil mengunggah ${publicPaths.length} file.");
                window.location.href = "/document-upload/${folderId}/files";
              </script>
            `);
          });
        };

        if (need > 0) {
          // 3) Tambah kolom baru: file(existingCount+1) .. file(existingCount+need)
          addMoreFileColumns(existingCount, need, (errAlter) => {
            if (errAlter) {
              console.error('ALTER TABLE gagal:', errAlter);
              return res.status(500).send('Gagal menambah kolom file di database.');
            }
            ensureColumnsThenUpdate();
          });
        } else {
          ensureColumnsThenUpdate();
        }
      });
    });
  }
);

// === DOCUMENT UPLOAD: DELETE FOLDER (dipanggil dari kebab menu) ===
router.post('/document-upload/:id/delete', isLoggedIn, (req, res) => {
  const folderId = parseInt(req.params.id, 10);
  if (!Number.isFinite(folderId)) return res.status(400).send('ID folder tidak valid.');

  // Hapus folder. Jika ada tabel relasi file-to-folder, pastikan dihapus/ON DELETE CASCADE
  const del = 'DELETE FROM document_upload WHERE id = ?';
  db.query(del, [folderId], (err, result) => {
    if (err) {
      console.error('Gagal menghapus folder:', err);
      return res.status(500).send('DB error saat menghapus folder.');
    }
    if (result.affectedRows === 0) {
      return res.status(404).send('Folder tidak ditemukan.');
    }
    return res.status(200).send('OK');
  });
});

// === CREATE NEW FOLDER (Document Upload) ===
router.post('/document-upload/new-folder', isLoggedIn, (req, res) => {
  const namaFolder = (req.body.folder_name || '').trim();

  if (!namaFolder) {
    return res.send(`
      <script>
        alert("Nama folder tidak boleh kosong.");
        window.location.href = "/document-upload";
      </script>
    `);
  }

  const sql = 'INSERT INTO document_upload (nama_folder) VALUES (?)';
  db.query(sql, [namaFolder], (err, result) => {
    if (err) {
      console.error('Gagal menyimpan folder:', err);
      return res.send(`
        <script>
          alert("Gagal menyimpan folder.");
          window.location.href = "/document-upload";
        </script>
      `);
    }

    // sukses
    return res.send(`
      <script>
        alert("Folder berhasil dibuat.");
        window.location.href = "/document-upload";
      </script>
    `);
  });
});

// Ambil daftar kolom bertema file1, file2, ...
function getFileColumns(cb) {
  const sql = `
    SELECT COLUMN_NAME
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'document_upload'
      AND COLUMN_NAME REGEXP '^file[0-9]+$'
    ORDER BY CAST(SUBSTRING(COLUMN_NAME, 5) AS UNSIGNED)
  `;
  db.query(sql, (err, rows) => {
    if (err) return cb(err);
    const cols = rows.map(r => r.COLUMN_NAME);
    cb(null, cols);
  });
}

// Tambah N kolom file bertipe VARCHAR(255) NULL (fileK berikutnya)
function addMoreFileColumns(startIndexExclusive, countToAdd, cb) {
  if (countToAdd <= 0) return cb(null);

  const parts = [];
  for (let i = 1; i <= countToAdd; i++) {
    const k = startIndexExclusive + i;
    parts.push(`ADD COLUMN \`file${k}\` VARCHAR(255) NULL`);
  }
  const alter = `ALTER TABLE document_upload ${parts.join(', ')}`;
  db.query(alter, cb);
}

// === PIPELINE PAGE ===
router.get('/pipeline', isLoggedIn, (req, res) => {
  res.render('pipeline', { user: req.user });
});

// === HOME PAGE ===
router.get('/home', (req, res) => {
  res.render('home');
});

module.exports = router;