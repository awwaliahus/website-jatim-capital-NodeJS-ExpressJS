const express = require('express');
const router = express.Router();
const passport = require('passport');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const db = require('../config/db');
const app = express();

app.use(express.json()); // penting agar req.body terbaca!
app.use(express.urlencoded({ extended: true }));

// routes
app.use('/', router);


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
    res.redirect('/dashboard');
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

  // Pastikan data checkbox bernilai 1 atau 0
  const toBool = (val) => (val ? 1 : 0);

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
    toBool(akte_pendirian_ptcv),
    toBool(akta_perubahan_ptcv),
    toBool(npwp_ptcv),
    toBool(sk_menkumham_ptcv),
    toBool(siup_nib),
    toBool(tdp),
    toBool(ktp_pengurus_ptcv),
    toBool(npwp_pengurus_ptcv),
    toBool(ktp_suami_istri),
    toBool(npwp_pribadi),
    toBool(kartu_keluarga),
    toBool(akta_nikah),
    toBool(laporan_keuangan),
    toBool(invoice_pelanggan_kontrak_kerja),
    toBool(sertifikat_shm_shgb),
    toBool(imb),
    toBool(pbb_terakhir),
    toBool(summary_kredit),
    toBool(hasil_resume_penilaian_kjpp),
    toBool(buku_appraisal)
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
  const query = 'SELECT jenis_pemohon, nama, nama_perusahaan, bidang_usaha, keterangan FROM document_checklist';

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
router.get('/document-checklist/:id/edit', (req, res) => {
  const id = req.params.id;
  const query = 'SELECT * FROM document_checklist WHERE id = ?';
  db.query(query, [id], (err, results) => {
    if (err) throw err;
    if (results.length === 0) return res.send('Data tidak ditemukan');
    res.render('documentchecklist', { editData: results[0], user: req.user });
  });
});

// === HAPUS DATA ===
router.post('/delete/:id', (req, res) => {
  const id = req.params.id;
  const query = 'DELETE FROM document_checklist WHERE id = ?';
  db.query(query, [id], (err) => {
    if (err) throw err;
    res.redirect('/log-data');
  });
});


// === HOME PAGE ===
router.get('/home', (req, res) => {
  res.render('home');
});

module.exports = router;
