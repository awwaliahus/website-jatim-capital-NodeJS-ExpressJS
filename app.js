const express = require('express');
const session = require('express-session');
const flash = require('connect-flash');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const path = require('path');
const db = require('./config/db');

const app = express();

// === Middleware Parsing Body ===
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // ← penting! agar req.body terbaca

// === Public & View Engine ===
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// === Session & Flash ===
app.use(session({
  secret: 'secret-key',
  resave: false,
  saveUninitialized: false
}));
app.use(flash());

// === Passport Setup ===
app.use(passport.initialize());
app.use(passport.session());

// === Local Strategy ===
passport.use(new LocalStrategy((usernameOrEmail, password, done) => {
  const query = 'SELECT * FROM users WHERE username = ? OR email = ?';
  db.query(query, [usernameOrEmail, usernameOrEmail], async (err, results) => {
    if (err) return done(err);
    if (results.length === 0) return done(null, false, { message: 'User not found' });

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    if (match) return done(null, user);
    else return done(null, false, { message: 'Incorrect password' });
  });
}));

// === Serialize / Deserialize ===
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  db.query('SELECT * FROM users WHERE id = ?', [id], (err, results) => {
    if (err) return done(err);
    done(null, results[0]);
  });
});

// === Routes ===
const routes = require('./routes/web');
app.use('/', routes);

// === Jalankan Server ===
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});