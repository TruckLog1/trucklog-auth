const express = require('express');
const session = require('express-session');
const passport = require('passport');
const SteamStrategy = require('passport-steam').Strategy;
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 8080;
const BASE_URL = process.env.BASE_URL || 'https://trucklog-production.up.railway.app';
const STEAM_API_KEY = process.env.STEAM_API_KEY || '';
const SESSION_SECRET = process.env.SESSION_SECRET || 'trucklog-secret-2024';

// Temporary store for auth tokens (in memory)
const authTokens = new Map();

app.use(cors({ origin: '*' }));
app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new SteamStrategy({
  returnURL: `${BASE_URL}/auth/steam/return`,
  realm: BASE_URL,
  apiKey: STEAM_API_KEY
}, (identifier, profile, done) => done(null, profile)));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// Start login - app sends a token, we store it
app.get('/auth/steam', (req, res, next) => {
  const token = req.query.token || crypto.randomBytes(16).toString('hex');
  req.session.authToken = token;
  req.session.save(() => {
    passport.authenticate('steam', { failureRedirect: '/' })(req, res, next);
  });
});

// Steam callback
app.get('/auth/steam/return',
  passport.authenticate('steam', { failureRedirect: '/auth/failed' }),
  (req, res) => {
    const user = req.user;
    const token = req.session.authToken;
    const data = {
      steamId: user.id,
      name: user.displayName,
      avatar: user.photos?.[2]?.value || user.photos?.[0]?.value || ''
    };
    if (token) authTokens.set(token, { ...data, timestamp: Date.now() });
    res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>TruckLog</title></head><body style="background:#0a0d14;color:#e8e0d0;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;flex-direction:column;gap:16px;text-align:center"><div style="font-size:36px">✅</div><div style="font-size:20px;font-weight:bold;color:#f5a623">Autentificat cu succes!</div><div style="font-size:16px;color:#14d9a0">${data.name}</div><div style="font-size:13px;color:#3a4560;margin-top:8px">Poți închide această fereastră și reveni la TruckLog</div></body></html>`);
  }
);

app.get('/auth/failed', (req, res) => {
  res.send('Autentificare eșuată. Închide această fereastră.');
});

// Polling endpoint - app checks if auth is done
app.get('/auth/check/:token', (req, res) => {
  const { token } = req.params;
  const data = authTokens.get(token);
  if (data) {
    authTokens.delete(token);
    res.json({ success: true, ...data });
  } else {
    res.json({ success: false });
  }
});

// Generate a token for new auth session
app.get('/auth/token', (req, res) => {
  const token = crypto.randomBytes(16).toString('hex');
  res.json({ token });
});

app.get('/', (req, res) => res.send('TruckLog Auth Server running!'));

// Cleanup old tokens every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of authTokens.entries()) {
    if (now - val.timestamp > 300000) authTokens.delete(key);
  }
}, 300000);

app.listen(PORT, () => console.log(`TruckLog Auth running on port ${PORT}`));
