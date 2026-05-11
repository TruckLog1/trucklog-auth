const express = require('express');
const passport = require('passport');
const SteamStrategy = require('passport-steam').Strategy;
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 8080;
const BASE_URL = process.env.BASE_URL || 'https://trucklog-production.up.railway.app';
const STEAM_API_KEY = process.env.STEAM_API_KEY || '';

// In-memory store
const authTokens = new Map();

app.use(cors({ origin: '*' }));
app.use(express.json());

// One SteamStrategy per token - use state parameter
passport.use(new SteamStrategy({
  returnURL: `${BASE_URL}/auth/steam/return`,
  realm: BASE_URL,
  apiKey: STEAM_API_KEY,
  stateless: true
}, (identifier, profile, done) => done(null, profile)));

app.use(passport.initialize());

// Start login
app.get('/auth/steam', (req, res, next) => {
  const token = req.query.token;
  if (!token) return res.status(400).send('Token required');
  // Store pending token
  authTokens.set(token, { pending: true, timestamp: Date.now() });
  // Pass token through as part of return URL
  passport.use(new SteamStrategy({
    returnURL: `${BASE_URL}/auth/steam/return?token=${token}`,
    realm: BASE_URL,
    apiKey: STEAM_API_KEY,
    stateless: true
  }, (identifier, profile, done) => done(null, profile)));
  passport.authenticate('steam')(req, res, next);
});

// Steam callback
app.get('/auth/steam/return', (req, res, next) => {
  const token = req.query.token;
  passport.use(new SteamStrategy({
    returnURL: `${BASE_URL}/auth/steam/return?token=${token}`,
    realm: BASE_URL,
    apiKey: STEAM_API_KEY,
    stateless: true
  }, (identifier, profile, done) => done(null, profile)));
  passport.authenticate('steam', { stateless: true, failureRedirect: '/auth/failed' },
    (err, user) => {
      if (err || !user) return res.redirect('/auth/failed');
      const data = {
        steamId: user.id,
        name: user.displayName,
        avatar: user.photos?.[2]?.value || user.photos?.[0]?.value || '',
        timestamp: Date.now()
      };
      if (token) authTokens.set(token, data);
      res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>TruckLog</title></head><body style="background:#0a0d14;color:#e8e0d0;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;flex-direction:column;gap:16px;text-align:center"><div style="font-size:48px">✅</div><div style="font-size:22px;font-weight:bold;color:#f5a623">Autentificat cu succes!</div><div style="font-size:18px;color:#14d9a0">${data.name}</div><div style="font-size:13px;color:#3a4560;margin-top:8px">Poți închide această fereastră și reveni la TruckLog</div></body></html>`);
    })(req, res, next);
});

app.get('/auth/failed', (req, res) => {
  res.send('Autentificare eșuată.');
});

// Poll endpoint
app.get('/auth/check/:token', (req, res) => {
  const data = authTokens.get(req.params.token);
  if (data && !data.pending && data.steamId) {
    authTokens.delete(req.params.token);
    res.json({ success: true, steamId: data.steamId, name: data.name, avatar: data.avatar });
  } else {
    res.json({ success: false });
  }
});

// Generate token
app.get('/auth/token', (req, res) => {
  const token = crypto.randomBytes(16).toString('hex');
  res.json({ token });
});

app.get('/', (req, res) => res.send('TruckLog Auth Server running!'));

// Cleanup every 5 min
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of authTokens.entries()) {
    if (now - v.timestamp > 300000) authTokens.delete(k);
  }
}, 300000);

app.listen(PORT, () => console.log(`TruckLog Auth running on port ${PORT}`));
