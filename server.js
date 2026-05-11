const express = require('express');
const session = require('express-session');
const passport = require('passport');
const SteamStrategy = require('passport-steam').Strategy;
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `https://trucklog-auth-production.up.railway.app`;
const STEAM_API_KEY = process.env.STEAM_API_KEY || '';
const SESSION_SECRET = process.env.SESSION_SECRET || 'trucklog-secret-key-2024';

app.use(cors({ origin: '*' }));
app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new SteamStrategy({
  returnURL: `${BASE_URL}/auth/steam/return`,
  realm: BASE_URL,
  apiKey: STEAM_API_KEY
}, (identifier, profile, done) => {
  return done(null, profile);
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// Start Steam login
app.get('/auth/steam', passport.authenticate('steam', { failureRedirect: '/' }));

// Steam callback
app.get('/auth/steam/return',
  passport.authenticate('steam', { failureRedirect: '/auth/failed' }),
  (req, res) => {
    const user = req.user;
    const steamId = user.id;
    const displayName = user.displayName;
    const avatar = user.photos?.[2]?.value || user.photos?.[0]?.value || '';
    // Redirect back to app with token
    res.redirect(`trucklog://auth?steamId=${steamId}&name=${encodeURIComponent(displayName)}&avatar=${encodeURIComponent(avatar)}`);
  }
);

app.get('/auth/failed', (req, res) => {
  res.redirect(`trucklog://auth?error=failed`);
});

// Verify endpoint - app calls this to verify a steamId
app.get('/verify/:steamId', async (req, res) => {
  const { steamId } = req.params;
  if (!steamId || steamId.length < 10) return res.json({ valid: false });
  try {
    const https = require('https');
    const url = `https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=${STEAM_API_KEY}&steamids=${steamId}`;
    https.get(url, (r) => {
      let data = '';
      r.on('data', d => data += d);
      r.on('end', () => {
        try {
          const json = JSON.parse(data);
          const player = json.response?.players?.[0];
          if (player) {
            res.json({ valid: true, steamId: player.steamid, name: player.personaname, avatar: player.avatarfull });
          } else {
            res.json({ valid: false });
          }
        } catch(e) { res.json({ valid: false }); }
      });
    }).on('error', () => res.json({ valid: false }));
  } catch(e) { res.json({ valid: false }); }
});

app.get('/', (req, res) => res.send('TruckLog Auth Server running!'));

app.listen(PORT, () => console.log(`TruckLog Auth Server running on port ${PORT}`));
