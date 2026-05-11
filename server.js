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
    res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>TruckLog Auth</title></head><body style="background:#0a0d14;color:#e8e0d0;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;flex-direction:column;gap:16px"><div style="font-size:24px">✅ Autentificat cu succes!</div><div style="font-size:16px;color:#14d9a0">${displayName}</div><div style="font-size:12px;color:#3a4560">Poți închide această fereastră și reveni la TruckLog</div><script>if(window.opener){window.opener.postMessage({type:'steam-auth',steamId:'${steamId}',name:'${displayName}',avatar:'${avatar}'},'*');}setTimeout(()=>window.close(),3000);</script></body></html>`);
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
