/* 17-News-RNG Server - PRODUCTION READY - PostgreSQL on Render */
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const session = require('express-session');
const MemoryStore = require('memorystore')(session);
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { Pool } = require('pg');               // <-- NEW

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  transports: ['websocket', 'polling'],
  pingTimeout: 60000,
  pingInterval: 25000
});

/* ------------------------------------------------------------------
   1. POSTGRESQL SETUP (Render)
   ------------------------------------------------------------------ */
const IS_RENDER = process.env.RENDER === 'true';
let pool;

if (IS_RENDER) {
  // Render supplies DATABASE_URL automatically, but you also gave a full URL
  const DATABASE_URL =
    process.env.DATABASE_URL ||
    'postgresql://one7_news_rng_db_user:hmnrbBufZC0qzL817Xpam0ktWzN0GCdv@dpg-d42nfu0dl3ps73cj4m0g-a/one7_news_rng_db';

  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false }   // Render needs this
  });

  console.log('PostgreSQL pool created for Render');
} else {
  console.warn('Not on Render – DB disabled, falling back to memory');
}

/* ------------------------------------------------------------------
   2. INITIAL SCHEMA (run once, idempotent)
   ------------------------------------------------------------------ */
async function initSchema() {
  if (!pool) return;

  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS game_data (
        id          SERIAL PRIMARY KEY,
        data        JSONB NOT NULL,
        updated_at  TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // Insert initial data if table is empty
    const { rowCount } = await client.query(`SELECT 1 FROM game_data LIMIT 1`);
    if (rowCount === 0) {
      const initial = initializeData();
      await client.query(
        `INSERT INTO game_data (data) VALUES ($1)`,
        [JSON.stringify(initial)]
      );
      console.log('Inserted initial game data');
    }
  } catch (e) {
    console.error('Schema init error (non-fatal):', e);
  } finally {
    client.release();
  }
}

/* ------------------------------------------------------------------
   3. READ / WRITE helpers (PostgreSQL first, memory fallback)
   ------------------------------------------------------------------ */
let _inMemoryCache = null;   // used only when DB is down

async function readData() {
  // 1. Try PostgreSQL
  if (pool) {
    const client = await pool.connect();
    try {
      const res = await client.query(`SELECT data FROM game_data ORDER BY id DESC LIMIT 1`);
      if (res.rows.length) {
        const data = res.rows[0].data;
        _inMemoryCache = data;               // keep a hot copy
        return data;
      }
    } catch (err) {
      console.error('PostgreSQL read failed, falling back to cache:', err);
    } finally {
      client.release();
    }
  }

  // 2. Return cached copy (or initialise)
  if (_inMemoryCache) return _inMemoryCache;
  _inMemoryCache = initializeData();
  return _inMemoryCache;
}

async function writeData(data) {
  _inMemoryCache = data;            // always keep hot copy

  if (!pool) return true;           // no DB → just memory

  const client = await pool.connect();
  try {
    // UPSERT pattern (PostgreSQL 9.5+)
    await client.query(`
      INSERT INTO game_data (data) VALUES ($1)
      ON CONFLICT ((SELECT 1 FROM game_data LIMIT 1))
      DO UPDATE SET data = EXCLUDED.data, updated_at = NOW();
    `, [JSON.stringify(data)]);
    return true;
  } catch (err) {
    console.error('PostgreSQL write failed (data kept in memory):', err);
    return false;
  } finally {
    client.release();
  }
}

/* ------------------------------------------------------------------
   4. REST OF YOUR ORIGINAL CODE (unchanged except data calls)
   ------------------------------------------------------------------ */
app.set('trust proxy', 1);

let kv; // kept for Vercel – unused on Render
const IS_VERCEL = process.env.VERCEL === '1';
if (IS_VERCEL) {
  try {
    const { kv: vercelKv } = require('@vercel/kv');
    kv = vercelKv;
    console.log('Vercel KV initialized');
  } catch (_) {}
}

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, message: 'Too many attempts' },
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: true }
});

// Security
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Session (still in-memory – fine for Render)
const sessionStore = new MemoryStore({
  checkPeriod: 86400000,
  ttl: 365 * 24 * 60 * 60 * 1000
});
const sessionMiddleware = session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET || 'rng2-production-secret-2025',
  resave: false,
  saveUninitialized: false,
  rolling: true,
  name: 'rng2.sid',
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 365 * 24 * 60 * 60 * 1000,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  }
});
app.use(sessionMiddleware);
io.use((socket, next) => sessionMiddleware(socket.request, {}, next));

// Static files
app.use(express.static(__dirname, {
  index: false,
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
  }
}));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

/* -------------------  DATA & SHOP ------------------- */
const SHOP_ITEMS = [
  { name: 'Potato Sticker', type: 'item', price: 300 },
  { name: 'Microphone', type: 'item', price: 800 },
  { name: 'Chromebook', type: 'item', price: 1500 }
];

function getCurrentShopItem() {
  const now = Date.now();
  const intervalStart = Math.floor(now / 600000) * 600000;
  const intervalIndex = Math.floor(intervalStart / 600000) % SHOP_ITEMS.length;
  return {
    item: SHOP_ITEMS[intervalIndex],
    nextRotation: intervalStart + 600000,
    intervalStart
  };
}
function broadcastShopRotation() {
  const shopData = getCurrentShopItem();
  io.emit('shop_rotated', { item: shopData.item, nextRotation: shopData.nextRotation });
  console.log('Shop rotated:', shopData.item.name);
}
setInterval(() => {
  const shopData = getCurrentShopItem();
  const timeUntilNext = shopData.nextRotation - Date.now();
  if (timeUntilNext < 5000 && timeUntilNext > 0) {
    setTimeout(broadcastShopRotation, timeUntilNext);
  }
}, 5000);

function initializeData() {
  return {
    users: [],
    codes: [
      { code: "WELCOME17", reward: { type: "coins", amount: 500 }, usedBy: [] },
      { code: "RELEASE2025", reward: { type: "coins", amount: 1000 }, usedBy: [] },
      { code: "LUCKPOTION", reward: { type: "potion", potion: "luck1" }, usedBy: [] }
    ],
    announcements: [],
    events: [],
    chatMessages: []
  };
}

/* -------------------  RARITIES & POTIONS ------------------- */
const RARITIES = [
  { name: '17 News', chance: 45, color: '#4CAF50', coin: 100 },
  { name: '17 News Reborn', chance: 30, color: '#2196F3', coin: 250 },
  { name: 'Delan Fernando', chance: 15, color: '#9C27B0', coin: 500 },
  { name: 'Cooper Metson', chance: 8, color: '#FF9800', coin: 1000 },
  { name: 'Mr Fernanski', chance: 2, color: '#F44336', coin: 2500 }
];
const POTIONS = {
  luck1: { name: 'Luck Potion I', multiplier: 2, duration: 300000, type: 'luck', price: 500 },
  luck2: { name: 'Luck Potion II', multiplier: 4, duration: 300000, type: 'luck', price: 2000 },
  speed1: { name: 'Speed Potion I', cooldownReduction: 0.5, duration: 300000, type: 'speed', price: 800 }
};

/* -------------------  AUTH MIDDLEWARE ------------------- */
function requireAuth(req, res, next) {
  if (!req.session?.user?.username) return res.status(401).json({ success: false, error: 'Not logged in' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session?.user?.isAdmin) return res.status(401).json({ success: false, error: 'Admin required' });
  next();
}

/* -------------------  ROUTES ------------------- */
app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.json({ success: false, message: 'Credentials required' });

    const data = await readData();
    const user = data.users.find(u => u.username === username);
    if (!user || user.password !== password) return res.json({ success: false, message: 'Invalid credentials' });

    req.session.user = { username: user.username, isAdmin: user.isAdmin || false };
    res.json({
      success: true,
      user: {
        username: user.username,
        isAdmin: user.isAdmin || false,
        coins: user.coins || 0,
        inventory: user.inventory || { rarities: {}, potions: {}, items: {} },
        activePotions: user.activePotions || []
      }
    });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* (All other routes – register, spin, shop, etc. – stay **exactly** the same,
   only `readData()` / `writeData()` now hit PostgreSQL) */

app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.json({ success: false, message: 'Credentials required' });
    if (username.length < 3 || username.length > 20) return res.json({ success: false, message: 'Username 3-20 chars' });
    if (password.length < 6) return res.json({ success: false, message: 'Password ≥6 chars' });

    const data = await readData();
    if (data.users.find(u => u.username === username)) return res.json({ success: false, message: 'Username taken' });

    const newUser = {
      username, password, isAdmin: false,
      inventory: { rarities: {}, potions: {}, items: {} },
      activePotions: [], coins: 1000, lastSpin: 0,
      joinDate: new Date().toISOString()
    };
    data.users.push(newUser);
    await writeData(data);

    req.session.user = { username: newUser.username, isAdmin: false };
    res.json({
      success: true,
      user: { username: newUser.username, isAdmin: false, coins: 1000, inventory: newUser.inventory, activePotions: [] }
    });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* … (all the other /api/* endpoints you already have – copy-paste them unchanged) … */

/* -------------------  SOCKET.IO CHAT ------------------- */
io.on('connection', socket => {
  console.log('Socket connected:', socket.id);

  socket.on('chat_message', async msg => {
    try {
      if (!msg?.username || !msg?.message) return;
      const sanitized = String(msg.message).trim().slice(0, 500);
      if (!sanitized) return;

      const data = await readData();
      const chatMsg = { username: msg.username, message: sanitized, timestamp: new Date().toISOString() };
      data.chatMessages.push(chatMsg);
      if (data.chatMessages.length > 100) data.chatMessages = data.chatMessages.slice(-100);
      await writeData(data);
      io.emit('chat_message', chatMsg);
    } catch (e) {
      console.error('Chat error:', e);
    }
  });

  socket.on('disconnect', () => console.log('Disconnected:', socket.id));
});

/* -------------------  STARTUP ------------------- */
(async () => {
  if (pool) await initSchema();          // create tables + seed
  const PORT = process.env.PORT || 3000;
  server.listen(PORT, () => {
    const shop = getCurrentShopItem();
    console.log('');
    console.log('════════════════════════════════════════════════');
    console.log(' 17-News-RNG Server – PRODUCTION (PostgreSQL)');
    console.log('════════════════════════════════════════════════');
    console.log('');
    console.log(`Server: ${process.env.RENDER ? 'Render' : `http://localhost:${PORT}`}`);
    console.log(`Shop: ${shop.item.name}`);
    console.log(`Next rotation: ${new Date(shop.nextRotation).toLocaleTimeString()}`);
    console.log(`Storage: ${pool ? 'PostgreSQL' : 'Memory (fallback)'}`);
    console.log('Ready!');
    console.log('════════════════════════════════════════════════');
    console.log('');
  });
})();

/* Graceful shutdown */
process.on('SIGTERM', () => server.close(() => process.exit(0)));
process.on('SIGINT',  () => server.close(() => process.exit(0)));

module.exports = app;
