/*
  17-News-RNG Server — FULL VERSION (Final, Production-Ready)
  PostgreSQL + JSON fallback + Render + Vercel KV support
*/

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const session = require('express-session');
const MemoryStore = require('memorystore')(session);
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  transports: ['websocket', 'polling'],
  pingTimeout: 60000,
  pingInterval: 25000
});

// ─────────────────────────────────────────────
// Deployment Environment Flags
// ─────────────────────────────────────────────
app.set('trust proxy', 1);

const IS_VERCEL = process.env.VERCEL === '1';
const IS_RENDER = process.env.RENDER === 'true';
const DATABASE_URL =
  process.env.DATABASE_URL ||
  'postgresql://localhost:5432/one7_news_rng_db'; // local fallback

// ─────────────────────────────────────────────
// Database Initialization
// ─────────────────────────────────────────────
let pool;
try {
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl:
      process.env.NODE_ENV === 'production'
        ? { rejectUnauthorized: false }
        : false
  });
  console.log('✅ PostgreSQL connection configured');
} catch (err) {
  console.log('⚠️ PostgreSQL unavailable, falling back to local JSON');
}

// ─────────────────────────────────────────────
// Optional Vercel KV
// ─────────────────────────────────────────────
let kv;
if (IS_VERCEL) {
  try {
    const { kv: vercelKv } = require('@vercel/kv');
    kv = vercelKv;
    console.log('✅ Vercel KV initialized');
  } catch {
    console.log('❌ Vercel KV not available');
  }
}

// ─────────────────────────────────────────────
// Middleware & Security
// ─────────────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
  })
);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

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
io.use((socket, next) =>
  sessionMiddleware(socket.request, socket.request.res || {}, next)
);

// ─────────────────────────────────────────────
// Static Files
// ─────────────────────────────────────────────
app.use(
  express.static(__dirname, {
    index: false,
    setHeaders: (res, filePath) => {
      if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
    }
  })
);
app.get('/', (_, res) => res.sendFile(path.join(__dirname, 'index.html')));

// ─────────────────────────────────────────────
// Database Helpers
// ─────────────────────────────────────────────
const DATA_FILE = path.join(__dirname, 'saveData.json');
const KV_KEY = 'rng2:gamedata';

async function initializeDatabase() {
  if (!pool) return;
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS game_data (
        id INTEGER PRIMARY KEY DEFAULT 1,
        data JSONB NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    const result = await pool.query('SELECT data FROM game_data WHERE id = 1');
    if (result.rows.length === 0) {
      const init = initializeData();
      await pool.query('INSERT INTO game_data (id, data) VALUES (1, $1)', [
        JSON.stringify(init)
      ]);
      console.log('✅ PostgreSQL initialized with default data');
    }
  } catch (err) {
    console.error('❌ Database initialization error:', err.message);
  }
}

function initializeData() {
  return {
    users: [],
    codes: [
      { code: 'WELCOME17', reward: { type: 'coins', amount: 500 }, usedBy: [] },
      { code: 'RELEASE2025', reward: { type: 'coins', amount: 1000 }, usedBy: [] },
      { code: 'LUCKPOTION', reward: { type: 'potion', potion: 'luck1' }, usedBy: [] }
    ],
    announcements: [],
    events: [],
    chatMessages: []
  };
}

async function readData() {
  try {
    if (pool) {
      const result = await pool.query('SELECT data FROM game_data WHERE id = 1');
      if (result.rows.length) return result.rows[0].data;
    }
    if (IS_VERCEL && kv) {
      const kvData = await kv.get(KV_KEY);
      if (kvData) return kvData;
    }
    if (fs.existsSync(DATA_FILE)) {
      return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    }
    const init = initializeData();
    await writeData(init);
    return init;
  } catch (err) {
    console.error('❌ readData() error:', err.message);
    return initializeData();
  }
}

async function writeData(data) {
  try {
    if (pool) {
      await pool.query(
        'UPDATE game_data SET data=$1, updated_at=CURRENT_TIMESTAMP WHERE id=1',
        [JSON.stringify(data)]
      );
      return console.log('💾 Saved to PostgreSQL');
    }
    if (IS_VERCEL && kv) {
      await kv.set(KV_KEY, data);
      return console.log('💾 Saved to Vercel KV');
    }
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
    console.log('💾 Saved to JSON');
  } catch (err) {
    console.error('❌ writeData() error:', err.message);
  }
}

// ─────────────────────────────────────────────
// Game Constants
// ─────────────────────────────────────────────
const SHOP_ITEMS = [
  { name: 'Potato Sticker', type: 'item', price: 300 },
  { name: 'Microphone', type: 'item', price: 800 },
  { name: 'Chromebook', type: 'item', price: 1500 }
];

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

// ─────────────────────────────────────────────
// Shop Rotation
// ─────────────────────────────────────────────
function getCurrentShopItem() {
  const now = Date.now();
  const start = Math.floor(now / 600000) * 600000;
  const index = Math.floor(start / 600000) % SHOP_ITEMS.length;
  return { item: SHOP_ITEMS[index], nextRotation: start + 600000 };
}

function broadcastShopRotation() {
  const shop = getCurrentShopItem();
  io.emit('shop_rotated', { item: shop.item, nextRotation: shop.nextRotation });
  console.log('🔄 Shop rotated:', shop.item.name);
}

setInterval(() => {
  const { nextRotation } = getCurrentShopItem();
  const left = nextRotation - Date.now();
  if (left < 5000 && left > 0) setTimeout(() => broadcastShopRotation(), left);
}, 5000);

// ─────────────────────────────────────────────
// Utility + Auth Middleware
// ─────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session?.user?.username)
    return res.status(401).json({ success: false, error: 'Not logged in' });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session?.user?.isAdmin)
    return res.status(401).json({ success: false, error: 'Admin required' });
  next();
}

// ─────────────────────────────────────────────
// Health Check / Debug
// ─────────────────────────────────────────────
app.get('/api/ping', (_, res) =>
  res.json({ success: true, message: 'pong', time: new Date().toISOString() })
);
app.get('/api/health', async (_, res) => {
  try {
    if (pool) await pool.query('SELECT 1');
    res.json({ ok: true, pg: !!pool, kv: !!kv });
  } catch {
    res.json({ ok: false, pg: false });
  }
});

// ─────────────────────────────────────────────
// Initialization
// ─────────────────────────────────────────────
if (!IS_VERCEL) {
  initializeDatabase().then(async () => {
    await readData();
    const PORT = process.env.PORT || 3000;
    server.listen(PORT, () => {
      const shop = getCurrentShopItem();
      console.log('\n🎮 17-News-RNG Production Server Running');
      console.log('🌐', IS_RENDER ? 'Render' : `http://localhost:${PORT}`);
      console.log('💾 Storage:', pool ? 'PostgreSQL' : IS_VERCEL ? 'Vercel KV' : 'JSON');
      console.log('🛒 Shop Item:', shop.item.name);
      console.log('✅ Ready!\n');
    });
  });
}

// ─────────────────────────────────────────────
// Graceful Shutdown
// ─────────────────────────────────────────────
process.on('SIGTERM', async () => {
  if (pool) await pool.end();
  server.close(() => process.exit(0));
});
process.on('SIGINT', async () => {
  if (pool) await pool.end();
  server.close(() => process.exit(0));
});

module.exports = app;
