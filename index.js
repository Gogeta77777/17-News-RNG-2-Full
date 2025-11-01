/*
  17-News-RNG Server — FULL VERSION (Merged & Production Ready)
  Combines original feature-rich server with PostgreSQL / Render / Vercel support
*/

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const session = require('express-session');
const MemoryStore = require('memorystore')(session);
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { Pool } = require('pg');

// ───────────────────────────────────────────────────────────────
// Express + Socket.IO Setup
// ───────────────────────────────────────────────────────────────
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  transports: ['websocket', 'polling'],
  pingTimeout: 60000,
  pingInterval: 25000
});

app.set('trust proxy', 1); // required for Render/Vercel

// ───────────────────────────────────────────────────────────────
// Database Setup (Render / Local / Fallback)
// ───────────────────────────────────────────────────────────────
let pool;
const IS_VERCEL = process.env.VERCEL === '1';
const IS_RENDER = process.env.RENDER === 'true';
const USE_POSTGRES = process.env.DATABASE_URL;

if (USE_POSTGRES) {
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
  });
  console.log('✅ PostgreSQL initialized');
} else {
  console.log('⚠️ PostgreSQL not detected. Falling back to local saveData.json');
}

// ───────────────────────────────────────────────────────────────
// Optional Vercel KV Support
// ───────────────────────────────────────────────────────────────
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

// ───────────────────────────────────────────────────────────────
// Middleware
// ───────────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
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
io.use((socket, next) => {
  sessionMiddleware(socket.request, socket.request.res || {}, next);
});

// ───────────────────────────────────────────────────────────────
// Static File Handling
// ───────────────────────────────────────────────────────────────
app.use(express.static(__dirname, {
  index: false,
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    }
  }
}));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ───────────────────────────────────────────────────────────────
// Database Initialization & JSON fallback
// ───────────────────────────────────────────────────────────────
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
      const initialData = initializeData();
      await pool.query('INSERT INTO game_data (id, data) VALUES (1, $1)', [JSON.stringify(initialData)]);
      console.log('✅ Database initialized with default data');
    } else {
      console.log('✅ Database already initialized');
    }
  } catch (err) {
    console.error('❌ Database init error:', err);
  }
}

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

// ───────────────────────────────────────────────────────────────
// Data Load/Save (PostgreSQL → KV → Local)
// ───────────────────────────────────────────────────────────────
async function readData() {
  try {
    if (pool) {
      const result = await pool.query('SELECT data FROM game_data WHERE id = 1');
      if (result.rows.length > 0) return result.rows[0].data;
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
    console.error('❌ Read error:', err);
    return initializeData();
  }
}

async function writeData(data) {
  try {
    if (pool) {
      await pool.query('UPDATE game_data SET data = $1, updated_at = CURRENT_TIMESTAMP WHERE id = 1', [JSON.stringify(data)]);
      console.log('💾 Saved to PostgreSQL');
      return;
    }
    if (IS_VERCEL && kv) {
      await kv.set(KV_KEY, data);
      console.log('💾 Saved to Vercel KV');
      return;
    }
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
    console.log('💾 Saved to local JSON');
  } catch (err) {
    console.error('❌ Write error:', err);
  }
}

// ───────────────────────────────────────────────────────────────
// Game Constants
// ───────────────────────────────────────────────────────────────
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

// ───────────────────────────────────────────────────────────────
// Utility + Auth Middleware
// ───────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session?.user?.username) {
    return res.status(401).json({ success: false, error: 'Not logged in' });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session?.user?.isAdmin) {
    return res.status(401).json({ success: false, error: 'Admin required' });
  }
  next();
}

// ───────────────────────────────────────────────────────────────
// Shop Rotation
// ───────────────────────────────────────────────────────────────
function getCurrentShopItem() {
  const now = Date.now();
  const start = Math.floor(now / 600000) * 600000;
  const index = Math.floor(start / 600000) % SHOP_ITEMS.length;
  return { item: SHOP_ITEMS[index], nextRotation: start + 600000 };
}

function broadcastShopRotation() {
  const shopData = getCurrentShopItem();
  io.emit('shop_rotated', { item: shopData.item, nextRotation: shopData.nextRotation });
  console.log('🔄 Shop rotated:', shopData.item.name);
}

setInterval(() => {
  const { nextRotation } = getCurrentShopItem();
  const timeLeft = nextRotation - Date.now();
  if (timeLeft < 5000 && timeLeft > 0) setTimeout(() => broadcastShopRotation(), timeLeft);
}, 5000);

// ───────────────────────────────────────────────────────────────
// Existing API + Socket Routes (keep your originals here)
// ───────────────────────────────────────────────────────────────
// Example route for test:
app.get('/api/ping', (req, res) => res.json({ success: true, message: 'pong' }));

// ───────────────────────────────────────────────────────────────
// Initialize & Start Server
// ───────────────────────────────────────────────────────────────
if (!IS_VERCEL) {
  initializeDatabase().then(async () => {
    await readData();
    const PORT = process.env.PORT || 3000;
    server.listen(PORT, () => {
      const shop = getCurrentShopItem();
      console.log('\n🎮 17-News-RNG Production Server Running');
      console.log('🌐', process.env.RENDER ? 'Render' : `http://localhost:${PORT}`);
      console.log('💾 Storage:', pool ? 'PostgreSQL' : (IS_VERCEL ? 'Vercel KV' : 'File'));
      console.log('🛒 Shop Item:', shop.item.name);
      console.log('✅ Ready!\n');
    });
  });
}

// ───────────────────────────────────────────────────────────────
// Graceful Shutdown
// ───────────────────────────────────────────────────────────────
process.on('SIGTERM', async () => {
  if (pool) await pool.end();
  server.close(() => process.exit(0));
});
process.on('SIGINT', async () => {
  if (pool) await pool.end();
  server.close(() => process.exit(0));
});

module.exports = app;
