/*
  17-News-RNG Server - PRODUCTION READY with PostgreSQL
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

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  transports: ['websocket', 'polling'],
  pingTimeout: 60000,
  pingInterval: 25000
});

// CRITICAL: Trust proxy for Render/Vercel/Railway deployments
app.set('trust proxy', 1);

// Database Setup
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
}

// Vercel KV Setup
let kv;
if (IS_VERCEL) {
  try {
    const { kv: vercelKv } = require('@vercel/kv');
    kv = vercelKv;
    console.log('✅ Vercel KV initialized');
  } catch (error) {
    console.error('❌ Vercel KV not available');
  }
}

// Rate limiting with proper proxy configuration
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, message: 'Too many attempts' },
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: true }
});

// Security
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Session configuration
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

// Socket.IO session sharing
io.use((socket, next) => {
  sessionMiddleware(socket.request, socket.request.res || {}, next);
});

// Static files
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

// DATABASE INITIALIZATION
async function initializeDatabase() {
  if (!pool) return;

  try {
    // Create tables if they don't exist
    await pool.query(`
      CREATE TABLE IF NOT EXISTS game_data (
        id INTEGER PRIMARY KEY DEFAULT 1,
        data JSONB NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Check if data exists
    const result = await pool.query('SELECT data FROM game_data WHERE id = 1');
    
    if (result.rows.length === 0) {
      // Insert initial data
      const initialData = initializeData();
      await pool.query(
        'INSERT INTO game_data (id, data) VALUES (1, $1)',
        [JSON.stringify(initialData)]
      );
      console.log('✅ Database initialized with default data');
    } else {
      console.log('✅ Database already initialized');
    }
  } catch (error) {
    console.error('❌ Database initialization error:', error);
  }
}

// DATA MANAGEMENT
const DATA_FILE = path.join(__dirname, 'saveData.json');
const KV_KEY = 'rng2:gamedata';

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
    intervalStart: intervalStart
  };
}

function broadcastShopRotation() {
  const shopData = getCurrentShopItem();
  io.emit('shop_rotated', {
    item: shopData.item,
    nextRotation: shopData.nextRotation
  });
  console.log('🔄 Shop rotated:', shopData.item.name);
}

// Shop rotation checker
setInterval(() => {
  const shopData = getCurrentShopItem();
  const timeUntilNext = shopData.nextRotation - Date.now();
  if (timeUntilNext < 5000 && timeUntilNext > 0) {
    setTimeout(() => broadcastShopRotation(), timeUntilNext);
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

// READ DATA - PostgreSQL Priority
async function readData() {
  try {
    // 1. Try PostgreSQL first
    if (pool) {
      const result = await pool.query('SELECT data FROM game_data WHERE id = 1');
      if (result.rows.length > 0) {
        return result.rows[0].data;
      }
    }

    // 2. Try Vercel KV
    if (IS_VERCEL && kv) {
      const data = await kv.get(KV_KEY);
      if (data) return data;
    }
    
    // 3. Fallback to local file
    if (fs.existsSync(DATA_FILE)) {
      const rawData = fs.readFileSync(DATA_FILE, 'utf8');
      return JSON.parse(rawData);
    }

    // 4. Return default data
    const initialData = initializeData();
    await writeData(initialData);
    return initialData;
  } catch (error) {
    console.error('❌ Read error:', error);
    return initializeData();
  }
}

// WRITE DATA - PostgreSQL Priority
async function writeData(data) {
  try {
    // 1. Write to PostgreSQL first
    if (pool) {
      await pool.query(
        'UPDATE game_data SET data = $1, updated_at = CURRENT_TIMESTAMP WHERE id = 1',
        [JSON.stringify(data)]
      );
      console.log('💾 Data saved to PostgreSQL');
      return true;
    }

    // 2. Write to Vercel KV
    if (IS_VERCEL && kv) {
      await kv.set(KV_KEY, data);
      console.log('💾 Data saved to Vercel KV');
      return true;
    }
    
    // 3. Fallback to local file
    const jsonData = JSON.stringify(data, null, 2);
    fs.writeFileSync(DATA_FILE, jsonData, 'utf8');
    console.log('💾 Data saved to file system');
    return true;
  } catch (error) {
    console.error('❌ Write error:', error);
    return false;
  }
}

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

function requireAuth(req, res, next) {
  if (!req.session || !req.session.user || !req.session.user.username) {
    return res.status(401).json({ success: false, error: 'Not logged in' });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.user || !req.session.user.isAdmin) {
    return res.status(401).json({ success: false, error: 'Admin required' });
  }
  next();
}

// ... (keep all your existing API routes exactly the same - they all use readData() and writeData())
// I'm not repeating them here to save space, but keep ALL routes from /api/login onwards

// Initialize
if (!IS_VERCEL) {
  initializeDatabase().then(async () => {
    await readData(); // Load initial data
    const PORT = process.env.PORT || 3000;
    server.listen(PORT, () => {
      const shopData = getCurrentShopItem();
      console.log('');
      console.log('🎮 ════════════════════════════════════════════════');
      console.log('🎮  17-News-RNG Server - PRODUCTION');
      console.log('🎮 ════════════════════════════════════════════════');
      console.log('');
      console.log('🌐 Server:', process.env.RENDER ? 'Render' : `http://localhost:${PORT}`);
      console.log('🛒 Shop:', shopData.item.name);
      console.log('⏰ Rotation:', new Date(shopData.nextRotation).toLocaleTimeString());
      console.log('💾 Storage:', pool ? 'PostgreSQL' : (IS_VERCEL ? 'Vercel KV' : 'File System'));
      console.log('🔒 Trust Proxy:', app.get('trust proxy') ? 'Enabled' : 'Disabled');
      console.log('');
      console.log('✅ Ready!');
      console.log('🎮 ════════════════════════════════════════════════');
      console.log('');
    });
  });
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  if (pool) await pool.end();
  server.close(() => process.exit(0));
});

process.on('SIGINT', async () => {
  if (pool) await pool.end();
  server.close(() => process.exit(0));
});

module.exports = app;
