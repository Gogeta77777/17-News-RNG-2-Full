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
const { Pool } = require('pg'); // <-- NEW: PostgreSQL

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
let pool = null;

if (IS_RENDER) {
  const DATABASE_URL =
    process.env.DATABASE_URL ||
    'postgresql://one7_news_rng_db_user:hmnrbBufZC0qzL817Xpam0ktWzN0GCdv@dpg-d42nfu0dl3ps73cj4m0g-a/one7_news_rng_db';

  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
  });

  console.log('PostgreSQL pool initialized for Render');
} else {
  console.warn('Not running on Render – falling back to in-memory storage');
}

/* ------------------------------------------------------------------
   2. SCHEMA INITIALIZATION
   ------------------------------------------------------------------ */
async function initSchema() {
  if (!pool) return;

  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS game_data (
        id SERIAL PRIMARY KEY,
        data JSONB NOT NULL,
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    const { rowCount } = await client.query(`SELECT 1 FROM game_data LIMIT 1`);
    if (rowCount === 0) {
      const initial = initializeData();
      await client.query(`INSERT INTO game_data (data) VALUES ($1)`, [JSON.stringify(initial)]);
      console.log('Inserted initial game data into PostgreSQL');
    }
  } catch (err) {
    console.error('Schema init failed (non-fatal):', err.message);
  } finally {
    client.release();
  }
}

/* ------------------------------------------------------------------
   3. READ / WRITE DATA (PostgreSQL + Memory Fallback)
   ------------------------------------------------------------------ */
let _memoryCache = null;

async function readData() {
  if (pool) {
    const client = await pool.connect();
    try {
      const res = await client.query(`SELECT data FROM game_data ORDER BY id DESC LIMIT 1`);
      if (res.rows.length > 0) {
        const data = res.rows[0].data;
        _memoryCache = data;
        return data;
      }
    } catch (err) {
      console.error('PostgreSQL read failed:', err.message);
    } finally {
      client.release();
    }
  }

  if (_memoryCache) return _memoryCache;
  _memoryCache = initializeData();
  return _memoryCache;
}

async function writeData(data) {
  _memoryCache = data;

  if (!pool) return true;

  const client = await pool.connect();
  try {
    await client.query(`
      INSERT INTO game_data (data) VALUES ($1)
      ON CONFLICT ((SELECT 1 FROM game_data LIMIT 1))
      DO UPDATE SET data = EXCLUDED.data, updated_at = NOW();
    `, [JSON.stringify(data)]);
    return true;
  } catch (err) {
    console.error('PostgreSQL write failed (data kept in memory):', err.message);
    return false;
  } finally {
    client.release();
  }
}

/* ------------------------------------------------------------------
   4. CONFIGURATION & MIDDLEWARE
   ------------------------------------------------------------------ */
app.set('trust proxy', 1);

let kv;
const IS_VERCEL = process.env.VERCEL === '1';
if (IS_VERCEL) {
  try {
    const { kv: vercelKv } = require('@vercel/kv');
    kv = vercelKv;
    console.log('Vercel KV initialized');
  } catch (error) {
    console.error('Vercel KV not available');
  }
}

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, message: 'Too many attempts' },
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: true }
});

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
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
io.use((socket, next) => sessionMiddleware(socket.request, {}, next));

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

/* ------------------------------------------------------------------
   5. SHOP & ROTATION LOGIC
   ------------------------------------------------------------------ */
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
  io.emit('shop_rotated', { item: shopData.item, nextRotation: shopData.nextRotation });
  console.log('Shop rotated:', shopData.item.name);
}

setInterval(() => {
  const shopData = getCurrentShopItem();
  const timeUntilNext = shopData.nextRotation - Date.now();
  if (timeUntilNext < 5000 && timeUntilNext > 0) {
    setTimeout(() => broadcastShopRotation(), timeUntilNext);
  }
}, 5000);

/* ------------------------------------------------------------------
   6. INITIAL DATA
   ------------------------------------------------------------------ */
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

/* ------------------------------------------------------------------
   7. RARITIES & POTIONS
   ------------------------------------------------------------------ */
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

/* ------------------------------------------------------------------
   8. AUTH MIDDLEWARE
   ------------------------------------------------------------------ */
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

/* ------------------------------------------------------------------
   9. API ROUTES
   ------------------------------------------------------------------ */
app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.json({ success: false, message: 'Credentials required' });
    }
    const data = await readData();
    const user = data.users.find(u => u.username === username);
    if (!user || user.password !== password) {
      return res.json({ success: false, message: 'Invalid credentials' });
    }
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
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.json({ success: false, message: 'Credentials required' });
    }
    if (username.length < 3 || username.length > 20) {
      return res.json({ success: false, message: 'Username must be 3-20 characters' });
    }
    if (password.length < 6) {
      return res.json({ success: false, message: 'Password must be 6+ characters' });
    }
    const data = await readData();
    if (data.users.find(u => u.username === username)) {
      return res.json({ success: false, message: 'Username taken' });
    }
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
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/check-session', async (req, res) => {
  try {
    if (!req.session || !req.session.user) {
      return res.json({ success: false, loggedIn: false });
    }
    const data = await readData();
    const user = data.users.find(u => u.username === req.session.user.username);
    if (!user) {
      return res.json({ success: false, loggedIn: false });
    }
    res.json({
      success: true,
      loggedIn: true,
      user: {
        username: user.username,
        isAdmin: user.isAdmin || false,
        coins: user.coins || 0,
        inventory: user.inventory || { rarities: {}, potions: {}, items: {} },
        activePotions: user.activePotions || []
      }
    });
  } catch (error) {
    console.error('Check session error:', error);
    res.json({ success: false, loggedIn: false });
  }
});

app.post('/api/spin', requireAuth, async (req, res) => {
  try {
    const data = await readData();
    const user = data.users.find(u => u.username === req.session.user.username);
    if (!user) {
      return res.json({ success: false, error: 'User not found' });
    }
    const now = Date.now();
    let cooldown = 3000;
    const speedPotion = (user.activePotions || []).find(p => p.type === 'speed' && p.expires > now);
    if (speedPotion) cooldown *= 0.5;
    if (user.lastSpin && (now - user.lastSpin) < cooldown) {
      const remaining = Math.ceil((cooldown - (now - user.lastSpin)) / 1000);
      return res.json({ success: false, error: `Wait ${remaining}s` });
    }
    let luckMultiplier = 1;
    user.activePotions = (user.activePotions || []).filter(p => p.expires > now);
    user.activePotions.filter(p => p.type === 'luck').forEach(p => luckMultiplier *= p.multiplier);
    const adjustedRarities = RARITIES.map((r, idx) => idx >= RARITIES.length - 2 ? { ...r, chance: r.chance * luckMultiplier } : r);
    const total = adjustedRarities.reduce((s, r) => s + r.chance, 0);
    const roll = Math.random() * total;
    let cursor = 0;
    let picked = RARITIES[RARITIES.length - 1];
    for (const rarity of adjustedRarities) {
      cursor += rarity.chance;
      if (roll <= cursor) {
        picked = RARITIES.find(r => r.name === rarity.name);
        break;
      }
    }
    const rarityKey = picked.name.toLowerCase().replace(/\s+/g, '-');
    if (!user.inventory.rarities) user.inventory.rarities = {};
    if (!user.inventory.rarities[rarityKey]) {
      user.inventory.rarities[rarityKey] = { name: picked.name, count: 0, color: picked.color };
    }
    user.inventory.rarities[rarityKey].count += 1;
    user.coins = (user.coins || 0) + (picked.coin || 0);
    user.lastSpin = now;
    await writeData(data);
    res.json({
      success: true,
      item: picked.name,
      rarity: picked,
      coins: user.coins,
      awarded: picked.coin || 0
    });
  } catch (error) {
    console.error('Spin error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/use-potion', requireAuth, async (req, res) => {
  try {
    const { potionKey } = req.body;
    if (!potionKey || !POTIONS[potionKey]) {
      return res.json({ success: false, error: 'Invalid potion' });
    }
    const data = await readData();
    const user = data.users.find(u => u.username === req.session.user.username);
    if (!user) {
      return res.json({ success: false, error: 'User not found' });
    }
    if (!user.inventory.potions) user.inventory.potions = {};
    if (!user.inventory.potions[potionKey] || user.inventory.potions[potionKey] <= 0) {
      return res.json({ success: false, error: 'No potion available' });
    }
    const potion = POTIONS[potionKey];
    if ((user.activePotions || []).find(p => p.key === potionKey)) {
      return res.json({ success: false, error: 'Potion already active' });
    }
    user.inventory.potions[potionKey] -= 1;
    if (!user.activePotions) user.activePotions = [];
    user.activePotions.push({
      key: potionKey,
      name: potion.name,
      type: potion.type,
      multiplier: potion.multiplier || 1,
      cooldownReduction: potion.cooldownReduction || 0,
      expires: Date.now() + potion.duration
    });
    await writeData(data);
    res.json({ success: true, message: `${potion.name} activated!`, activePotions: user.activePotions });
  } catch (error) {
    console.error('Potion error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.get('/api/shop/current', requireAuth, (req, res) => {
  const shopData = getCurrentShopItem();
  res.json({
    success: true,
    item: shopData.item,
    nextRotation: shopData.nextRotation,
    timeRemaining: Math.max(0, shopData.nextRotation - Date.now())
  });
});

app.post('/api/shop/buy', requireAuth, async (req, res) => {
  try {
    const { itemName } = req.body;
    const shopData = getCurrentShopItem();
    if (itemName !== shopData.item.name) {
      return res.json({ success: false, error: 'Item not available' });
    }
    const data = await readData();
    const user = data.users.find(u => u.username === req.session.user.username);
    if (!user) {
      return res.json({ success: false, error: 'User not found' });
    }
    if ((user.coins || 0) < shopData.item.price) {
      return res.json({ success: false, error: 'Not enough coins' });
    }
    user.coins -= shopData.item.price;
    if (!user.inventory.items) user.inventory.items = {};
    const itemKey = shopData.item.name.toLowerCase().replace(/\s+/g, '-');
    if (!user.inventory.items[itemKey]) {
      user.inventory.items[itemKey] = { name: shopData.item.name, count: 0 };
    }
    user.inventory.items[itemKey].count += 1;
    await writeData(data);
    res.json({ success: true, coins: user.coins, inventory: user.inventory });
  } catch (error) {
    console.error('Shop error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/shop/buy-potion', requireAuth, async (req, res) => {
  try {
    const { potionKey } = req.body;
    if (!potionKey || !POTIONS[potionKey]) {
      return res.json({ success: false, error: 'Invalid potion' });
    }
    const price = POTIONS[potionKey].price;
    const data = await readData();
    const user = data.users.find(u => u.username === req.session.user.username);
    if (!user) {
      return res.json({ success: false, error: 'User not found' });
    }
    if ((user.coins || 0) < price) {
      return res.json({ success: false, error: 'Not enough coins' });
    }
    user.coins -= price;
    if (!user.inventory.potions) user.inventory.potions = {};
    if (!user.inventory.potions[potionKey]) {
      user.inventory.potions[potionKey] = 0;
    }
    user.inventory.potions[potionKey] += 1;
    await writeData(data);
    res.json({ success: true, coins: user.coins, inventory: user.inventory });
  } catch (error) {
    console.error('Potion shop error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/use-code', requireAuth, async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) {
      return res.json({ success: false, error: 'Code required' });
    }
    const data = await readData();
    const user = data.users.find(u => u.username === req.session.user.username);
    if (!user) {
      return res.json({ success: false, error: 'User not found' });
    }
    const codeData = data.codes.find(c => c.code === code);
    if (!codeData) {
      return res.json({ success: false, error: 'Invalid code' });
    }
    if (!Array.isArray(codeData.usedBy)) codeData.usedBy = [];
    if (codeData.usedBy.includes(user.username)) {
      return res.json({ success: false, error: 'Code already used' });
    }
    if (codeData.reward.type === 'coins') {
      user.coins = (user.coins || 0) + codeData.reward.amount;
    } else if (codeData.reward.type === 'potion') {
      const potionKey = codeData.reward.potion;
      if (!user.inventory.potions) user.inventory.potions = {};
      if (!user.inventory.potions[potionKey]) user.inventory.potions[potionKey] = 0;
      user.inventory.potions[potionKey] += 1;
    }
    codeData.usedBy.push(user.username);
    await writeData(data);
    res.json({ success: true, coins: user.coins, inventory: user.inventory });
  } catch (error) {
    console.error('Code error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.get('/api/data', requireAuth, async (req, res) => {
  try {
    const data = await readData();
    const user = data.users.find(u => u.username === req.session.user.username);
    if (!user) {
      return res.json({ success: false, error: 'User not found' });
    }
    const now = Date.now();
    if (user.activePotions) {
      user.activePotions = user.activePotions.filter(p => p.expires > now);
    }
    res.json({
      success: true,
      user: {
        username: user.username,
        isAdmin: user.isAdmin || false,
        coins: user.coins || 0,
        inventory: user.inventory || { rarities: {}, potions: {}, items: {} },
        activePotions: user.activePotions || []
      },
      announcements: data.announcements || [],
      events: data.events || [],
      chatMessages: (data.chatMessages || []).slice(-50)
    });
  } catch (error) {
    console.error('Data error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/announcement', requireAdmin, async (req, res) => {
  try {
    const { title, content } = req.body;
    if (!title || !content) {
      return res.json({ success: false, error: 'Title and content required' });
    }
    const data = await readData();
    const announcement = {
      id: Date.now(),
      title,
      content,
      date: new Date().toISOString(),
      author: req.session.user.username
    };
    data.announcements.push(announcement);
    await writeData(data);
    io.emit('new_announcement', announcement);
    res.json({ success: true, announcement });
  } catch (error) {
    console.error('Announcement error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/event', requireAdmin, async (req, res) => {
  try {
    const { name, description, startDate, endDate } = req.body;
    if (!name || !startDate || !endDate) {
      return res.json({ success: false, error: 'Required fields missing' });
    }
    const data = await readData();
    const event = {
      id: Date.now(),
      name,
      description: description || '',
      startDate,
      endDate,
      active: true
    };
    data.events.push(event);
    await writeData(data);
    io.emit('new_event', event);
    res.json({ success: true, event });
  } catch (error) {
    console.error('Event error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error('Logout error:', err);
    res.clearCookie('rng2.sid');
    res.json({ success: true });
  });
});

/* ------------------------------------------------------------------
   10. SOCKET.IO - CHAT
   ------------------------------------------------------------------ */
io.on('connection', (socket) => {
  console.log('Socket connected:', socket.id);

  socket.on('chat_message', async (msg) => {
    try {
      if (!msg || !msg.username || !msg.message) return;
      const sanitizedMessage = String(msg.message).trim().slice(0, 500);
      if (!sanitizedMessage) return;

      const data = await readData();
      const chatMsg = {
        username: msg.username,
        message: sanitizedMessage,
        timestamp: new Date().toISOString()
      };
      data.chatMessages.push(chatMsg);
      if (data.chatMessages.length > 100) {
        data.chatMessages = data.chatMessages.slice(-100);
      }
      await writeData(data);
      io.emit('chat_message', chatMsg);
    } catch (error) {
      console.error('Chat error:', error);
    }
  });

  socket.on('disconnect', () => {
    console.log('Disconnected:', socket.id);
  });
});

/* ------------------------------------------------------------------
   11. ERROR HANDLING
   ------------------------------------------------------------------ */
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ success: false, error: 'Internal server error' });
});

/* ------------------------------------------------------------------
   12. START SERVER
   ------------------------------------------------------------------ */
(async () => {
  if (pool) await initSchema();

  const PORT = process.env.PORT || 3000;
  server.listen(PORT, () => {
    const shopData = getCurrentShopItem();
    console.log('');
    console.log('════════════════════════════════════════════════════════════');
    console.log(' 17-News-RNG Server - PRODUCTION (PostgreSQL on Render)');
    console.log('════════════════════════════════════════════════════════════');
    console.log('');
    console.log(`Server: ${process.env.RENDER ? 'Render' : `http://localhost:${PORT}`}`);
    console.log(`Shop: ${shopData.item.name}`);
    console.log(`Rotation: ${new Date(shopData.nextRotation).toLocaleTimeString()}`);
    console.log(`Storage: ${pool ? 'PostgreSQL' : 'Memory (fallback)'}`);
    console.log('Trust Proxy: Enabled');
    console.log('');
    console.log.log('READY!');
    console.log('════════════════════════════════════════════════════════════');
    console.log('');
  });
})();

/* Graceful shutdown */
process.on('SIGTERM', () => server.close(() => process.exit(0)));
process.on('SIGINT', () => server.close(() => process.exit(0)));

module.exports = app;
