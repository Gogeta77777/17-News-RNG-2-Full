/*
  17-News-RNG Server - Update 8.0 - MAJOR IMPROVEMENTS
  - Global Chat ensured
  - Admin abuse events logging & broadcasting
  - Shop rotation stability
  - Trading verified
  - Frontend style tweaks and performance improvements
  - Render.yaml deployment support
*/

// Ensure logs are flushed immediately
if (process.stdout._handle && process.stdout._handle.setBlocking) {
  process.stdout._handle.setBlocking(true);
  process.stderr._handle.setBlocking(true);
}

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
  transports: ['polling', 'websocket'],
  pingTimeout: 20000,
  pingInterval: 10000,
  maxHttpBufferSize: 1e6,
  serveClient: true,
  allowEIO3: true
});

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

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, message: 'Too many attempts' },
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: true }
});

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

// Health check endpoint for Render
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

// DATABASE INITIALIZATION
async function initializeDatabase() {
  if (!pool) return;

  try {
    console.log('🔧 Initializing database...');
    
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
      await pool.query(
        'INSERT INTO game_data (id, data) VALUES (1, $1)',
        [JSON.stringify(initialData)]
      );
      console.log('✅ Database initialized with Mr_Fernanski admin');
    } else {
      const data = result.rows[0].data;
      let needsUpdate = false;
      
      const mrF = data.users.find(u => u.username === 'Mr_Fernanski');
      if (!mrF) {
        data.users.push({
          username: 'Mr_Fernanski',
          password: 'loopdev2012',
          isAdmin: true,
          banned: false,
          hasAdminRole: false,
          inventory: { rarities: {}, potions: {}, items: {} },
          activePotions: [],
          coins: 10000,
          lastSpin: 0,
          totalSpins: 0,
          equippedTitle: null,
          joinDate: '2025-10-22T00:00:00.000Z'
        });
        needsUpdate = true;
      } else if (!mrF.isAdmin) {
        mrF.isAdmin = true;
        needsUpdate = true;
      }
      
      if (!data.adminEvents) {
        data.adminEvents = [];
        needsUpdate = true;
      }
      
      data.users.forEach(user => {
        if (user.banned === undefined) {
          user.banned = false;
          needsUpdate = true;
        }
        if (user.hasAdminRole === undefined) {
          user.hasAdminRole = false;
          needsUpdate = true;
        }
      });
      
      if (needsUpdate) {
        await pool.query(
          'UPDATE game_data SET data = $1, updated_at = CURRENT_TIMESTAMP WHERE id = 1',
          [JSON.stringify(data)]
        );
        console.log('✅ Database updated');
      }
    }
  } catch (error) {
    console.error('❌ Database initialization error:', error);
  }
}

const DATA_FILE = path.join(__dirname, 'saveData.json');
const KV_KEY = 'rng2:gamedata';

const SHOP_ITEMS = [
  { name: 'Potato Sticker', type: 'item', price: 300 },
  { name: 'Microphone', type: 'item', price: 800 },
  { name: 'Chromebook', type: 'item', price: 1500 },
  { name: 'Football', type: 'item', price: 2000 },
  { name: 'House Leader Badge', type: 'special', price: 10000 },
  { name: 'School Leader Badge', type: 'special', price: 50000 }
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
  console.log('📤 Broadcasting shop rotation:', shopData.item.name);
  io.emit('shop_rotated', {
    item: shopData.item,
    nextRotation: shopData.nextRotation
  });
  console.log('🔄 Shop rotated:', shopData.item.name);
}

let shopCheckInterval = null;

function startShopRotationCheck() {
  if (shopCheckInterval) clearInterval(shopCheckInterval);
  
  shopCheckInterval = setInterval(() => {
    const shopData = getCurrentShopItem();
    const timeUntilNext = shopData.nextRotation - Date.now();
    
    if (timeUntilNext <= 0) {
      broadcastShopRotation();
    }
  }, 1000);
}

startShopRotationCheck();

function initializeData() {
  return {
    users: [
      {
        username: 'Mr_Fernanski',
        password: 'loopdev2012',
        isAdmin: true,
        banned: false,
        hasAdminRole: false,
        inventory: { rarities: {}, potions: {}, items: {} },
        activePotions: [],
        coins: 10000,
        lastSpin: 0,
        totalSpins: 0,
        equippedTitle: null,
        joinDate: '2025-10-22T00:00:00.000Z'
      }
    ],
    codes: [
      { code: "WELCOME17", reward: { type: "coins", amount: 500 }, usedBy: [] },
      { code: "RELEASE2025", reward: { type: "coins", amount: 1000 }, usedBy: [] },
      { code: "LUCKPOTION", reward: { type: "potion", potion: "luck1" }, usedBy: [] },
      { code: "UPDATE5", reward: { type: "potion", potion: "finale" }, usedBy: [] },
      { code: "LORDFINNISHERE!", reward: { type: "potion", potion: "luck3", amount: 3 }, usedBy: [] },
      { code: "JONAHDELANSTEFANMIKASTANLEY", reward: { type: "rarity", rarityKey: "the-big-5" }, usedBy: [] }
    ],
    announcements: [],
    events: [],
    chatMessages: [],
    adminEvents: [],
    trades: []
  };
}

async function readData() {
  try {
    if (pool) {
      const result = await pool.query('SELECT data FROM game_data WHERE id = 1');
      if (result.rows.length > 0) {
        return result.rows[0].data;
      }
    }

    if (IS_VERCEL && kv) {
      const data = await kv.get(KV_KEY);
      if (data) return data;
    }
    
    if (fs.existsSync(DATA_FILE)) {
      const rawData = fs.readFileSync(DATA_FILE, 'utf8');
      return JSON.parse(rawData);
    }

    const initialData = initializeData();
    await writeData(initialData);
    return initialData;
  } catch (error) {
    console.error('❌ Read error:', error);
    return initializeData();
  }
}

async function writeData(data) {
  try {
    if (pool) {
      await pool.query(
        'UPDATE game_data SET data = $1, updated_at = CURRENT_TIMESTAMP WHERE id = 1',
        [JSON.stringify(data)]
      );
      return true;
    }

    if (IS_VERCEL && kv) {
      await kv.set(KV_KEY, data);
      return true;
    }
    
    const jsonData = JSON.stringify(data, null, 2);
    fs.writeFileSync(DATA_FILE, jsonData, 'utf8');
    return true;
  } catch (error) {
    console.error('❌ Write error:', error);
    return false;
  }
}

const RARITIES = [
  { name: '17 News', chance: 37, color: '#4CAF50', coin: 100 },
  { name: '17 News Reborn', chance: 25, color: '#2196F3', coin: 250 },
  { name: 'Hudson Walter', chance: 10, color: '#00BCD4', coin: 400 },
  { name: 'Baxter Walter', chance: 10, color: '#FF5722', coin: 500 },
  { name: 'Stanley Bowden', chance: 10, color: '#8B4513', coin: 450 },
  { name: 'John Tan', chance: 10, color: '#00B8D4', coin: 455 },
  { name: 'Iyo Tenedor', chance: 6, color: '#4B0082', coin: 900 },
  { name: 'Atticus Lok', chance: 8, color: '#9C27B0', coin: 750 },
  { name: 'The Great Ace', chance: 1, color: '#FFB6C1', coin: 3000, type: 'legendary' },
  { name: 'Delan Fernando', chance: 5, color: '#E91E63', coin: 1200 },
  { name: 'Cooper Metson', chance: 5, color: '#FF9800', coin: 1500 },
  { name: 'Ellerslie School Cast', chance: 0.7, color: '#7B68EE', coin: 3500 },
  { name: 'The Dark Knight', chance: 0.3, color: '#1a1a1a', coin: 7500, type: 'divine' },
  { name: 'Mr Fernanski', chance: 0.5, color: '#FF0000', coin: 5000, type: 'mythical' },
  { name: 'Mrs Joseph Mcglashan', chance: 0.1, color: '#00FF88', coin: 9999, type: 'divine' },
  { name: 'Lord Crinkle', chance: 0.01, color: '#FFD700', coin: 20000, type: 'secret' }
  ,
  { name: 'Lord Finn', chance: 0.0001, color: '#FFFFFF', coin: 1000000, type: 'lord-finn' }
  ,
  { name: 'The Big 5', chance: 0, color: '#FFD1DC', coin: 0, type: 'special-code' }
];

const POTIONS = {
  luck1: { name: 'Luck Potion I', multiplier: 2, duration: 300000, type: 'luck', price: 500 },
  luck2: { name: 'Luck Potion II', multiplier: 4, duration: 300000, type: 'luck', price: 2000 },
  luck3: { name: 'Luck Potion III', multiplier: 6, duration: 180000, type: 'luck', price: 0 },
  speed1: { name: 'Speed Potion I', cooldownReduction: 0.5, duration: 300000, type: 'speed', price: 800 },
  speed2: { name: 'Speed Potion II', cooldownReduction: 0.833, duration: 180000, type: 'speed', price: 0 },
  coin1: { name: 'Coin Potion I', coinMultiplier: 2, duration: 180000, type: 'coin', price: 1500 }
  ,
  coin2: { name: 'Coin Potion II', coinMultiplier: 4, duration: 180000, type: 'coin', price: 0 },
  finale: { name: 'Final Elixir', luckMultiplier: 100, singleUse: true, type: 'finale', price: 0 }
};

const CRAFT_RECIPES = {
  speed2: {
    name: 'Speed Potion II',
    requires: { potions: { speed1: 3 }, items: { 'chromebook': 1 } },
    result: { type: 'potion', key: 'speed2' }
  },
  luck3: {
    name: 'Luck Potion III',
    requires: { potions: { luck2: 3 }, items: { 'microphone': 2, 'school-leader-badge': 1 } },
    result: { type: 'potion', key: 'luck3' }
  },
  'media-badge': {
    name: 'Media Team Badge',
    requires: { items: { 'house-leader-badge': 3, 'school-leader-badge': 1, 'chromebook': 1, 'microphone': 1 } },
    result: { type: 'item', key: 'media-team-badge', name: 'Media Team Badge' }
  }

  ,
'coin2': {
    name: 'Coin Potion II',
    requires: { 
        potions: { coin1: 25 }, 
        items: { 'school-leader-badge': 5, 'media-team-badge': 2 } 
    },
    result: { type: 'potion', key: 'coin2' }
},
'finale': {
  name: 'Final Elixir',
    requires: { 
        items: { 
            'house-leader-badge': 10, 
            'school-leader-badge': 5, 
            'media-team-badge': 5,
            'meteor-piece': 5
        },
        coins: 500000
    },
    result: { type: 'potion', key: 'finale' }
}

};

const connectedSockets = new Set();

function requireAuth(req, res, next) {
  if (!req.session || !req.session.user || !req.session.user.username) {
    return res.status(401).json({ success: false, error: 'Not logged in' });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.user || (!req.session.user.isAdmin && !req.session.user.hasAdminRole)) {
    return res.status(401).json({ success: false, error: 'Admin required' });
  }
  next();
}

function requireFullAdmin(req, res, next) {
  // Treat the owner username as full admin as well for backward compatibility
  if (!req.session || !req.session.user || !(req.session.user.isAdmin || req.session.user.username === 'Mr_Fernanski')) {
    return res.status(401).json({ success: false, error: 'Full admin required' });
  }
  next();
}

// Helper to log and broadcast admin actions (admin abuse/events)
async function logAdminEvent(action, performedBy, target, details) {
  try {
    const data = await readData();
    if (!data.adminEvents) data.adminEvents = [];
    const ev = {
      id: Date.now().toString(),
      action: action,
      performedBy: performedBy || 'unknown',
      target: target || null,
      details: details || '',
      timestamp: new Date().toISOString()
    };
    data.adminEvents.push(ev);
    await writeData(data);
    io.emit('admin_event', ev);
  } catch (err) {
    console.error('❌ Admin event log error:', err);
  }
}

let coinRushInterval = null;
let discoModeActive = false;
let alienModeActive = false;
let coinRush2Active = false;

async function startCoinRush(coinsPerSecond) {
  if (coinRushInterval) {
    clearInterval(coinRushInterval);
  }
  
  // Broadcast start immediately to all clients
  io.emit('coin_rush_start', { coinsPerSecond });
  console.log('✅ Coin Rush started:', coinsPerSecond, 'coins/sec');
  
  coinRushInterval = setInterval(async () => {
    try {
      const data = await readData();
      let updated = false;
      
      data.users.forEach(user => {
        if (connectedSockets.has(user.username)) {
          user.coins = (user.coins || 0) + coinsPerSecond;
          updated = true;
        }
      });
      
      if (updated) {
        await writeData(data);
      }
      
      // Broadcast tick immediately
      io.emit('coin_rush_tick', { coins: coinsPerSecond });
    } catch (error) {
      console.error('Coin rush error:', error);
    }
  }, 1000);
}

function stopCoinRush() {
  if (coinRushInterval) {
    clearInterval(coinRushInterval);
    coinRushInterval = null;
  }
}

// ROUTES

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

    if (user.banned) {
      return res.json({ success: false, banned: true, message: 'Account banned' });
    }

    req.session.user = {
      username: user.username,
      isAdmin: user.isAdmin || false,
      hasAdminRole: user.hasAdminRole || false
    };

    res.json({
      success: true,
      user: {
        username: user.username,
        isAdmin: user.isAdmin || false,
        hasAdminRole: user.hasAdminRole || false,
        coins: user.coins || 0,
        inventory: user.inventory || { rarities: {}, potions: {}, items: {} },
        activePotions: user.activePotions || [],
        totalSpins: user.totalSpins || 0,
        equippedTitle: user.equippedTitle || null,
        joinDate: user.joinDate
      }
    });
  } catch (error) {
    console.error('❌ Login error:', error);
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
      username,
      password,
      isAdmin: false,
      banned: false,
      hasAdminRole: false,
      inventory: { rarities: {}, potions: {}, items: {} },
      activePotions: [],
      coins: 1000,
      lastSpin: 0,
      totalSpins: 0,
      equippedTitle: null,
      joinDate: new Date().toISOString()
    };

    data.users.push(newUser);
    await writeData(data);

    req.session.user = {
      username: newUser.username,
      isAdmin: false,
      hasAdminRole: false
    };

    res.json({
      success: true,
      user: {
        username: newUser.username,
        isAdmin: false,
        hasAdminRole: false,
        coins: 1000,
        inventory: newUser.inventory,
        activePotions: [],
        totalSpins: 0,
        equippedTitle: null,
        joinDate: newUser.joinDate
      }
    });
  } catch (error) {
    console.error('❌ Register error:', error);
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

    if (user.banned) {
      return res.json({ success: false, banned: true, loggedIn: false });
    }
    
    res.json({
      success: true,
      loggedIn: true,
      user: {
        username: user.username,
        isAdmin: user.isAdmin || false,
        hasAdminRole: user.hasAdminRole || false,
        coins: user.coins || 0,
        inventory: user.inventory || { rarities: {}, potions: {}, items: {} },
        activePotions: user.activePotions || [],
        totalSpins: user.totalSpins || 0,
        equippedTitle: user.equippedTitle || null,
        joinDate: user.joinDate
      }
    });
  } catch (error) {
    console.error('❌ Check session error:', error);
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
    if (speedPotion) cooldown *= (1 - speedPotion.cooldownReduction);
    
    if (user.lastSpin && (now - user.lastSpin) < cooldown) {
      const remaining = Math.ceil((cooldown - (now - user.lastSpin)) / 1000);
      return res.json({ success: false, error: `Wait ${remaining}s` });
    }

    let luckMultiplier = 1;
    user.activePotions = (user.activePotions || []).filter(p => p.expires > now);
    user.activePotions.filter(p => p.type === 'luck').forEach(p => luckMultiplier *= p.multiplier);

    if (discoModeActive) {
      luckMultiplier *= 5;
    }

    if (alienModeActive) {
      luckMultiplier *= 10;
    }

    // Check for Finale Elixir - guarantees rare pulls
    let isFinaleElixir = false;
    if (user.finaleElixirReady) {
      isFinaleElixir = true;
      luckMultiplier *= 100;
      user.finaleElixirReady = false; // Consume it
    }

    // If Finale Elixir is active, only allow these 4 rarities: The Dark Knight, Mrs Joseph Mcglashan, Lord Crinkle, Lord Finn
    let rarityPool = RARITIES;
    if (isFinaleElixir) {
      rarityPool = RARITIES.filter(r => 
        r.name === 'The Dark Knight' || 
        r.name === 'Mrs Joseph Mcglashan' || 
        r.name === 'Lord Crinkle' || 
        r.name === 'Lord Finn'
      );
    }

    const adjustedRarities = rarityPool.map((r) => 
      (r.type === 'mythical' || r.type === 'divine' || r.type === 'secret' || r.type === 'legendary' || r.name === 'Cooper Metson' || r.name === 'The Dark Knight' || isFinaleElixir) ? 
        { ...r, chance: r.chance * luckMultiplier } : r
    );
    
    const total = adjustedRarities.reduce((s, r) => s + r.chance, 0);
    const roll = Math.random() * total;
    let cursor = 0;
    let picked = rarityPool[rarityPool.length - 1];
    
    for (const rarity of adjustedRarities) {
      cursor += rarity.chance;
      if (roll <= cursor) {
        picked = rarityPool.find(r => r.name === rarity.name);
        break;
      }
    }

const rarityKey = picked.name.toLowerCase().replace(/\s+/g, '-');
if (!user.inventory.rarities) user.inventory.rarities = {};
if (!user.inventory.rarities[rarityKey]) {
    user.inventory.rarities[rarityKey] = {
        name: picked.name,
        count: 0,
        color: picked.color,
        serialNumbers: []
    };
}

// Lord Finn serial number tracking
let serialNumber = null;
if (picked.type === 'lord-finn') {
    // Count total Lord Finn pulls across all users
    let totalLordFinns = 0;
    data.users.forEach(u => {
        if (u.inventory.rarities && u.inventory.rarities['lord-finn']) {
            totalLordFinns += u.inventory.rarities['lord-finn'].count;
        }
    });
    serialNumber = totalLordFinns + 1;
    user.inventory.rarities[rarityKey].serialNumbers.push(serialNumber);
}

user.inventory.rarities[rarityKey].count += 1;
    
    let coinAward = picked.coin || 0;
    const coinPotion = user.activePotions.find(p => p.type === 'coin' && p.expires > now);
    if (coinPotion) {
      coinAward *= coinPotion.coinMultiplier;
    }
    
    user.coins = (user.coins || 0) + coinAward;
    user.lastSpin = now;
    user.totalSpins = (user.totalSpins || 0) + 1;

    // IMMEDIATE response - don't wait for DB writes
    const spinResult = {
      success: true,
      item: picked.name,
      rarity: picked,
      coins: user.coins,
      awarded: coinAward,
      serialNumber: serialNumber,
      finaleUsed: isFinaleElixir || false
    };

    res.json(spinResult);

    // Save and broadcast in background (non-blocking)
    setImmediate(async () => {
      try {
        await writeData(data);

        // Broadcast special pulls to chat
        if (picked.type === 'mythical') {
          const chatMsg = {
            username: 'SYSTEM',
            message: `🎉 ${user.username} just got the mythical ${picked.name}! (${picked.chance}% chance)`,
            timestamp: new Date().toISOString(),
            isAdmin: false,
            isSystem: true,
            rarityType: 'mythical',
            rarityName: picked.name
          };
          data.chatMessages.push(chatMsg);
          io.emit('announcement_popup', chatMsg);
          io.emit('chat_message', chatMsg);
        } else if (picked.type === 'divine') {
          const chatMsg = {
            username: 'SYSTEM',
            message: `✨ ${user.username} just got the divine ${picked.name}! (${picked.chance}% chance)`,
            timestamp: new Date().toISOString(),
            isAdmin: false,
        isSystem: true,
        rarityType: 'divine',
        rarityName: picked.name
      };
      data.chatMessages.push(chatMsg);
      await writeData(data);
      io.emit('announcement_popup', chatMsg);
      io.emit('chat_message', chatMsg);
    } else if (picked.type === 'secret') {
      const chatMsg = {
        username: 'SYSTEM',
        message: `🌟 ${user.username} just got the secret ${picked.name}! (${picked.chance}% chance)`,
        timestamp: new Date().toISOString(),
        isAdmin: false,
        isSystem: true,
        rarityType: 'secret',
        rarityName: picked.name
      };
      data.chatMessages.push(chatMsg);
      await writeData(data);
      io.emit('announcement_popup', chatMsg);
      io.emit('chat_message', chatMsg);
    } else if (picked.type === 'legendary') {
      const chatMsg = {
        username: 'SYSTEM',
        message: `⚡ ${user.username} just got the legendary ${picked.name}! (${picked.chance}% chance)`,
        timestamp: new Date().toISOString(),
        isAdmin: false,
        isSystem: true,
        rarityType: 'legendary',
        rarityName: picked.name
      };
      data.chatMessages.push(chatMsg);
      await writeData(data);
      io.emit('announcement_popup', chatMsg);
      io.emit('chat_message', chatMsg);
    } else if (picked.type === 'lord-finn') {
      const chatMsg = {
        username: 'SYSTEM',
        message: `⭐ ${user.username} JUST OBTAINED LORD FINN! Serial #${serialNumber} (0.0001% chance)`,
        timestamp: new Date().toISOString(),
        isAdmin: false,
        isSystem: true,
        rarityType: 'lord-finn',
        rarityName: picked.name,
        serialNumber: serialNumber
      };
      data.chatMessages.push(chatMsg);
      await writeData(data);
      io.emit('announcement_popup', chatMsg);
      io.emit('chat_message', chatMsg);
      
      // Broadcast banner event
      io.emit('lord_finn_pulled', {
        username: user.username,
        serialNumber: serialNumber
      });
        }

        // Write all data once at the end
        await writeData(data);
      } catch (err) {
        console.error('Spin save error:', err);
      }
    });
  } catch (error) {
    console.error('❌ Spin error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/craft', requireAuth, async (req, res) => {
  try {
    const { recipeId } = req.body;
    const recipe = CRAFT_RECIPES[recipeId];
    
    if (!recipe) {
      return res.json({ success: false, error: 'Invalid recipe' });
    }

    const data = await readData();
    const user = data.users.find(u => u.username === req.session.user.username);
    
    if (!user) {
      return res.json({ success: false, error: 'User not found' });
    }

    // Check if user has required materials
    if (recipe.requires.potions) {
      for (const [key, count] of Object.entries(recipe.requires.potions)) {
        const has = (user.inventory.potions && user.inventory.potions[key]) || 0;
        if (has < count) {
          return res.json({ success: false, error: 'Not enough materials' });
        }
      }
    }

    // Check coins requirement
if (recipe.requires.coins) {
    if ((user.coins || 0) < recipe.requires.coins) {
        return res.json({ success: false, error: `Not enough coins (need ${recipe.requires.coins})` });
    }
}
    
    if (recipe.requires.items) {
      for (const [key, count] of Object.entries(recipe.requires.items)) {
        const itemData = user.inventory.items && user.inventory.items[key];
        const has = itemData ? itemData.count : 0;
        if (has < count) {
          return res.json({ success: false, error: 'Not enough materials' });
        }
      }
    }

    // Consume materials
    if (recipe.requires.potions) {
      for (const [key, count] of Object.entries(recipe.requires.potions)) {
        user.inventory.potions[key] -= count;
      }
    }
    
    if (recipe.requires.items) {
      for (const [key, count] of Object.entries(recipe.requires.items)) {
        user.inventory.items[key].count -= count;
        if (user.inventory.items[key].count <= 0) {
          delete user.inventory.items[key];
        }
      }
    }

    // Consume coins if required
if (recipe.requires.coins) {
    user.coins -= recipe.requires.coins;
}

    // Give result
    if (recipe.result.type === 'potion') {
      if (!user.inventory.potions) user.inventory.potions = {};
      if (!user.inventory.potions[recipe.result.key]) {
        user.inventory.potions[recipe.result.key] = 0;
      }
      user.inventory.potions[recipe.result.key] += 1;
    } else if (recipe.result.type === 'item') {
      if (!user.inventory.items) user.inventory.items = {};
      if (!user.inventory.items[recipe.result.key]) {
        user.inventory.items[recipe.result.key] = {
          name: recipe.result.name,
          count: 0
        };
      }
      user.inventory.items[recipe.result.key].count += 1;
    }

    // IMMEDIATE response
    res.json({
      success: true,
      inventory: user.inventory
    });

    // Save in background
    setImmediate(async () => {
      try {
        await writeData(data);
      } catch (err) {
        console.error('Craft save error:', err);
      }
    });
  } catch (error) {
    console.error('❌ Craft error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/equip-title', requireAuth, async (req, res) => {
  try {
    const { titleId } = req.body;
    
    const data = await readData();
    const user = data.users.find(u => u.username === req.session.user.username);
    
    if (!user) {
      return res.json({ success: false, error: 'User not found' });
    }

    user.equippedTitle = titleId;
    
    await writeData(data);

    res.json({ success: true, equippedTitle: titleId });
  } catch (error) {
    console.error('❌ Equip title error:', error);
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
    
    // Check for Finale Elixir (single use)
    if (potionKey === 'finale') {
      // Decrement inventory first
      user.inventory.potions[potionKey] -= 1;
      if (user.inventory.potions[potionKey] < 0) {
        user.inventory.potions[potionKey] = 0;
      }
      
      // Set finale elixir ready for next spin
      user.finaleElixirReady = true;
      
      // IMMEDIATE response
      res.json({
        success: true,
        message: 'Final Elixir prepared! Your next spin will have 100x luck!',
        finaleReady: true,
        activePotions: user.activePotions || []
      });
      
      // Save in background
      setImmediate(async () => {
        try {
          await writeData(data);
        } catch (err) {
          console.error('Potion finale save error:', err);
        }
      });
      return;
    }

    // For other potions, decrement inventory
    user.inventory.potions[potionKey] -= 1;
    if (user.inventory.potions[potionKey] < 0) {
      user.inventory.potions[potionKey] = 0;
    }

    if (!user.activePotions) user.activePotions = [];

    // Check if same potion type is already active to prevent stacking duplicates
    const existingPotion = user.activePotions.find(p => p.key === potionKey);
    
    if (existingPotion) {
      // Stack: extend duration instead of adding duplicate
      existingPotion.expires += potion.duration;
    } else {
      // New potion: add it
      const activePotion = {
        key: potionKey,
        name: potion.name,
        type: potion.type,
        expires: Date.now() + potion.duration
      };
      
      if (potion.multiplier) activePotion.multiplier = potion.multiplier;
      if (potion.cooldownReduction) activePotion.cooldownReduction = potion.cooldownReduction;
      if (potion.coinMultiplier) activePotion.coinMultiplier = potion.coinMultiplier;
      
      user.activePotions.push(activePotion);
    }

    // IMMEDIATE response
    res.json({
      success: true,
      message: `${potion.name} activated!`,
      activePotions: user.activePotions
    });

    // Save in background
    setImmediate(async () => {
      try {
        await writeData(data);
      } catch (err) {
        console.error('Potion save error:', err);
      }
    });
  } catch (error) {
    console.error('❌ Potion error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// TRADING SYSTEM - Update 7
app.get('/api/trading/online-users', requireAuth, (req, res) => {
  try {
    const currentUser = req.session.user.username;
    const validOnlineUsers = Array.from(connectedSockets)
      .filter(u => u !== currentUser && userSessions.has(u) && userSessions.get(u).size > 0);
    res.json({ success: true, onlineUsers: validOnlineUsers });
  } catch (error) {
    console.error('❌ Get online users error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/trading/initiate', requireAuth, async (req, res) => {
  try {
    const { targetUser, offeredItems, requestedItems } = req.body;
    const initiatorUser = req.session.user.username;

    // Validate target user is online
    if (!connectedSockets.has(targetUser) || targetUser === initiatorUser) {
      return res.json({ success: false, error: 'Target user not online or invalid' });
    }

    const data = await readData();
    const initiator = data.users.find(u => u.username === initiatorUser);
    const target = data.users.find(u => u.username === targetUser);

    if (!initiator || !target) {
      return res.json({ success: false, error: 'User not found' });
    }

    // Validate offered items exist in initiator's inventory
    if (!validateTradeItems(initiator, offeredItems)) {
      return res.json({ success: false, error: 'Invalid items offered' });
    }

    // Create trade request ID
    const tradeId = Date.now().toString();
    if (!data.trades) data.trades = [];

    const tradeRequest = {
      id: tradeId,
      initiator: initiatorUser,
      target: targetUser,
      offeredItems,
      requestedItems,
      status: 'pending',
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 300000).toISOString() // 5 min expiry
    };

    data.trades.push(tradeRequest);

    // IMMEDIATE response - don't wait for DB
    res.json({ success: true, tradeId });

    // Emit socket event to target user
    io.emit('trade_request', {
      tradeId,
      from: initiatorUser,
      offeredItems,
      requestedItems,
      expiresAt: tradeRequest.expiresAt
    });

    // Save in background
    setImmediate(async () => {
      try {
        await writeData(data);
      } catch (err) {
        console.error('Trade initiate save error:', err);
      }
    });
  } catch (error) {
    console.error('❌ Initiate trade error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/trading/accept', requireAuth, async (req, res) => {
  try {
    const { tradeId } = req.body;
    const targetUser = req.session.user.username;

    const data = await readData();
    const trade = data.trades.find(t => t.id === tradeId);

    if (!trade) {
      return res.json({ success: false, error: 'Trade not found' });
    }

    if (trade.target !== targetUser) {
      return res.json({ success: false, error: 'Not authorized' });
    }

    if (trade.status !== 'pending') {
      return res.json({ success: false, error: 'Trade no longer available' });
    }

    // Check if trade expired
    if (new Date(trade.expiresAt) < new Date()) {
      trade.status = 'expired';
      await writeData(data);
      return res.json({ success: false, error: 'Trade expired' });
    }

    const initiator = data.users.find(u => u.username === trade.initiator);
    const target = data.users.find(u => u.username === targetUser);

    if (!initiator || !target) {
      return res.json({ success: false, error: 'User not found' });
    }

    // Final validation - items still exist
    if (!validateTradeItems(initiator, trade.offeredItems) || !validateTradeItems(target, trade.requestedItems)) {
      return res.json({ success: false, error: 'Items no longer available' });
    }

    // Execute trade
    removeTradeItems(initiator, trade.offeredItems);
    addTradeItems(initiator, trade.requestedItems);

    removeTradeItems(target, trade.requestedItems);
    addTradeItems(target, trade.offeredItems);

    trade.status = 'completed';

    // Emit trade completion immediately
    io.emit('trade_completed', {
      tradeId,
      initiator: trade.initiator,
      target: targetUser
    });

    // IMMEDIATE response
    res.json({ success: true, message: 'Trade completed!' });

    // Save in background
    setImmediate(async () => {
      try {
        await writeData(data);
      } catch (err) {
        console.error('Trade accept save error:', err);
      }
    });
  } catch (error) {
    console.error('❌ Accept trade error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/trading/decline', requireAuth, async (req, res) => {
  try {
    const { tradeId } = req.body;
    const targetUser = req.session.user.username;

    const data = await readData();
    const trade = data.trades.find(t => t.id === tradeId);

    if (!trade || trade.target !== targetUser) {
      return res.json({ success: false, error: 'Trade not found or unauthorized' });
    }

    trade.status = 'declined';

    // Emit immediately
    io.emit('trade_declined', { tradeId, by: targetUser });

    // IMMEDIATE response
    res.json({ success: true });

    // Save in background
    setImmediate(async () => {
      try {
        await writeData(data);
      } catch (err) {
        console.error('Trade decline save error:', err);
      }
    });
  } catch (error) {
    console.error('❌ Decline trade error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/trading/cancel', requireAuth, async (req, res) => {
  try {
    const { tradeId } = req.body;
    const initiatorUser = req.session.user.username;

    const data = await readData();
    const trade = data.trades.find(t => t.id === tradeId);

    if (!trade || trade.initiator !== initiatorUser) {
      return res.json({ success: false, error: 'Trade not found or unauthorized' });
    }

    if (trade.status !== 'pending') {
      return res.json({ success: false, error: 'Cannot cancel completed trade' });
    }

    trade.status = 'cancelled';

    // Emit immediately
    io.emit('trade_cancelled', { tradeId });

    // IMMEDIATE response
    res.json({ success: true });

    // Save in background
    setImmediate(async () => {
      try {
        await writeData(data);
      } catch (err) {
        console.error('Trade cancel save error:', err);
      }
    });
  } catch (error) {
    console.error('❌ Cancel trade error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Helper functions for trading
function validateTradeItems(user, items) {
  if (!items || (items.potions && Object.keys(items.potions).length === 0) && 
      (items.items && Object.keys(items.items).length === 0) && 
      (items.rarities && Object.keys(items.rarities).length === 0)) {
    return false;
  }

  if (items.potions) {
    for (const [key, count] of Object.entries(items.potions)) {
      const has = (user.inventory.potions && user.inventory.potions[key]) || 0;
      if (has < count) return false;
    }
  }

  if (items.items) {
    for (const [key, count] of Object.entries(items.items)) {
      const itemData = user.inventory.items && user.inventory.items[key];
      const has = itemData ? itemData.count : 0;
      if (has < count) return false;
    }
  }

  if (items.rarities) {
    for (const [key, count] of Object.entries(items.rarities)) {
      const rarityData = user.inventory.rarities && user.inventory.rarities[key];
      const has = rarityData ? rarityData.count : 0;
      if (has < count) return false;
    }
  }

  return true;
}

function removeTradeItems(user, items) {
  if (items.potions) {
    for (const [key, count] of Object.entries(items.potions)) {
      user.inventory.potions[key] -= count;
      if (user.inventory.potions[key] <= 0) delete user.inventory.potions[key];
    }
  }

  if (items.items) {
    for (const [key, count] of Object.entries(items.items)) {
      user.inventory.items[key].count -= count;
      if (user.inventory.items[key].count <= 0) delete user.inventory.items[key];
    }
  }

  if (items.rarities) {
    for (const [key, count] of Object.entries(items.rarities)) {
      user.inventory.rarities[key].count -= count;
      if (user.inventory.rarities[key].count <= 0) delete user.inventory.rarities[key];
    }
  }
}

function addTradeItems(user, items) {
  if (!user.inventory.potions) user.inventory.potions = {};
  if (!user.inventory.items) user.inventory.items = {};
  if (!user.inventory.rarities) user.inventory.rarities = {};

  if (items.potions) {
    for (const [key, count] of Object.entries(items.potions)) {
      if (!user.inventory.potions[key]) user.inventory.potions[key] = 0;
      user.inventory.potions[key] += count;
    }
  }

  if (items.items) {
    for (const [key, count] of Object.entries(items.items)) {
      if (!user.inventory.items[key]) {
        const itemName = key.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
        user.inventory.items[key] = { name: itemName, count: 0 };
      }
      user.inventory.items[key].count += count;
    }
  }

  if (items.rarities) {
    for (const [key, count] of Object.entries(items.rarities)) {
      if (!user.inventory.rarities[key]) {
        const rarity = RARITIES.find(r => r.name.toLowerCase().replace(/\s+/g, '-') === key);
        if (rarity) {
          user.inventory.rarities[key] = {
            name: rarity.name,
            count: 0,
            color: rarity.color,
            serialNumbers: []
          };
        }
      }
      user.inventory.rarities[key].count += count;
    }
  }
}

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
      user.inventory.items[itemKey] = { 
        name: shopData.item.name, 
        count: 0,
        type: shopData.item.type || 'item'
      };
    }
    user.inventory.items[itemKey].count += 1;

    // IMMEDIATE response
    res.json({ success: true, coins: user.coins, inventory: user.inventory });

    // Save in background
    setImmediate(async () => {
      try {
        await writeData(data);
      } catch (err) {
        console.error('Shop buy save error:', err);
      }
    });
  } catch (error) {
    console.error('❌ Shop error:', error);
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
    
    if (price === 0) {
      return res.json({ success: false, error: 'This potion cannot be purchased' });
    }

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

    // IMMEDIATE response
    res.json({ success: true, coins: user.coins, inventory: user.inventory });

    // Save in background
    setImmediate(async () => {
      try {
        await writeData(data);
      } catch (err) {
        console.error('Potion shop save error:', err);
      }
    });
  } catch (error) {
    console.error('❌ Potion shop error:', error);
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
      const amount = codeData.reward.amount || 1;
      if (!user.inventory.potions) user.inventory.potions = {};
      if (!user.inventory.potions[potionKey]) {
        user.inventory.potions[potionKey] = 0;
      }
      user.inventory.potions[potionKey] += amount;
    } else if (codeData.reward.type === 'rarity') {
      // Add a specific rarity to the user's inventory (one-off code reward)
      const rarityKey = (codeData.reward.rarityKey || '').toLowerCase().replace(/\s+/g, '-');
      if (!user.inventory.rarities) user.inventory.rarities = {};
      if (!user.inventory.rarities[rarityKey]) {
        // find rarity metadata if present, otherwise create a basic record
        const rarityMeta = RARITIES.find(r => (r.name || '').toLowerCase().replace(/\s+/g, '-') === rarityKey);
        user.inventory.rarities[rarityKey] = {
          name: (rarityMeta && rarityMeta.name) || (codeData.reward.rarityKey || 'Special Rarity'),
          count: 0,
          color: (rarityMeta && rarityMeta.color) || '#FFFFFF',
          serialNumbers: []
        };
      }
      user.inventory.rarities[rarityKey].count += 1;
    }

    codeData.usedBy.push(user.username);
    
    // IMMEDIATE response
    res.json({ success: true, coins: user.coins, inventory: user.inventory });

    // Save in background
    setImmediate(async () => {
      try {
        await writeData(data);
      } catch (err) {
        console.error('Code save error:', err);
      }
    });
  } catch (error) {
    console.error('❌ Code error:', error);
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

    const responseData = {
      success: true,
      user: {
        username: user.username,
        isAdmin: user.isAdmin || false,
        hasAdminRole: user.hasAdminRole || false,
        coins: user.coins || 0,
        inventory: user.inventory || { rarities: {}, potions: {}, items: {} },
        activePotions: user.activePotions || [],
        totalSpins: user.totalSpins || 0,
        equippedTitle: user.equippedTitle || null,
        joinDate: user.joinDate
      },
      announcements: data.announcements || [],
      events: data.events || [],
      chatMessages: (data.chatMessages || []).slice(-200),
      adminEvents: data.adminEvents || []
    };

    if (user.isAdmin || user.hasAdminRole) {
      responseData.allUsers = data.users.map(u => ({
        username: u.username,
        isAdmin: u.isAdmin || false,
        hasAdminRole: u.hasAdminRole || false,
        banned: u.banned || false,
        coins: u.coins || 0,
        totalSpins: u.totalSpins || 0,
        inventory: u.inventory || { rarities: {}, potions: {}, items: {} },
        password: u.password
      }));
    }

    res.json(responseData);
  } catch (error) {
    console.error('❌ Data error:', error);
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
      id: Date.now().toString(),
      title,
      content,
      date: new Date().toISOString(),
      author: req.session.user.username
    };

    data.announcements.push(announcement);
    
    // Also add announcement to chat for visibility
    const chatMsg = {
      username: 'ANNOUNCEMENT',
      message: `📢 [${title}] ${content}`,
      timestamp: new Date().toISOString(),
      isAdmin: false,
      isSystem: true,
      isAnnouncement: true,
      author: req.session.user.username
    };
    data.chatMessages.push(chatMsg);
    
    await writeData(data);
    io.emit('new_announcement', announcement);
    io.emit('announcement_popup', announcement);
    io.emit('chat_message', chatMsg);

    res.json({ success: true, announcement });
  } catch (error) {
    console.error('❌ Announcement error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.delete('/api/admin/announcement/:id', requireFullAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const data = await readData();
    
    const index = data.announcements.findIndex(a => a.id === id);
    if (index === -1) {
      return res.json({ success: false, error: 'Announcement not found' });
    }

    data.announcements.splice(index, 1);
    await writeData(data);

    // Log admin event for user modification
    setImmediate(() => logAdminEvent('modify_user', req.session.user.username, user.username, `action=${action}`));

    res.json({ success: true });
  } catch (error) {
    console.error('❌ Delete announcement error:', error);
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
      id: Date.now().toString(),
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
    console.error('❌ Event error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.delete('/api/admin/event/:id', requireFullAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const data = await readData();
    
    const index = data.events.findIndex(e => e.id === id);
    if (index === -1) {
      return res.json({ success: false, error: 'Event not found' });
    }

    data.events.splice(index, 1);
    await writeData(data);

    res.json({ success: true });
  } catch (error) {
    console.error('❌ Delete event error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/coin-rush/start', requireAdmin, async (req, res) => {
  try {
    const { coinsPerSecond } = req.body;
    
    if (!coinsPerSecond || coinsPerSecond < 1 || coinsPerSecond > 1000) {
      return res.json({ success: false, error: 'Invalid coins per second (1-1000)' });
    }

    const data = await readData();
    
    const adminEvent = {
      id: Date.now(),
      type: 'coin_rush',
      name: 'Coin Rush',
      active: true,
      coinsPerSecond,
      startedAt: new Date().toISOString(),
      startedBy: req.session.user.username
    };

    if (!data.adminEvents) data.adminEvents = [];
    data.adminEvents = data.adminEvents.filter(e => e.type !== 'coin_rush');
    data.adminEvents.push(adminEvent);
    
    await writeData(data);
    
    startCoinRush(coinsPerSecond);
    io.emit('coin_rush_start', { coinsPerSecond });

    res.json({ success: true, adminEvent });
  } catch (error) {
    console.error('❌ Coin rush start error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/coin-rush/stop', requireAdmin, async (req, res) => {
  try {
    stopCoinRush();
    
    // IMMEDIATE broadcast
    io.emit('coin_rush_stop');
    res.json({ success: true });
    
    // Save in background
    setImmediate(async () => {
      try {
        const data = await readData();
        if (!data.adminEvents) data.adminEvents = [];
        data.adminEvents = data.adminEvents.filter(e => e.type !== 'coin_rush');
        await writeData(data);
      } catch (err) {
        console.error('Coin rush stop save error:', err);
      }
    });
  } catch (error) {
    console.error('❌ Coin rush stop error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/meteor/start', requireAdmin, async (req, res) => {
  try {
    // IMMEDIATE broadcast
    io.emit('meteor_start');
    res.json({ success: true });
    
    // Give Meteor Piece in background
    setImmediate(async () => {
      try {
        const data = await readData();
        data.users.forEach(user => {
          if (connectedSockets.has(user.username)) {
            if (!user.inventory.items) user.inventory.items = {};
            const meteorKey = 'meteor-piece';
            if (!user.inventory.items[meteorKey]) {
              user.inventory.items[meteorKey] = { name: 'Meteor Piece', count: 0 };
            }
            user.inventory.items[meteorKey].count += 1;
          }
        });
        await writeData(data);
      } catch (err) {
        console.error('Meteor save error:', err);
      }
    });
  } catch (error) {
    console.error('❌ Meteor error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/banana-rain/start', requireAdmin, async (req, res) => {
  try {
    io.emit('banana_rain_start');
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Banana rain error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/coin-rush-2/start', requireAdmin, async (req, res) => {
  try {
    // IMMEDIATE broadcast
    io.emit('coin_rush_2_start');
    res.json({ success: true });
    
    // Give coins in background
    setImmediate(async () => {
      try {
        const data = await readData();
        const coinsAmount = 500;
        data.users.forEach(user => {
          if (connectedSockets.has(user.username)) {
            user.coins = (user.coins || 0) + coinsAmount;
          }
        });
        await writeData(data);
      } catch (err) {
        console.error('Coin rush 2 save error:', err);
      }
    });
  } catch (error) {
    console.error('❌ Coin rush 2.0 error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/return-to-zero/start', requireFullAdmin, async (req, res) => {
  try {
    // IMMEDIATE broadcast - don't wait for DB
    io.emit('return_to_zero_start', { startedBy: req.session.user.username });
    res.json({ success: true });
    
    // Save in background
    setImmediate(async () => {
      try {
        const data = await readData();
        const adminEvent = {
          id: Date.now(),
          type: 'return_to_zero',
          name: 'Return to Zero (visual event)',
          active: true,
          startedAt: new Date().toISOString(),
          startedBy: req.session.user.username
        };
        if (!data.adminEvents) data.adminEvents = [];
        data.adminEvents = data.adminEvents.filter(e => e.type !== 'return_to_zero');
        data.adminEvents.push(adminEvent);
        await writeData(data);
      } catch (err) {
        console.error('Return to zero save error:', err);
      }
    });
  } catch (error) {
    console.error('❌ Return to Zero error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/give-admin-role', requireFullAdmin, async (req, res) => {
  try {
    const { username } = req.body;
    
    if (!username) {
      return res.json({ success: false, error: 'Username required' });
    }

    const data = await readData();
    const user = data.users.find(u => u.username === username);
    
    if (!user) {
      return res.json({ success: false, error: 'User not found' });
    }

    if (user.username === 'Mr_Fernanski') {
      return res.json({ success: false, error: 'Cannot modify owner' });
    }

    user.hasAdminRole = true;
    await writeData(data);

    // Log admin event
    setImmediate(() => logAdminEvent('give_admin_role', req.session.user.username, user.username, 'granted hasAdminRole'));

    res.json({ success: true });
  } catch (error) {
    console.error('❌ Give admin role error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/remove-admin-role', requireFullAdmin, async (req, res) => {
  try {
    const { username } = req.body;
    
    if (!username) {
      return res.json({ success: false, error: 'Username required' });
    }

    const data = await readData();
    const user = data.users.find(u => u.username === username);
    
    if (!user) {
      return res.json({ success: false, error: 'User not found' });
    }

    user.hasAdminRole = false;
    await writeData(data);

    // Log admin event
    setImmediate(() => logAdminEvent('remove_admin_role', req.session.user.username, user.username, 'removed hasAdminRole'));

    res.json({ success: true });
  } catch (error) {
    console.error('❌ Remove admin role error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/disco/start', requireAdmin, async (req, res) => {
  try {
    discoModeActive = true;
    
    // IMMEDIATE broadcast - don't wait for DB
    io.emit('disco_start');
    res.json({ success: true });
    
    // Save in background
    setImmediate(async () => {
      try {
        const data = await readData();
        const adminEvent = {
          id: Date.now(),
          type: 'disco',
          name: 'Disco Mode',
          active: true,
          startedAt: new Date().toISOString(),
          startedBy: req.session.user.username
        };
        if (!data.adminEvents) data.adminEvents = [];
        data.adminEvents = data.adminEvents.filter(e => e.type !== 'disco');
        data.adminEvents.push(adminEvent);
        await writeData(data);
      } catch (err) {
        console.error('Disco save error:', err);
      }
    });
  } catch (error) {
    console.error('❌ Disco start error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/disco/stop', requireAdmin, async (req, res) => {
  try {
    discoModeActive = false;
    
    // IMMEDIATE broadcast
    io.emit('disco_stop');
    res.json({ success: true });
    
    // Save in background
    setImmediate(async () => {
      try {
        const data = await readData();
        if (!data.adminEvents) data.adminEvents = [];
        data.adminEvents = data.adminEvents.filter(e => e.type !== 'disco');
        await writeData(data);
      } catch (err) {
        console.error('Disco stop save error:', err);
      }
    });
  } catch (error) {
    console.error('❌ Disco stop error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/alien-mode/start', requireAdmin, async (req, res) => {
  try {
    alienModeActive = true;
    
    // IMMEDIATE broadcast
    io.emit('alien_mode_start');
    res.json({ success: true, message: 'Alien Mode activated! 10x Luck for all!' });
    
    // Save in background
    setImmediate(async () => {
      try {
        const data = await readData();
        const adminEvent = {
          id: Date.now(),
          type: 'alien_mode',
          name: 'Alien Mode',
          active: true,
          startedAt: new Date().toISOString(),
          startedBy: req.session.user.username
        };
        if (!data.adminEvents) data.adminEvents = [];
        data.adminEvents = data.adminEvents.filter(e => e.type !== 'alien_mode');
        data.adminEvents.push(adminEvent);
        await writeData(data);
      } catch (err) {
        console.error('Alien mode save error:', err);
      }
    });
  } catch (error) {
    console.error('❌ Alien mode start error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/alien-mode/stop', requireAdmin, async (req, res) => {
  try {
    alienModeActive = false;
    
    // IMMEDIATE broadcast
    io.emit('alien_mode_stop');
    res.json({ success: true });
    
    // Save in background
    setImmediate(async () => {
      try {
        const data = await readData();
        if (!data.adminEvents) data.adminEvents = [];
        data.adminEvents = data.adminEvents.filter(e => e.type !== 'alien_mode');
        await writeData(data);
      } catch (err) {
        console.error('Alien mode stop save error:', err);
      }
    });
  } catch (error) {
    console.error('❌ Alien mode stop error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/coin-rush-2/start', requireAdmin, async (req, res) => {
  try {
    coinRush2Active = true;
    
    const data = await readData();
    
    const adminEvent = {
      id: Date.now(),
      type: 'coin_rush_2',
      name: 'Coin Rush 2.0',
      active: true,
      startedAt: new Date().toISOString(),
      startedBy: req.session.user.username
    };

    if (!data.adminEvents) data.adminEvents = [];
    data.adminEvents = data.adminEvents.filter(e => e.type !== 'coin_rush_2');
    data.adminEvents.push(adminEvent);
    
    await writeData(data);
    
    io.emit('coin_rush_2_start');

    res.json({ success: true, message: 'Coin Rush 2.0 activated!' });
  } catch (error) {
    console.error('❌ Coin Rush 2.0 start error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/coin-rush-2/stop', requireAdmin, async (req, res) => {
  try {
    coinRush2Active = false;
    
    // IMMEDIATE broadcast
    io.emit('coin_rush_2_stop');
    res.json({ success: true });
    
    // Save in background
    setImmediate(async () => {
      try {
        const data = await readData();
        if (!data.adminEvents) data.adminEvents = [];
        data.adminEvents = data.adminEvents.filter(e => e.type !== 'coin_rush_2');
        await writeData(data);
      } catch (err) {
        console.error('Coin rush 2 stop save error:', err);
      }
    });
  } catch (error) {
    console.error('❌ Coin Rush 2.0 stop error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/blackhole/start', requireAdmin, async (req, res) => {
  try {
    io.emit('blackhole_start');
    res.json({ success: true, message: 'Blackhole event started!' });
  } catch (error) {
    console.error('❌ Blackhole error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/ban-user', requireFullAdmin, async (req, res) => {
  try {
    const { username, action } = req.body;
    
    if (!username || !action) {
      return res.json({ success: false, error: 'Username and action required' });
    }

    const data = await readData();
    const user = data.users.find(u => u.username === username);
    
    if (!user) {
      return res.json({ success: false, error: 'User not found' });
    }

    if (user.username === 'Mr_Fernanski') {
      return res.json({ success: false, error: 'Cannot ban owner' });
    }

    if (action === 'ban') {
      user.banned = true;
    } else if (action === 'unban') {
      user.banned = false;
    }

    await writeData(data);

    // Log admin event
    setImmediate(() => logAdminEvent('ban_user', req.session.user.username, user.username, `action=${action}`));

    res.json({ success: true });
  } catch (error) {
    console.error('❌ Ban user error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/modify-user', requireFullAdmin, async (req, res) => {
  try {
    const { username, action, value, itemName, potionKey, count, rarityKey, spins, totalSpins } = req.body;
    
    const data = await readData();
    const user = data.users.find(u => u.username === username);
    
    if (!user) {
      return res.json({ success: false, error: 'User not found' });
    }

    if (action === 'setCoins') {
      user.coins = Math.max(0, parseInt(value) || 0);
    } else if (action === 'addCoins') {
      user.coins = (user.coins || 0) + (parseInt(value) || 0);
    } else if (action === 'giveItem') {
      if (!user.inventory.items) user.inventory.items = {};
      const itemKey = itemName.toLowerCase().replace(/\s+/g, '-');
      if (!user.inventory.items[itemKey]) {
        user.inventory.items[itemKey] = {
          name: itemName,
          count: 0
        };
      }
      user.inventory.items[itemKey].count += parseInt(count) || 1;
    } else if (action === 'givePotion') {
      if (!user.inventory.potions) user.inventory.potions = {};
      if (!user.inventory.potions[potionKey]) {
        user.inventory.potions[potionKey] = 0;
      }
      user.inventory.potions[potionKey] += parseInt(count) || 1;
    } else if (action === 'giveRarity') {
      if (!user.inventory.rarities) user.inventory.rarities = {};
      const rarity = RARITIES.find(r => r.name.toLowerCase().replace(/\s+/g, '-') === rarityKey);
      if (rarity) {
        if (!user.inventory.rarities[rarityKey]) {
          user.inventory.rarities[rarityKey] = {
            name: rarity.name,
            count: 0,
            color: rarity.color,
            serialNumbers: []
          };
        }
        user.inventory.rarities[rarityKey].count += parseInt(count) || 1;
      }
    } else if (action === 'setSpins') {
      user.totalSpins = Math.max(0, parseInt(totalSpins) || 0);
    } else if (action === 'addSpins') {
      user.totalSpins = (user.totalSpins || 0) + (parseInt(spins) || 0);
    } else if (action === 'clearInventory') {
      user.inventory = { rarities: {}, potions: {}, items: {} };
    } else if (action === 'resetAccount') {
      user.coins = 1000;
      user.totalSpins = 0;
      user.inventory = { rarities: {}, potions: {}, items: {} };
      user.activePotions = [];
      user.finaleElixirReady = false;
      user.equippedTitle = null;
    }

    await writeData(data);

    res.json({ success: true });
  } catch (error) {
    console.error('❌ Modify user error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/change-password', requireFullAdmin, async (req, res) => {
  try {
    const { username, newPassword } = req.body;
    
    if (!username || !newPassword) {
      return res.json({ success: false, error: 'Username and password required' });
    }

    if (newPassword.length < 6) {
      return res.json({ success: false, error: 'Password must be at least 6 characters' });
    }

    const data = await readData();
    const user = data.users.find(u => u.username === username);
    
    if (!user) {
      return res.json({ success: false, error: 'User not found' });
    }

    // Update password
    user.password = newPassword;
    
    await writeData(data);

    // Log admin event for password change
    setImmediate(() => logAdminEvent('change_password', req.session.user.username, user.username, 'password changed by admin'));

    console.log(`✅ Password changed for ${username} by ${req.session.user.username}`);

    res.json({ success: true });
  } catch (error) {
    console.error('❌ Change password error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.delete('/api/admin/chat/:messageId', requireAdmin, async (req, res) => {
  try {
    const { messageId } = req.params;
    const data = await readData();
    
    const messageIndex = data.chatMessages.findIndex(m => m.timestamp === messageId);
    
    if (messageIndex === -1) {
      return res.json({ success: false, error: 'Message not found' });
    }

    data.chatMessages.splice(messageIndex, 1);
    await writeData(data);
    
    io.emit('chat_message_deleted', { messageId });

    res.json({ success: true });
  } catch (error) {
    console.error('❌ Delete message error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.delete('/api/admin/chat/bulk', requireFullAdmin, async (req, res) => {
  try {
    const data = await readData();
    const deletedCount = data.chatMessages.length;
    
    data.chatMessages = [];
    await writeData(data);
    
    io.emit('chat_cleared');

    res.json({ success: true, deletedCount });
  } catch (error) {
    console.error('❌ Bulk delete error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/logout', (req, res) => {
  const username = req.session?.user?.username;
  if (username) {
    connectedSockets.delete(username);
  }
  
  req.session.destroy((err) => {
    if (err) console.error('Logout error:', err);
    res.clearCookie('rng2.sid');
    res.json({ success: true });
  });
});

// Socket.IO - Optimized for performance and reliability
const userSessions = new Map();

io.on('connection', (socket) => {
  const username = socket.request.session?.user?.username;
  
  if (username) {
    if (!userSessions.has(username)) {
      userSessions.set(username, new Set());
    }
    userSessions.get(username).add(socket.id);
    connectedSockets.add(username);
    io.emit('users_updated', {
      onlineUsers: Array.from(connectedSockets).filter(u => userSessions.has(u) && userSessions.get(u).size > 0)
    });
  }

  socket.on('chat_message', async (msg, callback) => {
    console.log('📨 Server received chat message:', msg);
    try {
      if (!msg || !msg.username || !msg.message) {
        console.log('❌ Invalid message format');
        if (callback) callback({ success: false });
        return;
      }
      
      const sanitizedMessage = String(msg.message).trim().slice(0, 500);
      if (!sanitizedMessage || sanitizedMessage.length === 0) {
        console.log('❌ Empty message');
        if (callback) callback({ success: false });
        return;
      }

      const chatObj = {
        username: msg.username,
        message: sanitizedMessage,
        timestamp: new Date().toISOString(),
        isAdmin: false,
        userTitle: msg.userTitle || null
      };

      console.log('📤 Broadcasting chat message to all clients');
      io.emit('chat_message', chatObj);
      if (callback) callback({ success: true });

      setImmediate(async () => {
        try {
          const data = await readData();
          if (!data.chatMessages) data.chatMessages = [];
          data.chatMessages.push(chatObj);
          if (data.chatMessages.length > 500) {
            data.chatMessages = data.chatMessages.slice(-500);
          }
          await writeData(data);
        } catch (err) {
          console.error('Chat save error:', err);
        }
      });
    } catch (error) {
      console.error('Chat error:', error);
      if (callback) callback({ success: false });
    }
  });

  socket.on('disconnect', () => {
    if (username && userSessions.has(username)) {
      userSessions.get(username).delete(socket.id);
      if (userSessions.get(username).size === 0) {
        userSessions.delete(username);
        connectedSockets.delete(username);
      }
      io.emit('users_updated', {
        onlineUsers: Array.from(connectedSockets).filter(u => userSessions.has(u) && userSessions.get(u).size > 0)
      });
    }
  });
});

// Error handling
app.use((err, req, res, next) => {
  console.error('❌ Server error:', err);
  res.status(500).json({ success: false, error: 'Internal server error' });
});

// Handle unhandled rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
  // Continue running instead of crashing
});

// Initialize
const PORT = process.env.PORT || 3000;

console.log('🚀 Starting 17-News-RNG Server on port', PORT);

// Start server immediately (don't block on database)
server.listen(PORT, async () => {
  console.log('✅ Server listening on port', PORT);
  const shopData = getCurrentShopItem();
  console.log('');
  console.log('🎮 ════════════════════════════════════════════════');
  console.log('🎮  17-News-RNG Server - Update 8.0 - MAJOR IMPROVEMENTS');
  console.log('🎮 ════════════════════════════════════════════════');
  console.log('');
  console.log('🌐 Server:', process.env.RENDER ? 'Render' : `http://localhost:${PORT}`);
  console.log('🛒 Shop:', shopData.item.name);
  console.log('⏰ Rotation:', new Date(shopData.nextRotation).toLocaleTimeString());
  console.log('💾 Storage:', pool ? 'PostgreSQL ✅' : (IS_VERCEL ? 'Vercel KV' : 'File System'));
  console.log('👑 Admin: Mr_Fernanski ready');
  console.log('');
  console.log('✨ Update 8.0 Highlights:');
  console.log('   🔊 Global Chat: reliable & near-instant delivery');
  console.log('   🛡️ Admin Events: logged and broadcast for transparency');
  console.log('   🛒 Shop: rotation guaranteed and broadcast on start');
  console.log('   ⚖️ Trading: validated and efficient');
  console.log('   🚀 Performance: reduced blocking I/O and faster responses');
  console.log('   🎨 Frontend: refreshed styles and faster load path');
  console.log('');
  console.log('✅ Ready!');
  console.log('🎮 ════════════════════════════════════════════════');
  console.log('');

  // Broadcast current shop state on startup so clients sync immediately
  try { broadcastShopRotation(); } catch (e) { /* noop */ }

  // Initialize database in background (non-blocking)
  setImmediate(async () => {
    try {
      if (!IS_VERCEL && pool) {
        await initializeDatabase();
      }
      await readData();
      console.log('✅ Database initialized in background');
    } catch (err) {
      console.error('❌ Background init error:', err);
    }
  });
});

server.on('error', (err) => {
  console.error('❌ Server error:', err);
  if (err.code === 'EADDRINUSE') {
    console.error('❌ Port', PORT, 'is already in use');
  }
  process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('👋 Shutting down gracefully...');
  stopCoinRush();
  if (pool) await pool.end();
  server.close(() => process.exit(0));
});

process.on('SIGINT', async () => {
  console.log('👋 Shutting down gracefully...');
  stopCoinRush();
  if (pool) await pool.end();
  server.close(() => process.exit(0));
});

module.exports = app;
