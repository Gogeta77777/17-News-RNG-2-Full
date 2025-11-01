/*
  17-News-RNG Server - VERCEL KV VERSION
  - Data persists across deployments
  - Uses Vercel KV (Redis) for storage
  - No more data loss!
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

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

// Vercel KV Setup (Redis)
let kv;
const IS_VERCEL = process.env.VERCEL === '1';

if (IS_VERCEL) {
  try {
    const { kv: vercelKv } = require('@vercel/kv');
    kv = vercelKv;
    console.log('✅ Vercel KV initialized');
  } catch (error) {
    console.error('❌ Vercel KV not available - install @vercel/kv');
    console.error('Run: npm install @vercel/kv');
  }
}

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, message: 'Too many attempts' }
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
  secret: 'rng2-ultra-mega-secret-key-2025-bulletproof',
  resave: true,
  saveUninitialized: false,
  rolling: true,
  name: 'rng2.sid',
  cookie: {
    secure: false,
    httpOnly: true,
    maxAge: 365 * 24 * 60 * 60 * 1000,
    sameSite: 'lax'
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

// DATA MANAGEMENT - VERCEL KV VERSION
const DATA_FILE = path.join(__dirname, 'saveData.json');
const KV_KEY = 'rng2:gamedata';

const SHOP_ITEMS = [
  { name: 'Potato Sticker', type: 'item', price: 300, rarity: 'common' },
  { name: 'Microphone', type: 'item', price: 800, rarity: 'uncommon' },
  { name: 'Chromebook', type: 'item', price: 1500, rarity: 'rare' }
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

setInterval(() => {
  const shopData = getCurrentShopItem();
  const timeUntilNext = shopData.nextRotation - Date.now();
  if (timeUntilNext < 10000 && timeUntilNext > 0) {
    setTimeout(() => broadcastShopRotation(), timeUntilNext);
  }
}, 10000);

function initializeData() {
  return {
    users: [
      {
        username: "Mr_Fernanski",
        password: "admin123",
        isAdmin: true,
        inventory: { rarities: {}, potions: {}, items: {} },
        activePotions: [],
        coins: 10000,
        lastSpin: 0,
        joinDate: "2025-10-22T00:00:00.000Z"
      }
    ],
    codes: [
      { code: "WELCOME17", reward: { type: "coins", amount: 500 }, usedBy: [] },
      { code: "ALPHA2025", reward: { type: "coins", amount: 1000 }, usedBy: [] },
      { code: "POTION", reward: { type: "potion", potion: "luck1" }, usedBy: [] }
    ],
    announcements: [],
    events: [],
    chatMessages: [],
    aaEvents: []
  };
}

// READ DATA - Works on both Vercel and local
async function readData() {
  try {
    // VERCEL: Use KV
    if (IS_VERCEL && kv) {
      console.log('📖 Reading from Vercel KV...');
      const data = await kv.get(KV_KEY);
      
      if (!data) {
        console.log('📝 No data in KV, initializing...');
        const initialData = initializeData();
        await writeData(initialData);
        return initialData;
      }
      
      // Fix old inventory structure
      if (data.users) {
        data.users.forEach(user => {
          if (Array.isArray(user.inventory)) {
            user.inventory = { rarities: {}, potions: {}, items: {} };
          }
          if (!user.inventory) {
            user.inventory = { rarities: {}, potions: {}, items: {} };
          }
          if (!user.activePotions) user.activePotions = [];
          if (!user.lastSpin) user.lastSpin = 0;
        });
      }
      
      // Ensure all fields exist
      if (!data.users) data.users = [];
      if (!data.codes) data.codes = [];
      if (!data.announcements) data.announcements = [];
      if (!data.events) data.events = [];
      if (!data.chatMessages) data.chatMessages = [];
      if (!data.aaEvents) data.aaEvents = [];
      
      console.log('✅ Loaded from KV:', data.users.length, 'users');
      return data;
    }
    
    // LOCAL: Use file system
    if (!fs.existsSync(DATA_FILE)) {
      console.log('📝 Creating saveData.json');
      const initialData = initializeData();
      await writeData(initialData);
      return initialData;
    }
    
    const rawData = fs.readFileSync(DATA_FILE, 'utf8');
    const data = JSON.parse(rawData);
    
    // Fix old inventory structure
    if (data.users) {
      data.users.forEach(user => {
        if (Array.isArray(user.inventory)) {
          user.inventory = { rarities: {}, potions: {}, items: {} };
        }
        if (!user.inventory) {
          user.inventory = { rarities: {}, potions: {}, items: {} };
        }
        if (!user.activePotions) user.activePotions = [];
        if (!user.lastSpin) user.lastSpin = 0;
      });
    }
    
    if (!data.users) data.users = [];
    if (!data.codes) data.codes = [];
    if (!data.announcements) data.announcements = [];
    if (!data.events) data.events = [];
    if (!data.chatMessages) data.chatMessages = [];
    if (!data.aaEvents) data.aaEvents = [];
    
    console.log('✅ Loaded from file:', data.users.length, 'users');
    return data;
  } catch (error) {
    console.error('❌ Read error:', error);
    const backupData = initializeData();
    await writeData(backupData);
    return backupData;
  }
}

// WRITE DATA - Works on both Vercel and local
async function writeData(data) {
  try {
    // VERCEL: Use KV
    if (IS_VERCEL && kv) {
      console.log('💾 Writing to Vercel KV...');
      await kv.set(KV_KEY, data);
      console.log('✅ Saved to KV successfully');
      return true;
    }
    
    // LOCAL: Use file system with retry
    let attempts = 0;
    const maxAttempts = 3;
    
    while (attempts < maxAttempts) {
      try {
        const tempFile = DATA_FILE + '.tmp';
        const jsonData = JSON.stringify(data, null, 2);
        
        fs.writeFileSync(tempFile, jsonData, 'utf8');
        
        const verify = JSON.parse(fs.readFileSync(tempFile, 'utf8'));
        if (!verify.users || !Array.isArray(verify.users)) {
          throw new Error('Verification failed');
        }
        
        if (fs.existsSync(DATA_FILE)) {
          fs.unlinkSync(DATA_FILE);
        }
        fs.renameSync(tempFile, DATA_FILE);
        
        console.log('💾 Saved to file successfully');
        return true;
      } catch (error) {
        attempts++;
        console.error(`❌ Write attempt ${attempts} failed:`, error.message);
        
        try {
          const tempFile = DATA_FILE + '.tmp';
          if (fs.existsSync(tempFile)) fs.unlinkSync(tempFile);
        } catch (e) {}
        
        if (attempts < maxAttempts) {
          await new Promise(resolve => setTimeout(resolve, 100 * attempts));
        }
      }
    }
    
    console.error('❌ CRITICAL: Failed to save after', maxAttempts, 'attempts');
    return false;
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
  luck1: { name: 'Luck Potion I', multiplier: 2, duration: 300000, type: 'luck' },
  luck2: { name: 'Luck Potion II', multiplier: 4, duration: 300000, type: 'luck' },
  speed1: { name: 'Speed Potion I', cooldownReduction: 0.5, duration: 300000, type: 'speed' }
};

function requireAuth(req, res, next) {
  if (!req.session) {
    console.log('❌ No session');
    return res.status(401).json({ success: false, error: 'Not logged in' });
  }

  if (!req.session.user || !req.session.user.username) {
    console.log('❌ No user in session');
    return res.status(401).json({ success: false, error: 'Not logged in' });
  }

  req.session.touch();
  req.session.save(() => {});
  
  console.log('✅ Auth:', req.session.user.username);
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ success: false, error: 'Not logged in' });
  }
  
  req.session.touch();
  req.session.save(() => {});
  next();
}

// ROUTES - All use async/await for Vercel KV

app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    console.log('🔑 Login:', username);
    
    if (!username || !password) {
      return res.json({ success: false, message: 'Credentials required' });
    }

    const data = await readData();
    const user = data.users.find(u => u.username === username);
    
    if (!user || user.password !== password) {
      return res.json({ success: false, message: 'Invalid credentials' });
    }

    if (!user.inventory || Array.isArray(user.inventory)) {
      user.inventory = { rarities: {}, potions: {}, items: {} };
      await writeData(data);
    }

    req.session.regenerate((err) => {
      if (err) console.error('Regenerate error:', err);

      req.session.user = {
        username: user.username,
        isAdmin: user.isAdmin || false
      };
      
      req.session.save((err) => {
        if (err) console.error('Save error:', err);
        
        console.log('✅ Login success:', username);

        res.json({
          success: true,
          user: {
            username: user.username,
            isAdmin: user.isAdmin || false,
            coins: user.coins || 0,
            inventory: user.inventory,
            activePotions: user.activePotions || []
          }
        });
      });
    });
  } catch (error) {
    console.error('❌ Login error:', error);
    res.json({ success: false, message: 'Server error' });
  }
});

app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    console.log('📝 Register:', username);
    
    if (!username || !password) {
      return res.json({ success: false, message: 'Credentials required' });
    }

    if (username.length < 3 || username.length > 20) {
      return res.json({ success: false, message: 'Username 3-20 characters' });
    }

    if (password.length < 6) {
      return res.json({ success: false, message: 'Password 6+ characters' });
    }

    const data = await readData();
    
    if (data.users.find(u => u.username === username)) {
      return res.json({ success: false, message: 'Username taken' });
    }

    const newUser = {
      username,
      password,
      isAdmin: false,
      inventory: { rarities: {}, potions: {}, items: {} },
      activePotions: [],
      coins: 1000,
      lastSpin: 0,
      joinDate: new Date().toISOString()
    };

    data.users.push(newUser);
    
    const saved = await writeData(data);
    if (!saved) {
      return res.json({ success: false, message: 'Failed to save' });
    }

    req.session.regenerate((err) => {
      if (err) console.error('Regenerate error:', err);

      req.session.user = {
        username: newUser.username,
        isAdmin: false
      };
      
      req.session.save((err) => {
        if (err) console.error('Save error:', err);
        
        console.log('✅ Registered:', username);

        res.json({
          success: true,
          user: {
            username: newUser.username,
            isAdmin: false,
            coins: 1000,
            inventory: newUser.inventory,
            activePotions: []
          }
        });
      });
    });
  } catch (error) {
    console.error('❌ Register error:', error);
    res.json({ success: false, message: 'Server error' });
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
    
    req.session.touch();
    req.session.save(() => {});
    
    res.json({
      success: true,
      loggedIn: true,
      user: {
        username: user.username,
        isAdmin: user.isAdmin || false,
        coins: user.coins || 0,
        inventory: user.inventory,
        activePotions: user.activePotions || []
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
    if (speedPotion) cooldown *= 0.5;
    
    if (user.lastSpin && (now - user.lastSpin) < cooldown) {
      const remaining = Math.ceil((cooldown - (now - user.lastSpin)) / 1000);
      return res.json({ success: false, error: `Cooldown: ${remaining}s` });
    }

    let luckMultiplier = 1;
    user.activePotions = (user.activePotions || []).filter(p => p.expires > now);
    user.activePotions.filter(p => p.type === 'luck').forEach(p => luckMultiplier *= p.multiplier);

    const adjustedRarities = RARITIES.map((r, idx) => 
      idx >= RARITIES.length - 2 ? { ...r, chance: r.chance * luckMultiplier } : r
    );
    
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
    if (!user.inventory.rarities[rarityKey]) {
      user.inventory.rarities[rarityKey] = {
        name: picked.name,
        count: 0,
        color: picked.color
      };
    }
    user.inventory.rarities[rarityKey].count += 1;
    
    user.coins = (user.coins || 0) + (picked.coin || 0);
    user.lastSpin = now;
    
    await writeData(data);

    console.log('✅ Spin:', picked.name);

    res.json({
      success: true,
      item: picked.name,
      rarity: picked,
      coins: user.coins,
      awarded: picked.coin || 0
    });
  } catch (error) {
    console.error('❌ Spin error:', error);
    res.json({ success: false, error: 'Server error' });
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

    res.json({
      success: true,
      message: `${potion.name} activated!`,
      activePotions: user.activePotions
    });
  } catch (error) {
    console.error('❌ Potion error:', error);
    res.json({ success: false, error: 'Server error' });
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
    
    const itemKey = shopData.item.name.toLowerCase().replace(/\s+/g, '-');
    if (!user.inventory.items[itemKey]) {
      user.inventory.items[itemKey] = { name: shopData.item.name, count: 0 };
    }
    user.inventory.items[itemKey].count += 1;

    await writeData(data);

    res.json({ success: true, coins: user.coins, inventory: user.inventory });
  } catch (error) {
    console.error('❌ Shop error:', error);
    res.json({ success: false, error: 'Server error' });
  }
});

app.post('/api/shop/buy-potion', requireAuth, async (req, res) => {
  try {
    const { potionKey } = req.body;
    const POTION_PRICES = { luck1: 500, speed1: 800, luck2: 2000 };
    
    if (!potionKey || !POTIONS[potionKey]) {
      return res.json({ success: false, error: 'Invalid potion' });
    }

    const price = POTION_PRICES[potionKey];
    const data = await readData();
    const user = data.users.find(u => u.username === req.session.user.username);
    
    if (!user) {
      return res.json({ success: false, error: 'User not found' });
    }

    if ((user.coins || 0) < price) {
      return res.json({ success: false, error: 'Not enough coins' });
    }

    user.coins -= price;
    
    if (!user.inventory.potions[potionKey]) {
      user.inventory.potions[potionKey] = 0;
    }
    user.inventory.potions[potionKey] += 1;

    await writeData(data);

    res.json({ success: true, coins: user.coins, inventory: user.inventory });
  } catch (error) {
    console.error('❌ Potion shop error:', error);
    res.json({ success: false, error: 'Server error' });
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
      if (!user.inventory.potions[potionKey]) {
        user.inventory.potions[potionKey] = 0;
      }
      user.inventory.potions[potionKey] += 1;
    }

    codeData.usedBy.push(user.username);
    
    await writeData(data);

    res.json({ success: true, coins: user.coins, inventory: user.inventory });
  } catch (error) {
    console.error('❌ Code error:', error);
    res.json({ success: false, error: 'Server error' });
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
        inventory: user.inventory,
        activePotions: user.activePotions || []
      },
      announcements: data.announcements || [],
      events: data.events || [],
      chatMessages: (data.chatMessages || []).slice(-50)
    });
  } catch (error) {
    console.error('❌ Data error:', error);
    res.json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/announcement', requireAdmin, async (req, res) => {
  try {
    const { title, content } = req.body;
    
    if (!title || !content) {
      return res.json({ success: false, error: 'Title and content required' });
    }

    const data = await readData();
    
    // Check if user is actually admin
    const user = data.users.find(u => u.username === req.session.user.username);
    if (!user || !user.isAdmin) {
      return res.json({ success: false, error: 'Admin required' });
    }
    
    const event = {
      id: Date.now(),
      name,
      description: description || '',
      startDate,
      endDate,
      active: false
    };

    data.events.push(event);
    await writeData(data);
    io.emit('new_event', event);

    res.json({ success: true, event });
  } catch (error) {
    console.error('❌ Event error:', error);
    res.json({ success: false, error: 'Server error' });
  }
});

app.post('/api/logout', (req, res) => {
  const username = req.session?.user?.username;
  req.session.destroy((err) => {
    if (err) console.error('Logout error:', err);
    console.log('👋 Logout:', username);
    res.clearCookie('rng2.sid');
    res.json({ success: true });
  });
});

// Socket.IO
io.on('connection', (socket) => {
  const session = socket.request.session;
  const username = session?.user?.username;
  console.log('🔌 Socket:', username || 'guest');

  socket.on('chat_message', async (msg) => {
    try {
      if (!msg.username || !msg.message) return;
      
      const data = await readData();
      const chatMsg = {
        username: msg.username,
        message: msg.message.slice(0, 500),
        timestamp: new Date().toISOString()
      };
      
      data.chatMessages.push(chatMsg);
      if (data.chatMessages.length > 100) {
        data.chatMessages = data.chatMessages.slice(-100);
      }
      
      await writeData(data);
      io.emit('chat_message', chatMsg);
    } catch (error) {
      console.error('❌ Chat error:', error);
    }
  });

  socket.on('disconnect', () => {
    console.log('🔌 Disconnected:', username || 'guest');
  });
});

// Initialize
if (!IS_VERCEL) {
  readData().then(() => {
    const PORT = process.env.PORT || 3000;
    server.listen(PORT, () => {
      const shopData = getCurrentShopItem();
      console.log('');
      console.log('🎮 ════════════════════════════════════════════════');
      console.log('🎮  17-News-RNG Server - VERCEL KV Edition');
      console.log('🎮 ════════════════════════════════════════════════');
      console.log('');
      console.log('🌐 Server:', `http://localhost:${PORT}`);
      console.log('🛒 Shop Item:', shopData.item.name);
      console.log('⏰ Next Rotation:', new Date(shopData.nextRotation).toLocaleTimeString());
      console.log('💾 Data Mode:', 'File System (Local)');
      console.log('');
      console.log('📝 Ready for connections...');
      console.log('🎮 ════════════════════════════════════════════════');
      console.log('');
    });
  });
}

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('');
  console.log('👋 Shutting down gracefully...');
  server.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('');
  console.log('👋 Shutting down gracefully...');
  server.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
});

module.exports = app;.find(u => u.username === req.session.user.username);
    if (!user || !user.isAdmin) {
      return res.json({ success: false, error: 'Admin required' });
    }
    
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
    console.error('❌ Announcement error:', error);
    res.json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/event', requireAdmin, async (req, res) => {
  try {
    const { name, description, startDate, endDate } = req.body;
    
    if (!name || !startDate || !endDate) {
      return res.json({ success: false, error: 'Required fields missing' });
    }

    const data = await readData();
    
    // Check if user is actually admin
    const user = data.users
