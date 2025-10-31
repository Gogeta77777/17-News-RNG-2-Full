/*
  17-News-RNG Server - FIXED VERSION
  - Session persistence completely fixed
  - Shop timer synchronized globally (exact 10-minute intervals)
  - No more "Not Logged In" errors
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
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, message: 'Too many attempts' }
});

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session Store with longer TTL
const sessionStore = new MemoryStore({
  checkPeriod: 86400000, // 24 hours
  ttl: 30 * 24 * 60 * 60 * 1000 // 30 days
});

const sessionMiddleware = session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET || 'rng2-ultra-secret-key-2025',
  resave: false,
  saveUninitialized: false,
  rolling: true, // Refresh session on every request
  name: 'rng2.sid',
  cookie: {
    secure: false,
    httpOnly: true,
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
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

// Data
const IS_VERCEL = process.env.VERCEL === '1';
const DATA_FILE = path.join(__dirname, 'saveData.json');

// Shop rotation - FIXED to use exact 10-minute intervals
const SHOP_ITEMS = [
  { name: 'Potato Sticker', type: 'item', price: 300, rarity: 'common' },
  { name: 'Microphone', type: 'item', price: 800, rarity: 'uncommon' },
  { name: 'Chromebook', type: 'item', price: 1500, rarity: 'rare' }
];

// Calculate which item should be shown based on current time
function getCurrentShopItem() {
  const now = Date.now();
  // Round down to nearest 10-minute interval (600000ms)
  const intervalStart = Math.floor(now / 600000) * 600000;
  const intervalIndex = Math.floor(intervalStart / 600000) % SHOP_ITEMS.length;
  
  return {
    item: SHOP_ITEMS[intervalIndex],
    nextRotation: intervalStart + 600000, // Next 10-minute mark
    intervalStart: intervalStart
  };
}

// Broadcast shop rotation to all connected clients
function broadcastShopRotation() {
  const shopData = getCurrentShopItem();
  io.emit('shop_rotated', {
    item: shopData.item,
    nextRotation: shopData.nextRotation
  });
  console.log('🔄 Shop rotated to:', shopData.item.name, 'Next at:', new Date(shopData.nextRotation).toLocaleTimeString());
}

// Set up shop rotation check every 10 seconds
setInterval(() => {
  const shopData = getCurrentShopItem();
  const timeUntilNext = shopData.nextRotation - Date.now();
  
  // If we're within 10 seconds of rotation, broadcast
  if (timeUntilNext < 10000 && timeUntilNext > 0) {
    setTimeout(() => {
      broadcastShopRotation();
    }, timeUntilNext);
  }
}, 10000);

function readData() {
  if (IS_VERCEL) {
    return global.gameData || initializeData();
  }
  
  try {
    if (!fs.existsSync(DATA_FILE)) {
      console.log('📝 Creating saveData.json');
      return initializeData();
    }
    
    const rawData = fs.readFileSync(DATA_FILE, 'utf8');
    const data = JSON.parse(rawData);
    
    if (!data.users) data.users = [];
    if (!data.codes) data.codes = [];
    if (!data.announcements) data.announcements = [];
    if (!data.events) data.events = [];
    if (!data.chatMessages) data.chatMessages = [];
    if (!data.aaEvents) data.aaEvents = [];
    
    console.log('✅ Data loaded:', data.users.length, 'users');
    return data;
  } catch (error) {
    console.error('❌ Error reading data:', error);
    return initializeData();
  }
}

function initializeData() {
  const data = {
    users: [
      {
        username: "Mr_Fernanski",
        password: "admin123",
        isAdmin: true,
        inventory: {
          rarities: {},
          potions: {},
          items: {}
        },
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
  
  writeData(data);
  return data;
}

function writeData(data) {
  if (IS_VERCEL) {
    global.gameData = data;
    return true;
  }
  
  try {
    const tempFile = DATA_FILE + '.tmp';
    fs.writeFileSync(tempFile, JSON.stringify(data, null, 2), 'utf8');
    const verify = JSON.parse(fs.readFileSync(tempFile, 'utf8'));
    fs.renameSync(tempFile, DATA_FILE);
    console.log('💾 Saved');
    return true;
  } catch (error) {
    console.error('❌ Write error:', error);
    try {
      if (fs.existsSync(DATA_FILE + '.tmp')) fs.unlinkSync(DATA_FILE + '.tmp');
    } catch (e) {}
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

// FIXED Auth Middleware - No more "Not Logged In" errors
function requireAuth(req, res, next) {
  // Check if session exists
  if (!req.session) {
    console.log('❌ No session object');
    return res.status(401).json({ success: false, error: 'Not logged in' });
  }

  // Check if user in session
  if (!req.session.user || !req.session.user.username) {
    console.log('❌ No user in session');
    return res.status(401).json({ success: false, error: 'Not logged in' });
  }

  // Verify user exists in database
  const data = readData();
  const user = data.users.find(u => u.username === req.session.user.username);
  
  if (!user) {
    console.log('❌ User not in database');
    req.session.destroy();
    return res.status(401).json({ success: false, error: 'User not found' });
  }

  // Refresh session
  req.session.touch();
  
  console.log('✅ Auth passed:', req.session.user.username);
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ success: false, error: 'Not logged in' });
  }
  
  const data = readData();
  const user = data.users.find(u => u.username === req.session.user.username);
  
  if (!user || !user.isAdmin) {
    return res.status(403).json({ success: false, error: 'Admin required' });
  }
  
  req.session.touch();
  next();
}

// Routes

app.post('/api/login', authLimiter, (req, res) => {
  try {
    const { username, password } = req.body;
    
    console.log('🔑 Login:', username);
    
    if (!username || !password) {
      return res.json({ success: false, message: 'Username and password required' });
    }

    const data = readData();
    const user = data.users.find(u => u.username === username);
    
    if (!user || user.password !== password) {
      return res.json({ success: false, message: 'Invalid credentials' });
    }

    // Ensure inventory structure
    if (!user.inventory || !user.inventory.rarities) {
      user.inventory = { rarities: {}, potions: {}, items: {} };
      writeData(data);
    }

    // Set session
    req.session.regenerate((err) => {
      if (err) {
        console.error('Session regenerate error:', err);
        return res.json({ success: false, message: 'Session error' });
      }

      req.session.user = {
        username: user.username,
        isAdmin: user.isAdmin || false
      };
      
      req.session.save((err) => {
        if (err) {
          console.error('Session save error:', err);
          return res.json({ success: false, message: 'Session error' });
        }
        
        console.log('✅ Login success:', username, 'SID:', req.sessionID);

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

app.post('/api/register', authLimiter, (req, res) => {
  try {
    const { username, password } = req.body;
    
    console.log('📝 Register:', username);
    
    if (!username || !password) {
      return res.json({ success: false, message: 'Username and password required' });
    }

    if (username.length < 3 || username.length > 20) {
      return res.json({ success: false, message: 'Username must be 3-20 characters' });
    }

    if (password.length < 6) {
      return res.json({ success: false, message: 'Password must be at least 6 characters' });
    }

    const data = readData();
    
    if (data.users.find(u => u.username === username)) {
      return res.json({ success: false, message: 'Username taken' });
    }

    const newUser = {
      username,
      password,
      isAdmin: false,
      inventory: {
        rarities: {},
        potions: {},
        items: {}
      },
      activePotions: [],
      coins: 1000,
      lastSpin: 0,
      joinDate: new Date().toISOString()
    };

    data.users.push(newUser);
    
    if (!writeData(data)) {
      return res.json({ success: false, message: 'Failed to save' });
    }

    req.session.regenerate((err) => {
      if (err) {
        return res.json({ success: false, message: 'Session error' });
      }

      req.session.user = {
        username: newUser.username,
        isAdmin: false
      };
      
      req.session.save((err) => {
        if (err) {
          return res.json({ success: false, message: 'Session error' });
        }
        
        console.log('✅ Registration:', username);

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

app.get('/api/check-session', (req, res) => {
  if (!req.session || !req.session.user) {
    return res.json({ success: false, loggedIn: false });
  }
  
  const data = readData();
  const user = data.users.find(u => u.username === req.session.user.username);
  
  if (!user) {
    req.session.destroy();
    return res.json({ success: false, loggedIn: false });
  }
  
  // Refresh session
  req.session.touch();
  
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
});

app.post('/api/spin', requireAuth, (req, res) => {
  try {
    console.log('🎰 Spin:', req.session.user.username);
    
    const data = readData();
    const user = data.users.find(u => u.username === req.session.user.username);
    
    if (!user) {
      return res.json({ success: false, error: 'User not found' });
    }

    const now = Date.now();
    let cooldown = 3000;
    
    const speedPotion = (user.activePotions || []).find(p => p.type === 'speed');
    if (speedPotion && speedPotion.expires > now) {
      cooldown = cooldown * 0.5;
    }
    
    if (user.lastSpin && (now - user.lastSpin) < cooldown) {
      const remaining = Math.ceil((cooldown - (now - user.lastSpin)) / 1000);
      return res.json({ success: false, error: `Cooldown: ${remaining}s` });
    }

    let luckMultiplier = 1;
    const activePotions = (user.activePotions || []).filter(p => p.expires > now);
    user.activePotions = activePotions;
    
    const luckPotions = activePotions.filter(p => p.type === 'luck');
    luckPotions.forEach(p => {
      luckMultiplier *= p.multiplier;
    });

    let adjustedRarities = RARITIES.map((r, idx) => {
      if (idx >= RARITIES.length - 2) {
        return { ...r, chance: r.chance * luckMultiplier };
      }
      return r;
    });
    
    const total = adjustedRarities.reduce((s, r) => s + r.chance, 0);
    const roll = Math.random() * total;
    let cursor = 0;
    let picked = adjustedRarities[adjustedRarities.length - 1];
    
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
    
    const coinReward = picked.coin || 0;
    user.coins = (user.coins || 0) + coinReward;
    user.lastSpin = now;
    
    if (!writeData(data)) {
      return res.json({ success: false, error: 'Save failed' });
    }

    console.log('✅ Spin:', picked.name, '+', coinReward);

    res.json({
      success: true,
      item: picked.name,
      rarity: picked,
      coins: user.coins,
      awarded: coinReward,
      cooldown: cooldown
    });
  } catch (error) {
    console.error('❌ Spin error:', error);
    res.json({ success: false, error: 'Server error' });
  }
});

app.post('/api/use-potion', requireAuth, (req, res) => {
  try {
    const { potionKey } = req.body;
    
    console.log('🧪 Use potion:', potionKey);
    
    if (!potionKey || !POTIONS[potionKey]) {
      return res.json({ success: false, error: 'Invalid potion' });
    }

    const data = readData();
    const user = data.users.find(u => u.username === req.session.user.username);
    
    if (!user) {
      return res.json({ success: false, error: 'User not found' });
    }

    if (!user.inventory.potions[potionKey] || user.inventory.potions[potionKey] <= 0) {
      return res.json({ success: false, error: 'No potion available' });
    }

    const potion = POTIONS[potionKey];
    
    const existing = (user.activePotions || []).find(p => p.key === potionKey);
    if (existing) {
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

    if (!writeData(data)) {
      return res.json({ success: false, error: 'Save failed' });
    }

    console.log('✅ Potion used');

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
  const timeRemaining = Math.max(0, shopData.nextRotation - Date.now());
  
  res.json({
    success: true,
    item: shopData.item,
    nextRotation: shopData.nextRotation,
    timeRemaining
  });
});

app.post('/api/shop/buy', requireAuth, (req, res) => {
  try {
    const { itemName } = req.body;
    
    console.log('🛒 Shop buy:', itemName, 'by', req.session.user.username);
    
    const shopData = getCurrentShopItem();
    
    if (itemName !== shopData.item.name) {
      return res.json({ success: false, error: 'Item not available' });
    }

    const data = readData();
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
      user.inventory.items[itemKey] = {
        name: shopData.item.name,
        count: 0
      };
    }
    user.inventory.items[itemKey].count += 1;

    if (!writeData(data)) {
      return res.json({ success: false, error: 'Save failed' });
    }

    console.log('✅ Purchase');

    res.json({ success: true, coins: user.coins, inventory: user.inventory });
  } catch (error) {
    console.error('❌ Shop error:', error);
    res.json({ success: false, error: 'Server error' });
  }
});

app.post('/api/shop/buy-potion', requireAuth, (req, res) => {
  try {
    const { potionKey } = req.body;
    
    const POTION_PRICES = {
      luck1: 500,
      speed1: 800,
      luck2: 2000
    };
    
    if (!potionKey || !POTIONS[potionKey]) {
      return res.json({ success: false, error: 'Invalid potion' });
    }

    const price = POTION_PRICES[potionKey];
    
    const data = readData();
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

    if (!writeData(data)) {
      return res.json({ success: false, error: 'Save failed' });
    }

    console.log('✅ Potion purchased');

    res.json({ success: true, coins: user.coins, inventory: user.inventory });
  } catch (error) {
    console.error('❌ Shop error:', error);
    res.json({ success: false, error: 'Server error' });
  }
});

app.post('/api/use-code', requireAuth, (req, res) => {
  try {
    const { code } = req.body;
    
    console.log('🎫 Code:', code);
    
    if (!code) {
      return res.json({ success: false, error: 'Code required' });
    }

    const data = readData();
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
    
    if (!writeData(data)) {
      return res.json({ success: false, error: 'Save failed' });
    }

    console.log('✅ Code redeemed');

    res.json({ success: true, coins: user.coins, inventory: user.inventory });
  } catch (error) {
    console.error('❌ Code error:', error);
    res.json({ success: false, error: 'Server error' });
  }
});

app.get('/api/data', requireAuth, (req, res) => {
  try {
    const data = readData();
    const user = data.users.find(u => u.username === req.session.user.username);
    
    if (!user) {
      return res.json({ success: false, error: 'User not found' });
    }

    const now = Date.now();
    if (user.activePotions) {
      user.activePotions = user.activePotions.filter(p => p.expires > now);
      writeData(data);
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

app.post('/api/admin/announcement', requireAdmin, (req, res) => {
  try {
    const { title, content } = req.body;
    
    console.log('📢 Announcement:', title);
    
    if (!title || !content) {
      return res.json({ success: false, error: 'Title and content required' });
    }

    const data = readData();
    
    const announcement = {
      id: Date.now(),
      title,
      content,
      date: new Date().toISOString(),
      author: req.session.user.username
    };

    data.announcements.push(announcement);
    
    if (!writeData(data)) {
      return res.json({ success: false, error: 'Save failed' });
    }

    io.emit('new_announcement', announcement);

    console.log('✅ Announcement created');

    res.json({ success: true, announcement });
  } catch (error) {
    console.error('❌ Announcement error:', error);
    res.json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/event', requireAdmin, (req, res) => {
  try {
    const { name, description, startDate, endDate } = req.body;
    
    console.log('🎉 Event:', name);
    
    if (!name || !startDate || !endDate) {
      return res.json({ success: false, error: 'Required fields missing' });
    }

    const data = readData();
    
    const event = {
      id: Date.now(),
      name,
      description: description || '',
      startDate,
      endDate,
      active: false
    };

    data.events.push(event);
    
    if (!writeData(data)) {
      return res.json({ success: false, error: 'Save failed' });
    }

    io.emit('new_event', event);

    console.log('✅ Event created');

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

  socket.on('chat_message', (msg) => {
    try {
      if (!msg.username || !msg.message) return;
      
      const data = readData();
      const chatMsg = {
        username: msg.username,
        message: msg.message.slice(0, 500),
        timestamp: new Date().toISOString()
      };
      
      data.chatMessages.push(chatMsg);
      if (data.chatMessages.length > 100) {
        data.chatMessages = data.chatMessages.slice(-100);
      }
      
      const saved = writeData(data);
      
      if (saved) {
        io.emit('chat_message', chatMsg);
        console.log('💬 Chat saved:', msg.username);
      } else {
        console.error('❌ Chat save failed');
      }
    } catch (error) {
      console.error('❌ Chat error:', error);
    }
  });

  socket.on('disconnect', () => {
    console.log('🔌 Disconnected:', username || 'guest');
  });
});

// Initialize
readData();

const PORT = process.env.PORT || 3000;

if (!IS_VERCEL) {
  server.listen(PORT, () => {
    const shopData = getCurrentShopItem();
    console.log('');
    console.log('🎮 ═══════════════════════════════════════════');
    console.log('🎮 17 News RNG 2 - Server Running');
    console.log('🎮 ═══════════════════════════════════════════');
    console.log(`📍 Local: http://localhost:${PORT}`);
    console.log(`📦 Data: ${DATA_FILE}`);
    console.log(`👥 Users: ${readData().users.length}`);
    console.log(`🏪 Shop: ${shopData.item.name}`);
    console.log(`🔄 Next rotation: ${new Date(shopData.nextRotation).toLocaleTimeString()}`);
    console.log('🎮 ═══════════════════════════════════════════');
    console.log('');
  });
}

module.exports = server;
