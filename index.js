/*
  17-News-RNG Server - Final Version with All Fixes
  - Session persistence across refreshes
  - Fixed admin/code authentication
  - Fixed chat real-time updates
  - Proper data saving
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

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, message: 'Too many attempts, please try again later' }
});

// Middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration - PERSISTENT
const sessionMiddleware = session({
  store: new MemoryStore({
    checkPeriod: 86400000
  }),
  secret: process.env.SESSION_SECRET || 'dev-secret-17news-rng-2025-super-secure',
  resave: false,
  saveUninitialized: false,
  name: 'rng2.sid', // Custom cookie name
  cookie: {
    secure: false,
    httpOnly: true,
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    sameSite: 'lax'
  }
});

app.use(sessionMiddleware);

// Share session with Socket.IO
io.use((socket, next) => {
  sessionMiddleware(socket.request, socket.request.res || {}, next);
});

// Serve static files
app.use(express.static(__dirname, {
  index: false,
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    }
  }
}));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Data management
const IS_VERCEL = process.env.VERCEL === '1';
const DATA_FILE = path.join(__dirname, 'saveData.json');

function readData() {
  if (IS_VERCEL) {
    // For Vercel, use in-memory
    return global.gameData || initializeData();
  }
  
  try {
    if (!fs.existsSync(DATA_FILE)) {
      console.log('📝 Creating new saveData.json');
      return initializeData();
    }
    
    const rawData = fs.readFileSync(DATA_FILE, 'utf8');
    const data = JSON.parse(rawData);
    
    // Ensure all required fields
    if (!data.users) data.users = [];
    if (!data.codes) data.codes = [];
    if (!data.announcements) data.announcements = [];
    if (!data.events) data.events = [];
    if (!data.chatMessages) data.chatMessages = [];
    if (!data.aaEvents) data.aaEvents = [{ id: 'disco', name: 'Disco Mode', active: false }];
    
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
        inventory: [],
        coins: 10000,
        joinDate: "2025-10-22T00:00:00.000Z"
      }
    ],
    codes: [
      {
        code: "WELCOME17",
        reward: { type: "coins", amount: 500 },
        usedBy: []
      },
      {
        code: "ALPHA2025",
        reward: { type: "coins", amount: 1000 },
        usedBy: []
      }
    ],
    announcements: [],
    events: [],
    chatMessages: [],
    aaEvents: [{ id: 'disco', name: 'Disco Mode', active: false }]
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
    
    // Verify
    const verify = JSON.parse(fs.readFileSync(tempFile, 'utf8'));
    
    // Atomic rename
    fs.renameSync(tempFile, DATA_FILE);
    
    console.log('💾 Data saved successfully');
    return true;
  } catch (error) {
    console.error('❌ Error writing data:', error);
    
    // Cleanup
    try {
      const tempFile = DATA_FILE + '.tmp';
      if (fs.existsSync(tempFile)) fs.unlinkSync(tempFile);
    } catch (e) {}
    
    return false;
  }
}

// Rarities - CLEAN VERSION
const RARITIES = [
  { name: '17 News', chance: 45, color: '#4CAF50', coin: 100 },
  { name: '17 News Reborn', chance: 30, color: '#2196F3', coin: 250 },
  { name: 'Delan Fernando', chance: 15, color: '#9C27B0', coin: 500 },
  { name: 'Cooper Metson', chance: 8, color: '#FF9800', coin: 1000 },
  { name: 'Mr Fernanski', chance: 2, color: '#F44336', coin: 2500 }
];

// Auth middleware - FIXED
function requireAuth(req, res, next) {
  console.log('🔐 Auth check:', {
    hasSession: !!req.session,
    hasUser: !!req.session?.user,
    user: req.session?.user?.username,
    sessionID: req.sessionID
  });
  
  if (!req.session || !req.session.user || !req.session.user.username) {
    console.log('❌ Auth failed - no valid session');
    return res.status(401).json({ success: false, error: 'Not logged in' });
  }
  
  // Verify user still exists in database
  const data = readData();
  const user = data.users.find(u => u.username === req.session.user.username);
  
  if (!user) {
    console.log('❌ Auth failed - user not found in database');
    req.session.destroy();
    return res.status(401).json({ success: false, error: 'User not found' });
  }
  
  console.log('✅ Auth passed:', req.session.user.username);
  next();
}

function requireAdmin(req, res, next) {
  console.log('👑 Admin check:', {
    user: req.session?.user?.username,
    isAdmin: req.session?.user?.isAdmin
  });
  
  if (!req.session || !req.session.user) {
    console.log('❌ Admin check failed - no session');
    return res.status(401).json({ success: false, error: 'Not logged in' });
  }
  
  // Re-verify admin status from database
  const data = readData();
  const user = data.users.find(u => u.username === req.session.user.username);
  
  if (!user) {
    console.log('❌ Admin check failed - user not found');
    return res.status(401).json({ success: false, error: 'User not found' });
  }
  
  if (!user.isAdmin) {
    console.log('❌ Admin check failed - not admin');
    return res.status(403).json({ success: false, error: 'Admin access required' });
  }
  
  console.log('✅ Admin check passed');
  next();
}

// API Routes

app.post('/api/login', authLimiter, (req, res) => {
  try {
    const { username, password } = req.body;
    
    console.log('🔑 Login attempt:', username);
    
    if (!username || !password) {
      return res.json({ success: false, message: 'Username and password required' });
    }

    const data = readData();
    const user = data.users.find(u => u.username === username);
    
    if (!user || user.password !== password) {
      console.log('❌ Invalid credentials');
      return res.json({ success: false, message: 'Invalid credentials' });
    }

    // Set session with all user data
    req.session.user = {
      username: user.username,
      isAdmin: user.isAdmin || false
    };
    
    // Force save
    req.session.save((err) => {
      if (err) {
        console.error('❌ Session save error:', err);
        return res.json({ success: false, message: 'Session error' });
      }
      
      console.log('✅ Login successful:', username, 'SessionID:', req.sessionID);

      res.json({
        success: true,
        user: {
          username: user.username,
          isAdmin: user.isAdmin || false,
          coins: user.coins || 0,
          inventory: user.inventory || []
        }
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
    
    console.log('📝 Register attempt:', username);
    
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
      return res.json({ success: false, message: 'Username already taken' });
    }

    const newUser = {
      username,
      password,
      isAdmin: false,
      inventory: [],
      coins: 1000,
      joinDate: new Date().toISOString()
    };

    data.users.push(newUser);
    
    if (!writeData(data)) {
      return res.json({ success: false, message: 'Failed to save user' });
    }

    // Set session
    req.session.user = {
      username: newUser.username,
      isAdmin: false
    };
    
    req.session.save((err) => {
      if (err) {
        console.error('❌ Session save error:', err);
        return res.json({ success: false, message: 'Session error' });
      }
      
      console.log('✅ Registration successful:', username);

      res.json({
        success: true,
        user: {
          username: newUser.username,
          isAdmin: false,
          coins: 1000,
          inventory: []
        }
      });
    });
  } catch (error) {
    console.error('❌ Register error:', error);
    res.json({ success: false, message: 'Server error' });
  }
});

// Check session status
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
  
  res.json({
    success: true,
    loggedIn: true,
    user: {
      username: user.username,
      isAdmin: user.isAdmin || false,
      coins: user.coins || 0,
      inventory: user.inventory || []
    }
  });
});

app.post('/api/spin', requireAuth, (req, res) => {
  try {
    console.log('🎰 Spin request from:', req.session.user.username);
    
    const data = readData();
    const user = data.users.find(u => u.username === req.session.user.username);
    
    if (!user) {
      return res.json({ success: false, error: 'User not found' });
    }

    // Pick rarity
    const total = RARITIES.reduce((s, r) => s + r.chance, 0);
    const roll = Math.random() * total;
    let cursor = 0;
    let picked = RARITIES[RARITIES.length - 1];
    
    for (const rarity of RARITIES) {
      cursor += rarity.chance;
      if (roll <= cursor) {
        picked = rarity;
        break;
      }
    }

    const item = {
      name: picked.name,
      rarity: picked.name.toLowerCase().replace(/\s+/g, '-'),
      date: new Date().toISOString()
    };

    user.inventory.push(item);
    
    // Award coins
    const coinReward = picked.coin || 0;
    user.coins = (user.coins || 0) + coinReward;
    
    if (!writeData(data)) {
      return res.json({ success: false, error: 'Failed to save spin result' });
    }

    console.log('✅ Spin successful:', picked.name, '+', coinReward, 'coins');

    res.json({
      success: true,
      item: picked.name,
      rarity: picked,
      coins: user.coins,
      awarded: coinReward
    });
  } catch (error) {
    console.error('❌ Spin error:', error);
    res.json({ success: false, error: 'Server error' });
  }
});

app.post('/api/use-code', requireAuth, (req, res) => {
  try {
    const { code } = req.body;
    
    console.log('🎫 Code redemption:', code, 'by', req.session.user.username);
    
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

    if (!Array.isArray(codeData.usedBy)) {
      codeData.usedBy = [];
    }

    if (codeData.usedBy.includes(user.username)) {
      return res.json({ success: false, error: 'Code already used' });
    }

    // Apply reward
    if (codeData.reward.type === 'coins') {
      user.coins = (user.coins || 0) + (codeData.reward.amount || 0);
    } else if (codeData.reward.type === 'item') {
      user.inventory.push({
        name: codeData.reward.item,
        rarity: codeData.reward.rarity || 'common',
        date: new Date().toISOString()
      });
    }

    codeData.usedBy.push(user.username);
    
    if (!writeData(data)) {
      return res.json({ success: false, error: 'Failed to save code redemption' });
    }

    console.log('✅ Code redeemed:', code);

    res.json({ success: true, message: 'Code redeemed successfully', coins: user.coins });
  } catch (error) {
    console.error('❌ Code error:', error);
    res.json({ success: false, error: 'Server error' });
  }
});

app.post('/api/shop/buy', requireAuth, (req, res) => {
  try {
    const { itemName, price, rarity } = req.body;
    
    console.log('🛒 Shop purchase:', itemName, 'for', price, 'coins by', req.session.user.username);
    
    if (!itemName || typeof price !== 'number') {
      return res.json({ success: false, error: 'Invalid purchase data' });
    }

    const data = readData();
    const user = data.users.find(u => u.username === req.session.user.username);
    
    if (!user) {
      return res.json({ success: false, error: 'User not found' });
    }

    if ((user.coins || 0) < price) {
      return res.json({ success: false, error: 'Not enough coins' });
    }

    user.coins = (user.coins || 0) - price;
    user.inventory.push({
      name: itemName,
      rarity: rarity || 'common',
      date: new Date().toISOString()
    });

    if (!writeData(data)) {
      return res.json({ success: false, error: 'Failed to save purchase' });
    }

    console.log('✅ Purchase successful');

    res.json({ success: true, message: 'Purchase complete', coins: user.coins });
  } catch (error) {
    console.error('❌ Shop error:', error);
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

    res.json({
      success: true,
      user: {
        username: user.username,
        isAdmin: user.isAdmin || false,
        coins: user.coins || 0,
        inventory: user.inventory || []
      },
      announcements: data.announcements || [],
      events: data.events || [],
      chatMessages: (data.chatMessages || []).slice(-50),
      aaEvents: data.aaEvents || []
    });
  } catch (error) {
    console.error('❌ Data error:', error);
    res.json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/announcement', requireAdmin, (req, res) => {
  try {
    const { title, content } = req.body;
    
    console.log('📢 Admin creating announcement:', title, 'by', req.session.user.username);
    
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
      return res.json({ success: false, error: 'Failed to save announcement' });
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
    
    console.log('🎉 Admin creating event:', name, 'by', req.session.user.username);
    
    if (!name || !startDate || !endDate) {
      return res.json({ success: false, error: 'Name, start date, and end date required' });
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
      return res.json({ success: false, error: 'Failed to save event' });
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
    if (err) {
      console.error('Logout error:', err);
    }
    console.log('👋 User logged out:', username);
    res.clearCookie('rng2.sid');
    res.json({ success: true });
  });
});

// Socket.IO - FIXED with immediate updates
io.on('connection', (socket) => {
  const session = socket.request.session;
  const username = session?.user?.username;
  
  console.log('🔌 Socket connected:', socket.id, username || 'guest');

  socket.on('chat_message', (msg) => {
    try {
      if (!msg.username || !msg.message) {
        console.log('❌ Invalid chat message');
        return;
      }
      
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
      
      writeData(data);
      
      // Broadcast immediately to ALL clients including sender
      io.emit('chat_message', chatMsg);
      
      console.log('💬 Chat:', msg.username, '-', msg.message.substring(0, 30));
    } catch (error) {
      console.error('❌ Chat error:', error);
    }
  });

  socket.on('disconnect', () => {
    console.log('🔌 Socket disconnected:', socket.id);
  });
});

// Initialize data
readData();

// Start server
const PORT = process.env.PORT || 3000;

if (!IS_VERCEL) {
  server.listen(PORT, () => {
    console.log('');
    console.log('🎮 ═══════════════════════════════════════════');
    console.log('🎮 17 News RNG 2 - Server Running');
    console.log('🎮 ═══════════════════════════════════════════');
    console.log(`📍 Local: http://localhost:${PORT}`);
    console.log(`📦 Data: ${DATA_FILE}`);
    console.log(`👥 Users: ${readData().users.length}`);
    console.log('🎮 ═══════════════════════════════════════════');
    console.log('');
  });
}

module.exports = server;
