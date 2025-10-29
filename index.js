/*
  Fixed 17-News-RNG Server
  - Properly serves static files
  - Enhanced session management
  - Socket.IO integration
  - API endpoints
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

// Middleware - FIXED ORDER
app.use(helmet({
  contentSecurityPolicy: false, // Allow inline scripts
  crossOriginEmbedderPolicy: false
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
app.use(session({
  store: new MemoryStore({
    checkPeriod: 86400000
  }),
  secret: process.env.SESSION_SECRET || 'dev-secret-17news-rng-2025',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// Serve static files AFTER session middleware
app.use(express.static(__dirname, {
  index: false, // We'll handle index manually
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    }
  }
}));

// Explicitly serve index.html at root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Data management
const IS_VERCEL = process.env.VERCEL === '1';
const DATA_FILE = path.join(__dirname, 'saveData.json');

let inMemoryData = {
  users: [
    {
      username: "Mr_Fernanski",
      password: "admin123",
      isAdmin: true,
      inventory: [],
      coins: 10000,
      joinDate: new Date().toISOString()
    }
  ],
  codes: [
    {
      code: "WELCOME17",
      reward: { type: "coins", amount: 500 },
      usedBy: []
    }
  ],
  announcements: [],
  events: [],
  chatMessages: [],
  aaEvents: [
    { id: 'disco', name: 'Disco Mode', active: false }
  ]
};

function readData() {
  if (IS_VERCEL) return inMemoryData;
  
  try {
    if (!fs.existsSync(DATA_FILE)) {
      writeData(inMemoryData);
      return inMemoryData;
    }
    const data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    
    // Ensure aaEvents exists
    if (!data.aaEvents) {
      data.aaEvents = [{ id: 'disco', name: 'Disco Mode', active: false }];
    }
    
    return data;
  } catch (error) {
    console.error('Error reading data:', error);
    return inMemoryData;
  }
}

function writeData(data) {
  if (IS_VERCEL) {
    inMemoryData = data;
    return true;
  }
  
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
    return true;
  } catch (error) {
    console.error('Error writing data:', error);
    return false;
  }
}

// Rarities
const RARITIES = [
  { name: '17 News', chance: 45, color: '#4CAF50', coin: 100 },
  { name: '17 News Reborn', chance: 30, color: '#2196F3', coin: 250 },
  { name: 'Delan Fernando', chance: 15, color: '#9C27B0', coin: 500 },
  { name: 'Cooper Metson', chance: 8, color: '#FF9800', coin: 1000 },
  { name: 'Mr Fernanski', chance: 2, color: '#F44336', coin: 2500 }
];

function generateItemName(rarity) {
  const adj = ['Ancient', 'Glowing', 'Shiny', 'Rusty', 'Cyber', 'Arcane', 'Lucky'];
  const noun = ['Relic', 'Core', 'Shard', 'Crate', 'Module', 'Chip', 'Talisman'];
  const a = adj[Math.floor(Math.random() * adj.length)];
  const n = noun[Math.floor(Math.random() * noun.length)];
  return `${a} ${n} (${rarity})`;
}

// Auth middleware
function requireAuth(req, res, next) {
  if (!req.session?.user) {
    return res.status(401).json({ success: false, error: 'Not logged in' });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session?.user?.isAdmin) {
    return res.status(403).json({ success: false, error: 'Admin access required' });
  }
  next();
}

// API Routes
app.post('/api/login', authLimiter, (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.json({ success: false, message: 'Username and password required' });
    }

    const data = readData();
    const user = data.users.find(u => u.username === username);
    
    if (!user || user.password !== password) {
      return res.json({ success: false, message: 'Invalid credentials' });
    }

    req.session.user = {
      username: user.username,
      isAdmin: user.isAdmin || false
    };

    res.json({
      success: true,
      user: {
        username: user.username,
        isAdmin: user.isAdmin || false,
        coins: user.coins || 0,
        inventory: user.inventory || []
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.json({ success: false, message: 'Server error' });
  }
});

app.post('/api/register', authLimiter, (req, res) => {
  try {
    const { username, password } = req.body;
    
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
    writeData(data);

    req.session.user = {
      username: newUser.username,
      isAdmin: false
    };

    res.json({
      success: true,
      user: {
        username: newUser.username,
        isAdmin: false,
        coins: 1000,
        inventory: []
      }
    });
  } catch (error) {
    console.error('Register error:', error);
    res.json({ success: false, message: 'Server error' });
  }
});

app.post('/api/spin', requireAuth, (req, res) => {
  try {
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

    const itemName = generateItemName(picked.name);
    const item = {
      name: itemName,
      rarity: picked.name.toLowerCase(),
      date: new Date().toISOString()
    };

    user.inventory.push(item);
    
    // Award coins
    const coinReward = picked.coin || 0;
    user.coins = (user.coins || 0) + coinReward;
    
    writeData(data);

    res.json({
      success: true,
      item: itemName,
      rarity: picked,
      coins: user.coins,
      awarded: coinReward
    });
  } catch (error) {
    console.error('Spin error:', error);
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
    console.error('Data error:', error);
    res.json({ success: false, error: 'Server error' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Socket.IO
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

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
      
      writeData(data);
      io.emit('chat_message', chatMsg);
    } catch (error) {
      console.error('Chat error:', error);
    }
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// Start server
const PORT = process.env.PORT || 3000;

if (!IS_VERCEL) {
  server.listen(PORT, () => {
    console.log(`🚀 17 News RNG 2 running on port ${PORT}`);
    console.log(`📍 Local: http://localhost:${PORT}`);
  });
}

module.exports = server;
