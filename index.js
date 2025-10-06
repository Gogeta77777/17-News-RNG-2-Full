const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Middleware
// Serve static files from both root and public for Railway compatibility
app.use(express.static(__dirname));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: '17-news-rng-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false },
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: './' })
}));

// Data management
const DATA_DIR = process.env.DATA_DIR || './data';
const DATA_FILE = path.join(DATA_DIR, 'saveData.json');
const BACKUP_DIR = path.join(DATA_DIR, 'backups');

// Ensure data directories exist
function ensureDirectories() {
  [DATA_DIR, BACKUP_DIR].forEach(dir => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
      console.log(`Created directory: ${dir}`);
    }
  });
}

// Create backup of data file
function createBackup() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const backupFile = path.join(BACKUP_DIR, `saveData.backup.${Date.now()}.json`);
      fs.copyFileSync(DATA_FILE, backupFile);
      console.log(`Created backup: ${backupFile}`);
      
      // Keep only last 5 backups
      const backups = fs.readdirSync(BACKUP_DIR)
        .filter(f => f.startsWith('saveData.backup'))
        .sort()
        .reverse();
      
      if (backups.length > 5) {
        backups.slice(5).forEach(backup => {
          fs.unlinkSync(path.join(BACKUP_DIR, backup));
          console.log(`Removed old backup: ${backup}`);
        });
      }
    }
  } catch (err) {
    console.error('Backup creation failed:', err);
  }
}

function initializeData() {
  ensureDirectories();
  if (!fs.existsSync(DATA_FILE)) {
    const initialData = {
      users: [
        {
          username: 'Mr_Fernanski',
          password: bcrypt.hashSync('landex2008', 10),
          isAdmin: true,
          inventory: [],
          coins: 10000,
          joinDate: new Date().toISOString()
        }
      ],
      codes: [
        { code: 'WELCOME17', reward: { type: 'coins', amount: 500 }, usedBy: [] },
        { code: 'NEWS2023', reward: { type: 'item', item: 'Common Crate', rarity: 'common' }, usedBy: [] }
      ],
      announcements: [],
      events: [],
      chatMessages: []
    };
    fs.writeFileSync(DATA_FILE, JSON.stringify(initialData, null, 2));
  }
}

function readData() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch (err) {
    console.error('Failed to parse data file, backing up corrupt file and reinitializing:', err.message);
    try {
      const corruptPath = DATA_FILE + '.corrupt.' + Date.now();
      fs.copyFileSync(DATA_FILE, corruptPath);
      console.error('Backed up corrupt data to', corruptPath);
    } catch (copyErr) {
      console.error('Failed to backup corrupt data file:', copyErr.message);
    }
    // Recreate the data file with initial structure to recover the server
    initializeData();
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  }
}

function validateData(data) {
  const requiredFields = ['users', 'codes', 'announcements', 'events', 'chatMessages'];
  return requiredFields.every(field => Array.isArray(data[field]));
}

function writeData(data) {
  try {
    // Validate data before writing
    if (!validateData(data)) {
      throw new Error('Invalid data structure');
    }

    // Create backup before writing
    createBackup();

    // Write to temporary file first
    const tempFile = `${DATA_FILE}.tmp`;
    fs.writeFileSync(tempFile, JSON.stringify(data, null, 2));

    // Rename temp file to actual file (atomic operation)
    fs.renameSync(tempFile, DATA_FILE);
    
    console.log(`Data saved successfully at ${new Date().toISOString()}`);
  } catch (err) {
    console.error('Failed to write data:', err);
    throw err; // Re-throw to handle in route handlers
  }
}

// Set up periodic backup
const BACKUP_INTERVAL = 30 * 60 * 1000; // 30 minutes
setInterval(() => {
  console.log('Creating periodic backup...');
  const data = readData();
  createBackup();
}, BACKUP_INTERVAL);

initializeData();

// Rarity system
const RARITIES = [
  { name: 'Common', color: '#9e9e9e', chance: 40 },
  { name: 'Uncommon', color: '#4caf50', chance: 25 },
  { name: 'Rare', color: '#2196f3', chance: 15 },
  { name: 'Epic', color: '#9c27b0', chance: 10 },
  { name: 'Legendary', color: '#ff9800', chance: 6 },
  { name: 'Mythic', color: '#f44336', chance: 3 },
  { name: 'Divine', color: '#e91e63', chance: 1 }
];

// Small item name generator (no serial numbers)
const ADJECTIVES = ['Ancient','Glowing','Shiny','Rusty','Cyber','Arcane','Lucky','Nebula','Solar','Luminous','Phantom','Mystic'];
const NOUNS = ['Relic','Core','Shard','Crate','Module','Chip','Talisman','Beacon','Crystal','Orb','Console','Fragment'];
function generateItemName(rarityName) {
  const adj = ADJECTIVES[Math.floor(Math.random() * ADJECTIVES.length)];
  const noun = NOUNS[Math.floor(Math.random() * NOUNS.length)];
  return `${adj} ${noun} (${rarityName})`;
}

// Apply event rewards to all users depending on event type
function applyEventRewards(event) {
  const data = readData();
  const now = new Date();
  // apply only if event is active or has applyNow flag
  try {
    if (event.type === 'meteor_shower') {
      // give coins to all users
      const amount = (event.payload && event.payload.amount) || 500;
      data.users.forEach(u => { u.coins = (u.coins || 0) + amount; });
      // Add an announcement entry
      data.announcements.push({ id: Date.now()+1, title: `Meteor Shower!`, content: `All players received ${amount} coins!`, date: now.toISOString(), author: 'Server' });
    } else if (event.type === 'treasure_flood') {
      // give each user a crate (item)
      const itemName = (event.payload && event.payload.itemName) || 'Common Crate';
      data.users.forEach(u => { u.inventory = u.inventory || []; u.inventory.push({ name: itemName, rarity: 'common', date: now.toISOString() }); });
      data.announcements.push({ id: Date.now()+2, title: `Treasure Flood!`, content: `A flood of crates washed over the servers — everyone got a ${itemName}!`, date: now.toISOString(), author: 'Server' });
    } else if (event.type === 'rare_storm') {
      // give each user a rare item
      data.users.forEach(u => { u.inventory = u.inventory || []; u.inventory.push({ name: generateItemName('Rare'), rarity: 'rare', date: now.toISOString() }); });
      data.announcements.push({ id: Date.now()+3, title: `Rare Storm!`, content: `Rare items are falling from the sky — check your inventory!`, date: now.toISOString(), author: 'Server' });
    }
    writeData(data);
    // Broadcast via socket if available
    if (io) {
      io.emit('new_event', { name: event.name, description: event.description, type: event.type });
      io.emit('refresh_data');
    }
  } catch (err) {
    console.error('Error applying event rewards:', err);
  }
}

// Authentication middleware
const requireAuth = (req, res, next) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
};

// Serve main page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// API Routes
app.post('/api/login', async (req, res) => {
  const loginAttempt = async (userInput, passInput) => {
    try {
      // Input validation
      if (!userInput || !passInput || 
          typeof userInput !== 'string' || 
          typeof passInput !== 'string') {
        return res.status(400).json({ error: 'Invalid credentials format' });
      }

      // Rate limiting (simple)
      const now = Date.now();
      const attempts = req.session.loginAttempts || [];
      req.session.loginAttempts = attempts.filter(time => now - time < 15 * 60 * 1000);
      
      if (req.session.loginAttempts.length >= 5) {
        return res.status(429).json({ error: 'Too many login attempts. Please try again later.' });
      }

      const data = readData();
      const user = data.users.find(u => u.username === userInput);

      if (!user) {
        req.session.loginAttempts.push(now);
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const match = await bcrypt.compare(passInput, user.password);

      if (!match) {
        req.session.loginAttempts.push(now);
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Login successful
      req.session.user = {
        username: user.username,
        isAdmin: user.isAdmin
      };
      req.session.loginAttempts = [];

      return res.json({
        username: user.username,
        isAdmin: user.isAdmin,
        inventory: user.inventory,
        coins: user.coins
      });
    } catch (err) {
      console.error('Login error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
  };

  await loginAttempt(req.body.username, req.body.password);
  try {
    const { username, password } = req.body;
    
    // Input validation
    if (!username || !password || 
        typeof username !== 'string' || 
        typeof password !== 'string') {
      return res.status(400).json({ error: 'Invalid credentials format' });
    }

    // Rate limiting (simple)
    const now = Date.now();
    const attempts = req.session.loginAttempts || [];
    req.session.loginAttempts = attempts.filter(time => now - time < 15 * 60 * 1000); // Keep attempts within last 15 min
    
    if (req.session.loginAttempts.length >= 5) {
      return res.status(429).json({ error: 'Too many login attempts. Please try again later.' });
    }
  const { username, password } = req.body;
  if (!username || !password) {
    return res.json({ success: false, error: 'Username and password required.' });
  }
  const data = readData();
  const user = data.users.find(u => u.username === username);
  if (!user) {
    return res.json({ success: false, error: 'User not found.' });
  }
  if (!bcrypt.compareSync(password, user.password)) {
    return res.json({ success: false, error: 'Incorrect password.' });
  }
  req.session.user = user;
  res.json({ success: true, user: { ...user, password: undefined } });
});

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Input validation
    if (!username || !password || 
        typeof username !== 'string' || 
        typeof password !== 'string' || 
        username.length < 3 || username.length > 20 || 
        password.length < 6 || password.length > 50 || 
        !/^[a-zA-Z0-9_]+$/.test(username)) {
      return res.status(400).json({ 
        error: 'Invalid credentials. Username must be 3-20 characters (alphanumeric and underscore only). Password must be 6-50 characters.' 
      });
    }
  const { username, password } = req.body;
  if (!username || !password) {
    return res.json({ success: false, error: 'Username and password required.' });
  }
  if (username.length < 3 || password.length < 4) {
    return res.json({ success: false, error: 'Username must be at least 3 characters and password at least 4.' });
  }
  const data = readData();
  if (data.users.find(u => u.username === username)) {
    return res.json({ success: false, error: 'Username already exists.' });
  }
  const newUser = {
    username,
    password: bcrypt.hashSync(password, 10),
    isAdmin: false,
    inventory: [],
    coins: 1000,
    joinDate: new Date().toISOString()
  };
  data.users.push(newUser);
  writeData(data);
  req.session.user = newUser;
  res.json({ success: true, user: { ...newUser, password: undefined } });
});

app.post('/api/spin', (req, res) => {
  if (!req.session.user) {
    return res.json({ success: false, error: 'Not logged in' });
  }

  const data = readData();
  const userIndex = data.users.findIndex(u => u.username === req.session.user.username);

  // Spin is now free, do not deduct coins

  // Determine rarity
  const random = Math.random() * 100;
  let cumulativeChance = 0;
  let selectedRarity;

  for (const rarity of RARITIES) {
    cumulativeChance += rarity.chance;
    if (random <= cumulativeChance) {
      selectedRarity = rarity;
      break;
    }
  }

  // Add item to inventory
  const itemName = `${selectedRarity.name} Item #${Date.now()}`;
  data.users[userIndex].inventory.push({
    name: itemName,
    rarity: selectedRarity.name.toLowerCase(),
    date: new Date().toISOString()
  });

  writeData(data);

  // Update session
  req.session.user = data.users[userIndex];

  res.json({ 
    success: true, 
    rarity: selectedRarity,
    item: itemName,
    coins: data.users[userIndex].coins // coins remain unchanged
  });
});

app.post('/api/use-code', (req, res) => {
  if (!req.session.user) {
    return res.json({ success: false, error: 'Not logged in' });
  }
  
  const { code } = req.body;
  const data = readData();
  const userIndex = data.users.findIndex(u => u.username === req.session.user.username);
  
  const codeData = data.codes.find(c => c.code === code);
  
  if (!codeData) {
    return res.json({ success: false, error: 'Invalid code' });
  }
  
  if (codeData.usedBy.includes(req.session.user.username)) {
    return res.json({ success: false, error: 'Code already used' });
  }
  
  // Apply reward
  if (codeData.reward.type === 'coins') {
    data.users[userIndex].coins += codeData.reward.amount;
  } else if (codeData.reward.type === 'item') {
    data.users[userIndex].inventory.push({
      name: codeData.reward.item,
      rarity: codeData.reward.rarity,
      date: new Date().toISOString()
    });
  }
  
  codeData.usedBy.push(req.session.user.username);
  writeData(data);
  
  // Update session
  req.session.user = data.users[userIndex];
  
  res.json({ 
    success: true, 
    message: `Code redeemed! Received: ${codeData.reward.type === 'coins' 
      ? codeData.reward.amount + ' coins' 
      : codeData.reward.item}` 
  });
});

app.post('/api/admin/announcement', (req, res) => {
  if (!req.session.user || !req.session.user.isAdmin) {
    return res.json({ success: false, error: 'Unauthorized' });
  }
  
  const { title, content } = req.body;
  const data = readData();
  
  data.announcements.push({
    id: Date.now(),
    title,
    content,
    date: new Date().toISOString(),
    author: req.session.user.username
  });
  
  writeData(data);
  
  // Broadcast to all connected clients
  io.emit('new_announcement', {
    title,
    content,
    author: req.session.user.username
  });
  
  res.json({ success: true });
});

app.post('/api/admin/event', (req, res) => {
  if (!req.session.user || !req.session.user.isAdmin) {
    return res.json({ success: false, error: 'Unauthorized' });
  }
  const { name, description, startDate, endDate, type, payload, applyNow } = req.body;
  const data = readData();

  const newEvent = {
    id: Date.now(),
    name,
    description,
    startDate,
    endDate,
    type: type || 'custom',
    payload: payload || {},
    active: new Date() >= new Date(startDate) && new Date() <= new Date(endDate)
  };

  data.events.push(newEvent);
  writeData(data);

  // Broadcast to all connected clients
  io.emit('new_event', { name, description, type: newEvent.type });

  // If admin requested immediate application or event is already active, apply rewards
  if (applyNow || newEvent.active) {
    applyEventRewards(newEvent);
  }

  res.json({ success: true, event: newEvent });
});

app.get('/api/data', (req, res) => {
  if (!req.session.user) {
    return res.json({ success: false, error: 'Not logged in' });
  }
  
  const data = readData();
  res.json({
    success: true,
    user: req.session.user,
    announcements: data.announcements,
    events: data.events,
    chatMessages: data.chatMessages.slice(-50) // Last 50 messages
  });
});

app.get('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Socket.IO for real-time chat
io.on('connection', (socket) => {
  console.log('A user connected');
  
  socket.on('chat_message', (data) => {
    const chatMessage = {
      username: data.username,
      message: data.message,
      timestamp: new Date().toISOString()
    };
    
    // Save to data
    const dataStore = readData();
    dataStore.chatMessages.push(chatMessage);
    // Keep only last 100 messages
    if (dataStore.chatMessages.length > 100) {
      dataStore.chatMessages = dataStore.chatMessages.slice(-100);
    }
    writeData(dataStore);
    
    // Broadcast message to all clients
    io.emit('chat_message', chatMessage);
  });
  
  socket.on('disconnect', () => {
    console.log('User disconnected');
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`17 News RNG server running on port ${PORT}`);
});
