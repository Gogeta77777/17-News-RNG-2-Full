const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Middleware
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  secret: '17-news-rng-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Data file paths
const USERS_FILE = './data/users.json';
const CODES_FILE = './data/codes.json';
const ANNOUNCEMENTS_FILE = './data/announcements.json';
const EVENTS_FILE = './data/events.json';

// Initialize data files if they don't exist
function initializeDataFiles() {
  if (!fs.existsSync('./data')) fs.mkdirSync('./data');
  
  if (!fs.existsSync(USERS_FILE)) {
    const adminUser = {
      username: 'Mr_Fernanski',
      password: bcrypt.hashSync('admin123', 10),
      isAdmin: true,
      inventory: [],
      coins: 10000,
      joinDate: new Date().toISOString()
    };
    fs.writeFileSync(USERS_FILE, JSON.stringify([adminUser], null, 2));
  }
  
  if (!fs.existsSync(CODES_FILE)) {
    const initialCodes = [
      { code: 'WELCOME17', reward: { type: 'coins', amount: 500 }, usedBy: [] },
      { code: 'NEWS2023', reward: { type: 'item', item: 'Common Crate', rarity: 'common' }, usedBy: [] }
    ];
    fs.writeFileSync(CODES_FILE, JSON.stringify(initialCodes, null, 2));
  }
  
  if (!fs.existsSync(ANNOUNCEMENTS_FILE)) {
    fs.writeFileSync(ANNOUNCEMENTS_FILE, JSON.stringify([], null, 2));
  }
  
  if (!fs.existsSync(EVENTS_FILE)) {
    fs.writeFileSync(EVENTS_FILE, JSON.stringify([], null, 2));
  }
}

initializeDataFiles();

// Utility functions for data management
function readJSON(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function writeJSON(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

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

// Routes
app.get('/', (req, res) => {
  if (req.session.user) {
    res.redirect('/game');
  } else {
    res.render('index');
  }
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.username === username);
  
  if (user && bcrypt.compareSync(password, user.password)) {
    req.session.user = user;
    res.redirect('/game');
  } else {
    res.render('login', { error: 'Invalid username or password' });
  }
});

app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const users = readJSON(USERS_FILE);
  
  if (users.find(u => u.username === username)) {
    res.render('register', { error: 'Username already exists' });
  } else {
    const newUser = {
      username,
      password: bcrypt.hashSync(password, 10),
      isAdmin: false,
      inventory: [],
      coins: 1000,
      joinDate: new Date().toISOString()
    };
    
    users.push(newUser);
    writeJSON(USERS_FILE, users);
    
    req.session.user = newUser;
    res.redirect('/game');
  }
});

app.get('/game', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  
  const user = req.session.user;
  const announcements = readJSON(ANNOUNCEMENTS_FILE);
  const events = readJSON(EVENTS_FILE);
  
  res.render('game', { 
    user, 
    rarities: RARITIES,
    announcements,
    events
  });
});

app.get('/admin', (req, res) => {
  if (!req.session.user || !req.session.user.isAdmin) {
    return res.redirect('/game');
  }
  
  const announcements = readJSON(ANNOUNCEMENTS_FILE);
  const events = readJSON(EVENTS_FILE);
  const codes = readJSON(CODES_FILE);
  
  res.render('admin', { 
    user: req.session.user,
    announcements,
    events,
    codes
  });
});

app.post('/admin/announcement', (req, res) => {
  if (!req.session.user || !req.session.user.isAdmin) {
    return res.redirect('/game');
  }
  
  const { title, content } = req.body;
  const announcements = readJSON(ANNOUNCEMENTS_FILE);
  
  announcements.push({
    id: Date.now(),
    title,
    content,
    date: new Date().toISOString(),
    author: req.session.user.username
  });
  
  writeJSON(ANNOUNCEMENTS_FILE, announcements);
  
  // Broadcast to all connected clients
  io.emit('new_announcement', {
    title,
    content,
    author: req.session.user.username
  });
  
  res.redirect('/admin');
});

app.post('/admin/event', (req, res) => {
  if (!req.session.user || !req.session.user.isAdmin) {
    return res.redirect('/game');
  }
  
  const { name, description, startDate, endDate } = req.body;
  const events = readJSON(EVENTS_FILE);
  
  events.push({
    id: Date.now(),
    name,
    description,
    startDate,
    endDate,
    active: new Date() >= new Date(startDate) && new Date() <= new Date(endDate)
  });
  
  writeJSON(EVENTS_FILE, events);
  
  // Broadcast to all connected clients
  io.emit('new_event', {
    name,
    description
  });
  
  res.redirect('/admin');
});

app.post('/use-code', (req, res) => {
  if (!req.session.user) {
    return res.json({ success: false, message: 'Not logged in' });
  }
  
  const { code } = req.body;
  const codes = readJSON(CODES_FILE);
  const users = readJSON(USERS_FILE);
  
  const codeData = codes.find(c => c.code === code);
  const userIndex = users.findIndex(u => u.username === req.session.user.username);
  
  if (!codeData) {
    return res.json({ success: false, message: 'Invalid code' });
  }
  
  if (codeData.usedBy.includes(req.session.user.username)) {
    return res.json({ success: false, message: 'Code already used' });
  }
  
  // Apply reward
  if (codeData.reward.type === 'coins') {
    users[userIndex].coins += codeData.reward.amount;
  } else if (codeData.reward.type === 'item') {
    users[userIndex].inventory.push({
      name: codeData.reward.item,
      rarity: codeData.reward.rarity,
      date: new Date().toISOString()
    });
  }
  
  codeData.usedBy.push(req.session.user.username);
  
  writeJSON(USERS_FILE, users);
  writeJSON(CODES_FILE, codes);
  
  // Update session
  req.session.user = users[userIndex];
  
  res.json({ 
    success: true, 
    message: `Code redeemed! Received: ${codeData.reward.type === 'coins' 
      ? codeData.reward.amount + ' coins' 
      : codeData.reward.item}` 
  });
});

app.post('/spin', (req, res) => {
  if (!req.session.user) {
    return res.json({ success: false, message: 'Not logged in' });
  }
  
  const users = readJSON(USERS_FILE);
  const userIndex = users.findIndex(u => u.username === req.session.user.username);
  
  if (users[userIndex].coins < 100) {
    return res.json({ success: false, message: 'Not enough coins' });
  }
  
  // Deduct coins
  users[userIndex].coins -= 100;
  
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
  users[userIndex].inventory.push({
    name: itemName,
    rarity: selectedRarity.name.toLowerCase(),
    date: new Date().toISOString()
  });
  
  writeJSON(USERS_FILE, users);
  
  // Update session
  req.session.user = users[userIndex];
  
  res.json({ 
    success: true, 
    rarity: selectedRarity,
    item: itemName,
    coins: users[userIndex].coins
  });
});

// Socket.IO for real-time chat
io.on('connection', (socket) => {
  console.log('A user connected');
  
  socket.on('chat_message', (data) => {
    // Broadcast message to all clients
    io.emit('chat_message', {
      username: data.username,
      message: data.message,
      timestamp: new Date().toISOString()
    });
  });
  
  socket.on('disconnect', () => {
    console.log('User disconnected');
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`17 News RNG server running on port ${PORT}`);
});
