const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Middleware
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: '17-news-rng-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

// Data management
const DATA_FILE = './saveData.json';

function initializeData() {
  if (!fs.existsSync(DATA_FILE)) {
    const initialData = {
      users: [
        {
          username: 'Mr_Fernanski',
          password: bcrypt.hashSync('admin123', 10),
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
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
}

function writeData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

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

// Serve main page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// API Routes
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const data = readData();
  const user = data.users.find(u => u.username === username);
  
  if (user && bcrypt.compareSync(password, user.password)) {
    req.session.user = user;
    res.json({ success: true, user: { ...user, password: undefined } });
  } else {
    res.json({ success: false, error: 'Invalid username or password' });
  }
});

app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  const data = readData();
  
  if (data.users.find(u => u.username === username)) {
    res.json({ success: false, error: 'Username already exists' });
  } else {
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
  }
});

app.post('/api/spin', (req, res) => {
  if (!req.session.user) {
    return res.json({ success: false, error: 'Not logged in' });
  }
  
  const data = readData();
  const userIndex = data.users.findIndex(u => u.username === req.session.user.username);
  
  if (data.users[userIndex].coins < 100) {
    return res.json({ success: false, error: 'Not enough coins' });
  }
  
  // Deduct coins
  data.users[userIndex].coins -= 100;
  
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
    coins: data.users[userIndex].coins
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
  
  const { name, description, startDate, endDate } = req.body;
  const data = readData();
  
  data.events.push({
    id: Date.now(),
    name,
    description,
    startDate,
    endDate,
    active: new Date() >= new Date(startDate) && new Date() <= new Date(endDate)
  });
  
  writeData(data);
  
  // Broadcast to all connected clients
  io.emit('new_event', {
    name,
    description
  });
  
  res.json({ success: true });
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
