/*
  Clean, minimal server for 17-News-RNG
  - Serves index.html and static files
  - Manages sessions (connect-sqlite3)
  - Reads/writes data/saveData.json with backup
  - API: /api/login, /api/register, /api/spin, /api/use-code, /api/admin/*, /api/data, /api/logout
  - Socket.IO broadcasts for chat, announcements, events
*/

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Middleware
app.use(express.static(__dirname));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-17news',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false },
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: './' })
}));

// Data file locations
const DATA_DIR = './data';
const DATA_FILE = path.join(DATA_DIR, 'saveData.json');
const BACKUP_DIR = path.join(DATA_DIR, 'backups');

// Ensure directories exist
function ensureDirs() {
  [DATA_DIR, BACKUP_DIR].forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); });
}

// Simple backup rotation
function createBackup() {
  try {
    if (!fs.existsSync(DATA_FILE)) return;
    const name = `saveData.backup.${Date.now()}.json`;
    fs.copyFileSync(DATA_FILE, path.join(BACKUP_DIR, name));
    const files = fs.readdirSync(BACKUP_DIR).filter(f => f.startsWith('saveData.backup')).sort().reverse();
    if (files.length > 5) files.slice(5).forEach(f => fs.unlinkSync(path.join(BACKUP_DIR, f)));
  } catch (e) {
    console.error('Backup error', e.message);
  }
}

// Initialize data if missing
function initializeData() {
  ensureDirs();
  if (!fs.existsSync(DATA_FILE)) {
    const initial = {
      users: [
        { username: 'Mr_Fernanski', password: bcrypt.hashSync('landex2008', 10), isAdmin: true, inventory: [], coins: 10000, joinDate: new Date().toISOString() }
      ],
      codes: [
        { code: 'WELCOME17', reward: { type: 'coins', amount: 500 }, usedBy: [] },
        { code: 'NEWS2023', reward: { type: 'item', item: 'Common Crate', rarity: 'common' }, usedBy: [] }
      ],
      announcements: [],
      events: [],
      aaEvents: [
        { id: 'disco', name: 'Disco', active: false }
      ],
      chatMessages: []
    };
    fs.writeFileSync(DATA_FILE, JSON.stringify(initial, null, 2));
  }
}

function readData() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch (e) {
    console.error('readData error:', e.message);
    // Try to recover by backing up and reinitializing
    try { if (fs.existsSync(DATA_FILE)) fs.copyFileSync(DATA_FILE, DATA_FILE + '.corrupt.' + Date.now()); } catch (e2) {}
    initializeData();
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  }
}

function validateDataShape(data) {
  return data && Array.isArray(data.users) && Array.isArray(data.codes) && Array.isArray(data.announcements) && Array.isArray(data.events) && Array.isArray(data.chatMessages);
}

function writeData(data) {
  if (!validateDataShape(data)) throw new Error('Invalid data shape');
  createBackup();
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, DATA_FILE);
}

// Simple rarity table
const RARITIES = [
  { name: 'Common', chance: 39, color: '#9e9e9e', coin: 10 },
  { name: 'Uncommon', chance: 25, color: '#4caf50', coin: 20 },
  { name: 'Rare', chance: 15, color: '#2196f3', coin: 50 },
  { name: 'Epic', chance: 10, color: '#9c27b0', coin: 120 },
  { name: 'Legendary', chance: 6, color: '#ff9800', coin: 300 },
  { name: 'Mythic', chance: 3, color: '#f44336', coin: 800 },
  { name: 'Divine', chance: 0.5, color: '#e91e63', coin: 2000 },
  // Explosive is a special rare cutscene-triggering rarity
  { name: 'Explosive', chance: 1.5, color: '#ffd700', coin: 0 }
];

function generateItemName(rarity) {
  const ADJ = ['Ancient','Glowing','Shiny','Rusty','Cyber','Arcane','Lucky'];
  const NOUN = ['Relic','Core','Shard','Crate','Module','Chip','Talisman'];
  const a = ADJ[Math.floor(Math.random()*ADJ.length)];
  const n = NOUN[Math.floor(Math.random()*NOUN.length)];
  return `${a} ${n} (${rarity})`;
}

// Auth helper
function requireAdmin(req, res, next) {
  if (!req.session?.user || !req.session.user.isAdmin) return res.status(403).json({ success: false, error: 'Unauthorized' });
  next();
}

// Routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.json({ success: false, error: 'Username and password required.' });
    const data = readData();
    const user = data.users.find(u => u.username === username);
    if (!user) return res.json({ success: false, error: 'User not found.' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.json({ success: false, error: 'Incorrect password.' });
    req.session.user = { username: user.username, isAdmin: !!user.isAdmin };
    return res.json({ success: true, user: { username: user.username, isAdmin: !!user.isAdmin, coins: user.coins, inventory: user.inventory } });
  } catch (e) {
    console.error('login error', e.message);
    return res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.json({ success: false, error: 'Username and password required.' });
    if (typeof username !== 'string' || typeof password !== 'string') return res.json({ success: false, error: 'Invalid types' });
    if (username.length < 3 || username.length > 20) return res.json({ success: false, error: 'Username length 3-20' });
    if (password.length < 6 || password.length > 50) return res.json({ success: false, error: 'Password length 6-50' });

    const data = readData();
    if (data.users.find(u => u.username === username)) return res.json({ success: false, error: 'Username already exists.' });
    const newUser = { username, password: bcrypt.hashSync(password, 10), isAdmin: false, inventory: [], coins: 1000, joinDate: new Date().toISOString() };
    data.users.push(newUser);
    writeData(data);
    req.session.user = { username: newUser.username, isAdmin: false };
    return res.json({ success: true, user: { username: newUser.username, isAdmin: false, coins: newUser.coins, inventory: newUser.inventory } });
  } catch (e) {
    console.error('register error', e.message);
    return res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.post('/api/spin', (req, res) => {
  try {
    if (!req.session.user) return res.json({ success: false, error: 'Not logged in' });
    const data = readData();
    const user = data.users.find(u => u.username === req.session.user.username);
    if (!user) return res.json({ success: false, error: 'User not found' });
    // Weighted rarity pick (supports floating chances)
    const total = RARITIES.reduce((s, x) => s + (x.chance || 0), 0);
    const roll = Math.random() * total;
    let cursor = 0;
    let picked = RARITIES[RARITIES.length - 1];
    for (const rr of RARITIES) {
      cursor += rr.chance;
      if (roll <= cursor) { picked = rr; break; }
    }

    const item = { name: generateItemName(picked.name), rarity: picked.name.toLowerCase(), date: new Date().toISOString() };
    user.inventory.push(item);
    // Award coin rewards for the spin (if defined)
    const discoActive = ((data.aaEvents || []).find(a => a.id === 'disco') || {}).active;
    const baseCoin = picked.coin || 0;
    const award = Math.round(baseCoin * (discoActive ? 2 : 1));
    user.coins = (user.coins || 0) + award;
    writeData(data);
    io.emit('refresh_data');

    // If Explosive, include cutscene flag for client-side animation
    const extra = {};
    if (picked.name === 'Explosive') { extra.cutscene = true; extra.cutsceneType = 'explosive'; }

    // include computed color and coin awarded
    return res.json({ success: true, rarity: picked, item: item.name, coins: user.coins, awarded: award, ...extra });
  } catch (e) {
    console.error('/api/spin', e.message);
    return res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.post('/api/use-code', (req, res) => {
  try {
    if (!req.session.user) return res.json({ success: false, error: 'Not logged in' });
    const { code } = req.body || {};
    if (!code) return res.json({ success: false, error: 'Code required' });
    const data = readData();
    const user = data.users.find(u => u.username === req.session.user.username);
    if (!user) return res.json({ success: false, error: 'User not found' });
    const cd = data.codes.find(c => c.code === code);
    if (!cd) return res.json({ success: false, error: 'Invalid code' });
    if (!Array.isArray(cd.usedBy)) cd.usedBy = [];
    if (cd.usedBy.includes(user.username)) return res.json({ success: false, error: 'Code already used' });
    if (cd.reward.type === 'coins') user.coins = (user.coins||0) + (cd.reward.amount||0);
    else if (cd.reward.type === 'item') user.inventory.push({ name: cd.reward.item, rarity: cd.reward.rarity || 'common', date: new Date().toISOString() });
    cd.usedBy.push(user.username);
    writeData(data);
    io.emit('refresh_data');
    return res.json({ success: true, message: 'Code redeemed' });
  } catch (e) {
    console.error('/api/use-code', e.message);
    return res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Simple shop buy endpoint
app.post('/api/shop/buy', (req, res) => {
  try {
    if (!req.session.user) return res.json({ success: false, error: 'Not logged in' });
    const { itemId, price, itemName, rarity } = req.body || {};
    if (!itemName || typeof price !== 'number') return res.json({ success: false, error: 'Invalid purchase' });
    const data = readData();
    const user = data.users.find(u => u.username === req.session.user.username);
    if (!user) return res.json({ success: false, error: 'User not found' });
    if ((user.coins || 0) < price) return res.json({ success: false, error: 'Not enough coins' });
    user.coins = (user.coins || 0) - price;
    user.inventory.push({ name: itemName, rarity: rarity || 'common', date: new Date().toISOString() });
    writeData(data);
    io.emit('refresh_data');
    return res.json({ success: true, message: 'Purchase complete', coins: user.coins });
  } catch (e) {
    console.error('/api/shop/buy', e.message);
    return res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.post('/api/admin/announcement', requireAdmin, (req, res) => {
  try {
    const { title, content } = req.body || {};
    if (!title || !content) return res.json({ success: false, error: 'Missing fields' });
    const data = readData();
    const ann = { id: Date.now(), title, content, date: new Date().toISOString(), author: req.session.user.username };
    data.announcements.push(ann);
    writeData(data);
    io.emit('new_announcement', ann);
    return res.json({ success: true, announcement: ann });
  } catch (e) {
    console.error('admin announcement', e.message);
    return res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.post('/api/admin/event', requireAdmin, (req, res) => {
  try {
    const { name, description, startDate, endDate, type, payload, applyNow } = req.body || {};
    if (!name || !startDate || !endDate) return res.json({ success: false, error: 'Missing fields' });
    const data = readData();
    const ev = { id: Date.now(), name, description: description||'', startDate, endDate, type: type||'custom', payload: payload||{}, active: false };
    data.events.push(ev);
    writeData(data);
    io.emit('new_event', ev);
    if (applyNow) {
      // simple immediate apply: give item/coins depending on type
      if (ev.type === 'meteor_shower') data.users.forEach(u => u.coins = (u.coins||0) + (ev.payload?.amount||500));
      else if (ev.type === 'treasure_flood') data.users.forEach(u => u.inventory.push({ name: ev.payload?.itemName||'Common Crate', rarity: 'common', date: new Date().toISOString() }));
      writeData(data);
      io.emit('refresh_data');
    }
    return res.json({ success: true, event: ev });
  } catch (e) {
    console.error('admin event', e.message);
    return res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/data', (req, res) => {
  try {
    if (!req.session.user) return res.json({ success: false, error: 'Not logged in' });
  const data = readData();
  const fullUser = data.users.find(u => u.username === req.session.user.username);
  const safeUser = fullUser ? { username: fullUser.username, isAdmin: fullUser.isAdmin, coins: fullUser.coins || 0, inventory: fullUser.inventory || [] } : req.session.user;
  return res.json({ success: true, user: safeUser, announcements: data.announcements, events: data.events, chatMessages: data.chatMessages.slice(-50), aaEvents: data.aaEvents || [] });
  } catch (e) {
    console.error('/api/data', e.message);
    return res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/logout', (req, res) => { req.session.destroy(() => {}); res.json({ success: true }); });

// Admin helper: rebroadcast last announcement
app.post('/api/admin/rebroadcast-last-announcement', requireAdmin, (req, res) => {
  try {
    const data = readData();
    const last = (data.announcements || []).slice(-1)[0];
    if (!last) return res.json({ success: false, error: 'No announcements' });
    io.emit('new_announcement', last);
    io.emit('chat_message', { username: 'Server', message: `${last.title} — ${last.content}`, timestamp: new Date().toISOString() });
    return res.json({ success: true });
  } catch (e) {
    console.error('rebroadcast', e.message);
    return res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Admin helper: apply all active events now
app.post('/api/admin/apply-active-events', requireAdmin, (req, res) => {
  try {
    const data = readData();
    const active = (data.events || []).filter(ev => ev.active || (new Date(ev.startDate) <= new Date() && new Date(ev.endDate) >= new Date()));
    if (!active.length) return res.json({ success: false, error: 'No active events' });
    active.forEach(ev => {
      // simple apply logic
      if (ev.type === 'meteor_shower') data.users.forEach(u => u.coins = (u.coins||0) + (ev.payload?.amount || 500));
      else if (ev.type === 'treasure_flood') data.users.forEach(u => u.inventory.push({ name: ev.payload?.itemName || 'Common Crate', rarity: 'common', date: new Date().toISOString() }));
      else if (ev.type === 'rare_storm') data.users.forEach(u => u.inventory.push({ name: generateItemName('Rare'), rarity: 'rare', date: new Date().toISOString() }));
      // mark applied (non-destructive)
    });
    writeData(data);
    io.emit('refresh_data');
    io.emit('new_event', { name: 'Admin applied events', description: `${active.length} events applied`, date: new Date().toISOString() });
    return res.json({ success: true, applied: active.length });
  } catch (e) {
    console.error('apply-active-events', e.message);
    return res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Admin: toggle AA Event (Disco)
app.post('/api/admin/aa-event', requireAdmin, (req, res) => {
  try {
    const { id, action } = req.body || {};
    const data = readData();
    const ev = (data.aaEvents || []).find(a => a.id === id);
    if (!ev) return res.json({ success: false, error: 'AA Event not found' });
    if (action === 'start') ev.active = true;
    else if (action === 'stop') ev.active = false;
    else return res.json({ success: false, error: 'Invalid action' });
    writeData(data);
    // Broadcast disco start/stop
    io.emit('aa_event', { id: ev.id, name: ev.name, active: ev.active });
    return res.json({ success: true, event: ev });
  } catch (e) { console.error('aa-event', e.message); return res.status(500).json({ success: false, error: 'Internal server error' }); }
});

// Socket.IO chat
io.on('connection', socket => {
  socket.on('chat_message', msg => {
    try {
      const data = readData();
      data.chatMessages.push({ username: msg.username, message: msg.message, timestamp: new Date().toISOString() });
      if (data.chatMessages.length > 100) data.chatMessages = data.chatMessages.slice(-100);
      writeData(data);
      io.emit('chat_message', { username: msg.username, message: msg.message, timestamp: new Date().toISOString() });
    } catch (e) { console.error('socket chat', e.message); }
  });
});

// Start
initializeData();
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`17 News RNG 2 server running on port ${PORT}`));
