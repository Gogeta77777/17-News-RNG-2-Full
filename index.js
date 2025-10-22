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

// Security middleware
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

// Rate limiting for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5 // limit each IP to 5 requests per windowMs
});

// Middleware
app.use(helmet()); // Add security headers
app.use(express.static(__dirname));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Enhanced session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-17news',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  },
  store: new SQLiteStore({ 
    db: 'sessions.sqlite', 
    dir: process.env.NODE_ENV === 'production' ? '/tmp' : './',
    concurrentDB: true // Handle concurrent access
  })
}));

// Data file locations
// Data directories - use tmp for platforms that need writable directories
const DATA_DIR = process.env.NODE_ENV === 'production' ? '/tmp/data' : path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'saveData.json');
const BACKUP_DIR = path.join(DATA_DIR, 'backups');

// Ensure directories exist and handle legacy data
function ensureDirs() {
  // Create directories if missing
  [DATA_DIR, BACKUP_DIR].forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); });
  
  // Check for legacy saveData.json in root and migrate if needed
  const legacyPath = path.join(__dirname, 'saveData.json');
  if (fs.existsSync(legacyPath)) {
    try {
      // If we have a legacy file but no data/saveData.json, migrate it
      if (!fs.existsSync(DATA_FILE)) {
        console.log('Migrating legacy saveData.json to data directory...');
        fs.copyFileSync(legacyPath, DATA_FILE);
        // Create a backup of the legacy file with timestamp
        const backupName = `saveData.legacy.${Date.now()}.json`;
        fs.copyFileSync(legacyPath, path.join(BACKUP_DIR, backupName));
        // Don't delete legacy file - let admin do that manually
        console.log('Migration complete. Legacy file preserved at root.');
      }
    } catch (e) {
      console.error('Legacy data migration failed:', e.message);
    }
  }
}

// Enhanced backup rotation with safety checks
function createBackup() {
  try {
    if (!fs.existsSync(DATA_FILE)) return;
    
    // Verify current data is valid JSON before backing up
    try {
      const data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      if (!validateDataShape(data)) {
        throw new Error('Invalid data shape');
      }
    } catch (e) {
      console.error('Invalid data file, skipping backup:', e.message);
      return;
    }

    // Create timestamped backup
    const name = `saveData.backup.${Date.now()}.json`;
    fs.copyFileSync(DATA_FILE, path.join(BACKUP_DIR, name));
    
    // Rotate backups (keep 5 most recent)
    const files = fs.readdirSync(BACKUP_DIR)
      .filter(f => f.startsWith('saveData.backup'))
      .sort()
      .reverse();
      
    if (files.length > 5) {
      files.slice(5).forEach(f => {
        try {
          fs.unlinkSync(path.join(BACKUP_DIR, f));
        } catch (e) {
          console.error('Error removing old backup:', e.message);
        }
      });
    }
  } catch (e) {
    console.error('Backup error:', e.message);
  }
}

// Initialize data if missing
function initializeData() {
  ensureDirs();
  // If the app previously stored a top-level saveData.json (older versions), migrate it
  const legacyRoot = path.join(__dirname, 'saveData.json');
  if (!fs.existsSync(DATA_FILE) && fs.existsSync(legacyRoot)) {
    try {
      fs.copyFileSync(legacyRoot, DATA_FILE);
      console.log('Migrated legacy saveData.json into data/saveData.json');
    } catch (e) {
      console.error('Migration error:', e.message);
    }
  }

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

// Enhanced data reading with retries
function readData() {
  const maxRetries = 3;
  let lastError = null;

  for (let i = 0; i < maxRetries; i++) {
    try {
      const data = fs.readFileSync(DATA_FILE, 'utf8');
      const parsed = JSON.parse(data);
      
      if (!validateDataShape(parsed)) {
        throw new Error('Invalid data shape');
      }
      
      return parsed;
    } catch (e) {
      console.error(`Read attempt ${i + 1} failed:`, e);
      lastError = e;
      
      // Try to restore from backup if file read fails
      if (e.code === 'ENOENT' || e.name === 'SyntaxError') {
        const restored = tryRestoreFromBackup();
        if (restored) return restored;
      }
      
      // Small delay before retry
      if (i < maxRetries - 1) {
        require('timers').setTimeout(() => {}, 100 * Math.pow(2, i));
      }
    }
  }
  
  throw new Error(`Failed to read data after ${maxRetries} attempts: ${lastError}`);
}

function validateDataShape(data) {
  if (!data || typeof data !== 'object') return false;
  
  const requiredArrays = ['users', 'codes', 'announcements', 'events', 'chatMessages'];
  return requiredArrays.every(key => 
    Array.isArray(data[key]) && 
    data[key].every(item => item && typeof item === 'object')
  );
}

// Try to restore from most recent backup
function tryRestoreFromBackup() {
  try {
    const backups = fs.readdirSync(BACKUP_DIR)
      .filter(f => f.startsWith('backup-'))
      .sort()
      .reverse();
    
    for (const backup of backups) {
      try {
        const data = fs.readFileSync(path.join(BACKUP_DIR, backup), 'utf8');
        const parsed = JSON.parse(data);
        
        if (validateDataShape(parsed)) {
          // Found valid backup, restore it
          fs.copyFileSync(path.join(BACKUP_DIR, backup), DATA_FILE);
          return parsed;
        }
      } catch (e) {
        console.error('Backup restore failed:', backup, e);
        continue;
      }
    }
  } catch (e) {
    console.error('Backup directory read failed:', e);
  }
  return null;
}

// Atomic write with temporary file
function writeData(data) {
  if (!validateDataShape(data)) {
    throw new Error('Invalid data shape');
  }
  
  ensureDirs();
  createBackup();
  
  const tempFile = `${DATA_FILE}.tmp`;
  try {
    // Write to temp file first
    fs.writeFileSync(tempFile, JSON.stringify(data, null, 2));
    
    // Atomic rename
    fs.renameSync(tempFile, DATA_FILE);
    
    return true;
  } catch (e) {
    console.error('Write failed:', e);
    // Clean up temp file if it exists
    try {
      if (fs.existsSync(tempFile)) {
        fs.unlinkSync(tempFile);
      }
    } catch (cleanupError) {
      console.error('Failed to clean up temp file:', cleanupError);
    }
    throw e;
  }
}

function validateDataShape(data) {
  return data && Array.isArray(data.users) && Array.isArray(data.codes) && Array.isArray(data.announcements) && Array.isArray(data.events) && Array.isArray(data.chatMessages);
}

function writeData(data) {
  if (!validateDataShape(data)) throw new Error('Invalid data shape');
  
  // Always ensure directories exist
  ensureDirs();
  
  // Create backup first
  createBackup();
  
  try {
    // Write to temp file first
    const tmp = DATA_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
    
    // Verify the written data is valid JSON
    const verify = JSON.parse(fs.readFileSync(tmp, 'utf8'));
    if (!validateDataShape(verify)) {
      throw new Error('Written data validation failed');
    }
    
    // If verification passed, do the atomic rename
    fs.renameSync(tmp, DATA_FILE);
  } catch (e) {
    console.error('writeData error:', e.message);
    // Clean up temp file if it exists
    try {
      const tmp = DATA_FILE + '.tmp';
      if (fs.existsSync(tmp)) fs.unlinkSync(tmp);
    } catch (e2) {}
    throw e; // Re-throw to let caller handle
  }
}

// Special 17 News rarity table
const RARITIES = [
  { name: '17 News', chance: 45, color: '#4CAF50', coin: 100 },
  { name: '17 News Reborn', chance: 30, color: '#2196F3', coin: 250 },
  { name: 'Delan Fernando', chance: 15, color: '#9C27B0', coin: 500 },
  { name: 'Cooper Metson', chance: 8, color: '#FF9800', coin: 1000 },
  { name: 'Mr Fernanski', chance: 2, color: '#F44336', coin: 2500 }
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

// Input validation
function validateUsername(username) {
  return typeof username === 'string' && 
         username.length >= 3 && 
         username.length <= 20 &&
         /^[a-zA-Z0-9_-]+$/.test(username);
}

function validatePassword(password) {
  return typeof password === 'string' && 
         password.length >= 6 &&
         password.length <= 100;
}

app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!validateUsername(username) || !validatePassword(password)) {
      return res.status(400).json({ error: 'Invalid username or password format' });
    }

    const data = readData();
    const user = data.users.find(u => u.username.toLowerCase() === username.toLowerCase());

    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Set session
    req.session.userId = user.username;
    req.session.isAdmin = user.isAdmin;

    // Don't send password back
    const { password: _, ...safeUser } = user;
    res.json(safeUser);
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!validateUsername(username)) {
      return res.status(400).json({ 
        error: 'Username must be 3-20 characters and contain only letters, numbers, underscores, and hyphens' 
      });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({ 
        error: 'Password must be 6-100 characters' 
      });
    }

    const data = readData();

    // Check for existing username
    if (data.users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
      return res.status(409).json({ error: 'Username already taken' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    const newUser = {
      username,
      password: hashedPassword,
      isAdmin: false,
      inventory: [],
      coins: 0,
      joinDate: new Date().toISOString()
    };

    // Add user atomically
    data.users.push(newUser);
    writeData(data);

    // Set session
    req.session.userId = username;
    req.session.isAdmin = false;

    // Don't send password back
    const { password: _, ...safeUser } = newUser;
    res.json(safeUser);
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
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
