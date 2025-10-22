
// multiplayer.js
// Enhanced multiplayer logic with rate limiting and better state management

const socketIo = require('socket.io');

function setupMultiplayer(server, readData, writeData) {
  const io = socketIo(server, {
    cors: {
      origin: '*',
      methods: ['GET', 'POST']
    }
  });

  // Rate limiting
  const rateLimits = new Map();
  const RATE_LIMIT_WINDOW = 1000; // 1 second
  const CHAT_LIMIT = 1; // messages per window
  const EVENT_LIMIT = 2; // events per window

  function checkRateLimit(id, type) {
    const now = Date.now();
    const key = `${id}:${type}`;
    const userLimits = rateLimits.get(key) || { count: 0, resetTime: now };

    if (now > userLimits.resetTime) {
      userLimits.count = 1;
      userLimits.resetTime = now + RATE_LIMIT_WINDOW;
      rateLimits.set(key, userLimits);
      return true;
    }

    if (userLimits.count >= (type === 'chat' ? CHAT_LIMIT : EVENT_LIMIT)) {
      return false;
    }

    userLimits.count++;
    return true;
  }

  // Connected users tracking
  const connectedUsers = new Map();

  io.on('connection', (socket) => {
    console.log('A user connected (multiplayer)', socket.id);

    // Authentication required before allowing other actions
    socket.on('authenticate', (userData) => {
      if (!userData.username || !userData.sessionId) {
        socket.disconnect();
        return;
      }

      connectedUsers.set(socket.id, {
        username: userData.username,
        lastActive: Date.now()
      });

      // Send initial state
      const data = readData();
      socket.emit('initial_state', {
        chatMessages: data.chatMessages.slice(-50),
        announcements: data.announcements.slice(-10),
        activeEvents: data.events.filter(e => e.active)
      });
    });

    socket.on('chat_message', (data) => {
      const user = connectedUsers.get(socket.id);
      if (!user) {
        socket.emit('error', { message: 'Authentication required' });
        return;
      }

      if (!checkRateLimit(socket.id, 'chat')) {
        socket.emit('error', { message: 'You are sending messages too quickly' });
        return;
      }

      // Sanitize message
      const message = (data.message || '').trim().slice(0, 500);
      if (!message) return;

      const chatMessage = {
        username: user.username,
        message: message,
        timestamp: new Date().toISOString()
      };

      try {
        // Save to data
        let dataStore = readData();
        dataStore.chatMessages.push(chatMessage);
        if (dataStore.chatMessages.length > 100) {
          dataStore.chatMessages = dataStore.chatMessages.slice(-100);
        }
        writeData(dataStore);
        
        // Broadcast to all clients
        io.emit('chat_message', chatMessage);
      } catch (error) {
        console.error('Failed to save chat message:', error);
        socket.emit('error', { message: 'Failed to save message' });
      }
    });

    // Handle real-time events with rate limiting
    socket.on('game_event', (eventData) => {
      const user = connectedUsers.get(socket.id);
      if (!user) {
        socket.emit('error', { message: 'Authentication required' });
        return;
      }

      if (!checkRateLimit(socket.id, 'event')) {
        socket.emit('error', { message: 'Too many actions, please wait' });
        return;
      }

      // Add user context to event
      const enrichedEvent = {
        ...eventData,
        username: user.username,
        timestamp: new Date().toISOString()
      };

      io.emit('game_event', enrichedEvent);
    });

    // Handle announcements (admin only)
    socket.on('announcement', (announcement) => {
      const user = connectedUsers.get(socket.id);
      if (!user) return;

      // Verify admin status from data store
      const data = readData();
      const userRecord = data.users.find(u => u.username === user.username);
      if (!userRecord?.isAdmin) return;

      io.emit('announcement', {
        ...announcement,
        timestamp: new Date().toISOString(),
        author: user.username
      });
    });

    // Clean up on disconnect
    socket.on('disconnect', (reason) => {
      console.log(`User disconnected (multiplayer): ${socket.id} Reason: ${reason}`);
      connectedUsers.delete(socket.id);
      
      // Clean up rate limits
      for (const key of rateLimits.keys()) {
        if (key.startsWith(socket.id)) {
          rateLimits.delete(key);
        }
      }
    });
  });

  return io;
}

module.exports = setupMultiplayer;

