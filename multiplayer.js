
// multiplayer.js
// Handles multiplayer logic using Socket.IO for 17 News RNG

const socketIo = require('socket.io');

function setupMultiplayer(server, readData, writeData) {
  const io = socketIo(server, {
    cors: {
      origin: '*',
      methods: ['GET', 'POST']
    }
  });

  io.on('connection', (socket) => {
    console.log('A user connected (multiplayer)', socket.id);

    socket.on('chat_message', (data) => {
      const chatMessage = {
        username: data.username,
        message: data.message,
        timestamp: new Date().toISOString()
      };
      // Save to data
      let dataStore = readData();
      dataStore.chatMessages.push(chatMessage);
      if (dataStore.chatMessages.length > 100) {
        dataStore.chatMessages = dataStore.chatMessages.slice(-100);
      }
      writeData(dataStore);
      io.emit('chat_message', chatMessage);
    });

    socket.on('disconnect', (reason) => {
      console.log(`User disconnected (multiplayer): ${socket.id} Reason: ${reason}`);
    });
  });

  return io;
}

module.exports = setupMultiplayer;

