// Chat functionality
document.addEventListener('DOMContentLoaded', function() {
    const socket = io();
    const chatMessages = document.getElementById('chat-messages');
    const chatInput = document.getElementById('chat-input');
    const sendBtn = document.getElementById('send-btn');
    
    // Focus chat input when chat tab is active
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            if (btn.getAttribute('data-tab') === 'chat') {
                setTimeout(() => {
                    chatInput.focus();
                }, 100);
            }
        });
    });
    
    // Send message function
    function sendMessage() {
        const message = chatInput.value.trim();
        if (message) {
            socket.emit('chat_message', {
                username: document.querySelector('.user-info strong').textContent,
                message: message
            });
            chatInput.value = '';
        }
    }
    
    // Send message on button click
    if (sendBtn) {
        sendBtn.addEventListener('click', sendMessage);
    }
    
    // Send message on Enter key
    if (chatInput) {
        chatInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });
    }
    
    // Receive messages
    socket.on('chat_message', (data) => {
        const messageElement = document.createElement('div');
        messageElement.className = 'chat-message';
        messageElement.innerHTML = `
            <span class="username">${data.username}:</span>
            <span class="message">${data.message}</span>
            <br>
            <small class="timestamp">${new Date(data.timestamp).toLocaleTimeString()}</small>
        `;
        
        if (chatMessages) {
            chatMessages.appendChild(messageElement);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }
    });
    
    // Handle announcements from admin
    socket.on('new_announcement', (data) => {
        // Show notification or update announcements tab
        if (Notification.permission === 'granted') {
            new Notification('New Announcement', {
                body: `${data.title}: ${data.content}`
            });
        } else if (Notification.permission !== 'denied') {
            Notification.requestPermission().then(permission => {
                if (permission === 'granted') {
                    new Notification('New Announcement', {
                        body: `${data.title}: ${data.content}`
                    });
                }
            });
        }
        
        // If on announcements tab, refresh content
        if (document.getElementById('announcements-tab').classList.contains('active')) {
            // In a real app, you might fetch updated announcements
            // For simplicity, we'll just reload
            location.reload();
        }
    });
    
    // Handle new events from admin
    socket.on('new_event', (data) => {
        // Show notification
        if (Notification.permission === 'granted') {
            new Notification('New Event', {
                body: `${data.name}: ${data.description}`
            });
        }
        
        // If on events tab, refresh content
        if (document.getElementById('events-tab').classList.contains('active')) {
            location.reload();
        }
    });
    
    // Request notification permission
    if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission();
    }
});
