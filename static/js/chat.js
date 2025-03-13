// static/js/chat.js
document.addEventListener('DOMContentLoaded', function() {
    // Common variables
    const messageContainer = document.getElementById('message-container');
    const chatForm = document.getElementById('chat-form');
    const messageInput = document.getElementById('message-input');
    
    // Store sent message IDs to prevent duplicates
    const sentMessageIds = new Set();
    
    // Scroll to bottom of message container on load
    if (messageContainer) {
        messageContainer.scrollTop = messageContainer.scrollHeight;
    }
    
    // Handle chat form submission via AJAX
    if (chatForm) {
        chatForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Get the message content
            const message = messageInput.value.trim();
            if (!message) return;
            
            // Get form action (URL)
            const url = chatForm.getAttribute('action');
            
            // Create form data
            const formData = new FormData();
            formData.append('message', message);
            
            // Clear input field immediately (better UX)
            messageInput.value = '';
            
            // Send POST request
            fetch(url, {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Add message ID to the set of sent messages
                    sentMessageIds.add(data.message.id);
                    
                    // Append new message to container
                    appendMessage(data.message);
                    
                    // Scroll to bottom
                    messageContainer.scrollTop = messageContainer.scrollHeight;
                }
            })
            .catch(error => console.error('Error:', error));
        });
    }
    
    // Function to append a new message to the container
    function appendMessage(message) {
        // Check if we already have this message displayed (prevent duplicates)
        if (document.querySelector(`.message[data-message-id="${message.id}"]`)) {
            return;
        }
        
        const messageDiv = document.createElement('div');
        
        // Add appropriate classes based on sender
        if (message.is_own) {
            messageDiv.className = 'message sent-message';
            messageDiv.innerHTML = `
                <div class="message-content">${message.content}</div>
                <div class="message-time text-muted small text-end">${message.timestamp}</div>
            `;
        } else {
            messageDiv.className = 'message received-message';
            messageDiv.innerHTML = `
                <div><strong>${message.sender}</strong></div>
                <div class="message-content">${message.content}</div>
                <div class="message-time text-muted small">${message.timestamp}</div>
            `;
        }
        
        // Add message ID as data attribute
        messageDiv.setAttribute('data-message-id', message.id);
        
        // Add animation class
        messageDiv.classList.add('new-message');
        
        // Append to container
        messageContainer.appendChild(messageDiv);
    }
    
    // Fetch new messages periodically
    let lastMessageId = 0;
    const chatId = document.getElementById('chat-id')?.value;
    const chatType = document.getElementById('chat-type')?.value;
    
    if (chatId && chatType && messageContainer) {
        // Find the last message ID
        const allMessages = document.querySelectorAll('.message');
        if (allMessages.length > 0) {
            const lastMessage = allMessages[allMessages.length - 1];
            lastMessageId = parseInt(lastMessage.dataset.messageId) || 0;
        }
        
        // Set up polling for new messages
        setInterval(() => {
            fetchNewMessages(chatId, chatType, lastMessageId);
        }, 3000); // Poll every 3 seconds
    }
    
    // Function to fetch new messages
    function fetchNewMessages(id, type, lastId) {
        const url = `/fetch_messages?type=${type}&id=${id}&last_id=${lastId}`;
        
        fetch(url)
            .then(response => response.json())
            .then(data => {
                if (data.messages && data.messages.length > 0) {
                    // Add each new message
                    data.messages.forEach(message => {
                        // Skip messages we've sent ourselves (to avoid duplicates)
                        if (sentMessageIds.has(message.id)) {
                            return;
                        }
                        
                        appendMessage(message);
                        
                        // Update last message ID
                        if (message.id > lastMessageId) {
                            lastMessageId = message.id;
                        }
                    });
                    
                    // Scroll to bottom if user was already at the bottom
                    const isAtBottom = messageContainer.scrollHeight - messageContainer.clientHeight <= messageContainer.scrollTop + 100;
                    if (isAtBottom) {
                        messageContainer.scrollTop = messageContainer.scrollHeight;
                    }
                }
            })
            .catch(error => console.error('Error fetching messages:', error));
    }
});