// static/js/chat.js
document.addEventListener('DOMContentLoaded', function() {
    // Common variables
    const messageContainer = document.getElementById('message-container');
    const chatForm = document.getElementById('chat-form');
    const messageInput = document.getElementById('message-input');
    const leaveGroupBtn = document.querySelector('.leave-group-btn');
    
    // Store sent message IDs to prevent duplicates
    const sentMessageIds = new Set();
    
    // Scroll to bottom of message container on load
    if (messageContainer) {
        messageContainer.scrollTop = messageContainer.scrollHeight;
    }
    
    // Handle leave group functionality
    if (leaveGroupBtn) {
        leaveGroupBtn.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Get confirmation from user
            if (confirm('Are you sure you want to leave this group?')) {
                // Get the URL from the href attribute
                const url = this.getAttribute('href');
                
                // Create a fetch request to leave the group
                fetch(url, {
                    method: 'GET',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                })
                .then(response => {
                    if (response.redirected) {
                        // If the server redirects, follow the redirect
                        window.location.href = response.url;
                    } else {
                        return response.json();
                    }
                })
                .then(data => {
                    if (data && data.success) {
                        // If the server returns a success JSON response
                        window.location.href = data.redirect_url;
                    }
                })
                .catch(error => {
                    console.error('Error leaving group:', error);
                    // Fallback to redirect to dashboard if there's an error
                    window.location.href = '/dashboard';
                });
            }
        });
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
    
    // Fetch new messages and group members periodically
    let lastMessageId = 0;
    const chatId = document.getElementById('chat-id')?.value;
    const chatType = document.getElementById('chat-type')?.value;
    const membersList = document.querySelector('.members-list');
    
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
        
        // If this is a group chat, also poll for member updates
        if (chatType === 'group' && membersList) {
            setInterval(() => {
                fetchGroupMembers(chatId);
            }, 5000); // Poll every 5 seconds
        }
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
    
    // Function to fetch group members
    function fetchGroupMembers(groupId) {
        const url = `/fetch_group_members/${groupId}`;
        const membersList = document.querySelector('.members-list');
        const memberCountEl = document.querySelector('.member-count');
        
        if (!membersList) return;
        
        fetch(url)
            .then(response => {
                // If we get a 403, it means we're no longer a member
                // Redirect to dashboard
                if (response.status === 403) {
                    window.location.href = '/dashboard';
                    return;
                }
                return response.json();
            })
            .then(data => {
                if (!data || !data.members) return;
                
                // Update member count if element exists
                if (memberCountEl) {
                    memberCountEl.textContent = data.count;
                }
                
                // Get current user ID from data attribute
                const currentUserId = parseInt(membersList.dataset.currentUserId);
                const isCreator = membersList.dataset.isCreator === 'True';
                
                // Clear and rebuild members list
                membersList.innerHTML = '';
                
                data.members.forEach(member => {
                    const listItem = document.createElement('li');
                    listItem.className = 'list-group-item px-0 py-2 d-flex justify-content-between align-items-center';
                    
                    // Create member name div with creator badge if applicable
                    const nameDiv = document.createElement('div');
                    nameDiv.textContent = member.username;
                    
                    if (member.is_creator) {
                        const creatorBadge = document.createElement('span');
                        creatorBadge.className = 'badge bg-primary ms-2';
                        creatorBadge.textContent = 'Creator';
                        nameDiv.appendChild(creatorBadge);
                    }
                    
                    listItem.appendChild(nameDiv);
                    
                    // Add remove button if current user is creator and member is not current user
                    if (isCreator && member.id !== currentUserId) {
                        const removeBtn = document.createElement('a');
                        removeBtn.href = `/remove_member/${groupId}/${member.id}`;
                        removeBtn.className = 'btn btn-danger btn-sm';
                        removeBtn.textContent = 'Remove';
                        removeBtn.onclick = function(e) {
                            e.preventDefault();
                            if (confirm(`Are you sure you want to remove ${member.username} from this group?`)) {
                                window.location.href = this.href;
                            }
                        };
                        
                        listItem.appendChild(removeBtn);
                    }
                    
                    membersList.appendChild(listItem);
                });
            })
            .catch(error => console.error('Error fetching group members:', error));
    }
});