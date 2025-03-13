# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20), default='info')  # info, success, warning, danger
    related_to = db.Column(db.String(20), nullable=True)  # group, user, etc.
    related_id = db.Column(db.Integer, nullable=True)  # ID of related entity
    read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'content': self.content,
            'type': self.type,
            'related_to': self.related_to,
            'related_id': self.related_id,
            'read': self.read,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        }

# Database models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    profile_picture = db.Column(db.String(120), default='default.jpg')
    bio = db.Column(db.String(200), default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(200))
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Define a relationship to access members
    members = db.relationship('User', secondary='group_member',
                             backref=db.backref('groups', lazy='dynamic'))

class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

class PrivateMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)

class GroupMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


def create_notification(user_id, content, notification_type='info', related_to=None, related_id=None):
    """Create a notification for a user"""
    notification = Notification(
        user_id=user_id,
        content=content,
        type=notification_type,
        related_to=related_to,
        related_id=related_id
    )
    db.session.add(notification)
    db.session.commit()
    return notification

def notify_group_member_added(group_id, added_user_id, added_by_id):
    """Notify all group members when a new member is added"""
    group = Group.query.get(group_id)
    added_user = User.query.get(added_user_id)
    added_by = User.query.get(added_by_id)
    
    # Notify the added user
    content = f"You were added to the group '{group.name}' by {added_by.username}"
    create_notification(added_user_id, content, 'success', 'group', group_id)
    
    # Notify all other group members
    for member in group.members:
        if member.id != added_user_id and member.id != added_by_id:
            content = f"{added_user.username} was added to the group '{group.name}' by {added_by.username}"
            create_notification(member.id, content, 'info', 'group', group_id)

def notify_group_member_removed(group_id, removed_user_id, removed_by_id=None):
    """Notify relevant users when a member is removed from a group"""
    group = Group.query.get(group_id)
    removed_user = User.query.get(removed_user_id)
    
    # If removed by someone else (not self-leave)
    if removed_by_id and removed_by_id != removed_user_id:
        removed_by = User.query.get(removed_by_id)
        
        # Notify the removed user
        content = f"You were removed from the group '{group.name}' by {removed_by.username}"
        create_notification(removed_user_id, content, 'warning', 'group', group_id)
        
        # Notify all other group members
        for member in group.members:
            if member.id != removed_user_id and member.id != removed_by_id:
                content = f"{removed_user.username} was removed from the group '{group.name}' by {removed_by.username}"
                create_notification(member.id, content, 'info', 'group', group_id)
    
    # If the user left the group themselves
    else:
        # Notify all group members
        for member in group.members:
            if member.id != removed_user_id:
                content = f"{removed_user.username} has left the group '{group.name}'"
                create_notification(member.id, content, 'info', 'group', group_id)

def get_user_notifications(user_id, limit=10, unread_only=False):
    """Get the latest notifications for a user"""
    query = Notification.query.filter_by(user_id=user_id)
    
    if unread_only:
        query = query.filter_by(read=False)
    
    return query.order_by(Notification.timestamp.desc()).limit(limit).all()

def mark_notification_as_read(notification_id):
    """Mark a specific notification as read"""
    notification = Notification.query.get(notification_id)
    if notification:
        notification.read = True
        db.session.commit()
        return True
    return False

def mark_all_notifications_as_read(user_id):
    """Mark all notifications for a user as read"""
    Notification.query.filter_by(user_id=user_id, read=False).update({'read': True})
    db.session.commit()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
        
        user = User(username=username, email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    users = User.query.filter(User.id != current_user.id).all()
    groups = Group.query.all()
    return render_template('dashboard.html', users=users, groups=groups)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        email = request.form['email']
        bio = request.form['bio']
        
        current_user.email = email
        current_user.bio = bio
        
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file.filename:
                # Save profile picture (in a real app, handle file storage properly)
                filename = current_user.username + '.' + file.filename.split('.')[-1]
                file.save(os.path.join(app.static_folder, 'profile_pics', filename))
                current_user.profile_picture = filename
        
        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('profile'))
    
    return render_template('edit_profile.html')

@app.route('/fetch_messages', methods=['GET'])
@login_required
def fetch_messages():
    """Fetch new messages based on chat type and last message ID."""
    chat_type = request.args.get('type')
    chat_id = request.args.get('id')
    last_id = int(request.args.get('last_id', 0))
    
    if not chat_type or not chat_id:
        return jsonify({'error': 'Missing parameters'}), 400
    
    messages = []
    
    if chat_type == 'private':
        # Fetch new private messages
        user_id = int(chat_id)
        user = User.query.get_or_404(user_id)
        
        # Get messages sent by current user to the other user
        sent_messages = PrivateMessage.query.filter_by(
            sender_id=current_user.id,
            recipient_id=user_id
        ).filter(PrivateMessage.id > last_id).all()
        
        # Get messages sent to current user from the other user
        received_messages = PrivateMessage.query.filter_by(
            sender_id=user_id,
            recipient_id=current_user.id
        ).filter(PrivateMessage.id > last_id).all()
        
        # Mark received messages as read
        for message in received_messages:
            if not message.read:
                message.read = True
        
        db.session.commit()
        
        # Prepare messages for JSON response
        for message in sorted(sent_messages + received_messages, key=lambda x: x.id):
            messages.append({
                'id': message.id,
                'content': message.content,
                'timestamp': message.timestamp.strftime('%H:%M | %b %d'),
                'is_own': message.sender_id == current_user.id,
                'sender': 'You' if message.sender_id == current_user.id else user.username
            })
    
    elif chat_type == 'group':
        # Fetch new group messages
        group_id = int(chat_id)
        group = Group.query.get_or_404(group_id)
        
        # Check if user is a member
        is_member = GroupMember.query.filter_by(
            user_id=current_user.id, group_id=group_id
        ).first() is not None
        
        if not is_member:
            return jsonify({'error': 'Not a member of this group'}), 403
        
        # Get all new group messages
        new_messages = GroupMessage.query.filter_by(group_id=group_id).filter(
            GroupMessage.id > last_id
        ).order_by(GroupMessage.id).all()
        
        # Prepare messages for JSON response
        for message in new_messages:
            sender = User.query.get(message.sender_id)
            messages.append({
                'id': message.id,
                'content': message.content,
                'timestamp': message.timestamp.strftime('%H:%M | %b %d'),
                'is_own': message.sender_id == current_user.id,
                'sender': 'You' if message.sender_id == current_user.id else sender.username
            })
    
    return jsonify({'messages': messages})

@app.route('/private_chat/<int:user_id>', methods=['GET', 'POST'])
@login_required
def private_chat(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        # Check if it's an AJAX request
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        
        content = request.form['message']
        if content:
            message = PrivateMessage(
                sender_id=current_user.id,
                recipient_id=user_id,
                content=content
            )
            db.session.add(message)
            db.session.commit()
            
            # If AJAX request, return JSON response
            if is_ajax:
                return jsonify({
                    'success': True,
                    'message': {
                        'id': message.id,
                        'content': message.content,
                        'timestamp': message.timestamp.strftime('%H:%M | %b %d'),
                        'is_own': True,
                        'sender': 'You'
                    }
                })
    
    # Get messages between current user and the selected user
    sent_messages = PrivateMessage.query.filter_by(
        sender_id=current_user.id, recipient_id=user_id
    ).all()
    
    received_messages = PrivateMessage.query.filter_by(
        sender_id=user_id, recipient_id=current_user.id
    ).all()
    
    # Mark received messages as read
    for message in received_messages:
        if not message.read:
            message.read = True
    
    db.session.commit()
    
    # Combine and sort messages by timestamp
    messages = sorted(sent_messages + received_messages, key=lambda x: x.timestamp)
    
    return render_template('private_chat.html', user=user, messages=messages)


@app.route('/remove_group/<int:group_id>')
@login_required
def remove_group(group_id):
    group = Group.query.get_or_404(group_id)
    
    # Check if current user is the creator of the group
    if group.created_by != current_user.id:
        flash('You do not have permission to remove this group', 'danger')
        return redirect(url_for('dashboard'))
    
    # Delete all messages in the group
    GroupMessage.query.filter_by(group_id=group_id).delete()
    
    # Remove all members from the group
    GroupMember.query.filter_by(group_id=group_id).delete()
    
    # Delete the group
    db.session.delete(group)
    db.session.commit()
    
    flash('Group has been removed successfully', 'success')
    return redirect(url_for('dashboard'))


@app.route('/create_group', methods=['GET', 'POST'])
@login_required
def create_group():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        
        if Group.query.filter_by(name=name).first():
            flash('Group name already exists', 'danger')
            return redirect(url_for('create_group'))
        
        group = Group(name=name, description=description, created_by=current_user.id)
        db.session.add(group)
        db.session.commit()
        
        # Add creator as a member
        membership = GroupMember(user_id=current_user.id, group_id=group.id)
        db.session.add(membership)
        db.session.commit()
        
        flash('Group created successfully', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('create_group.html')

@app.route('/join_group/<int:group_id>')
@login_required
def join_group(group_id):
    group = Group.query.get_or_404(group_id)
    
    if GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id).first():
        flash('You are already a member of this group', 'info')
    else:
        membership = GroupMember(user_id=current_user.id, group_id=group_id)
        db.session.add(membership)
        db.session.commit()
        flash('You have joined the group', 'success')
    
    return redirect(url_for('group_chat', group_id=group_id))


@app.route('/leave_group/<int:group_id>')
@login_required
def leave_group(group_id):
    # Check if request is AJAX
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    # Get the group
    group = Group.query.get_or_404(group_id)
    
    # Check if the current user is the creator
    if group.created_by == current_user.id:
        flash('As the creator, you cannot leave the group. You can remove the group instead.', 'warning')
        if is_ajax:
            return jsonify({'success': False, 'message': 'As the creator, you cannot leave the group.'})
        return redirect(url_for('group_chat', group_id=group_id))
    
    # Check if the current user is a member of the group
    membership = GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id).first()
    if not membership:
        flash('You are not a member of this group', 'warning')
        if is_ajax:
            return jsonify({'success': False, 'message': 'You are not a member of this group'})
        return redirect(url_for('dashboard'))
    
    # Create notifications before removing the user
    notify_group_member_removed(group_id, current_user.id)
    
    # Remove the user from the group
    db.session.delete(membership)
    db.session.commit()
    
    flash(f'You have left the group: {group.name}', 'success')
    
    # Handle AJAX or regular request differently
    if is_ajax:
        return jsonify({
            'success': True, 
            'message': f'You have left the group: {group.name}',
            'redirect_url': url_for('dashboard')
        })
    
    # Redirect to dashboard after leaving
    return redirect(url_for('dashboard'))

@app.route('/add_member/<int:group_id>', methods=['GET', 'POST'])
@login_required
def add_member(group_id):
    group = Group.query.get_or_404(group_id)
    
    # Check if current user is a member of the group
    is_member = GroupMember.query.filter_by(
        user_id=current_user.id, group_id=group_id
    ).first() is not None
    
    if not is_member:
        flash('You must be a member of the group to add new members', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        
        if not user_id:
            flash('Please select a user to add', 'danger')
            return redirect(url_for('add_member', group_id=group_id))
        
        user = User.query.get(user_id)
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('add_member', group_id=group_id))
        
        # Check if user is already a member
        existing_member = GroupMember.query.filter_by(
            user_id=user_id, group_id=group_id
        ).first()
        
        if existing_member:
            flash(f'{user.username} is already a member of this group', 'info')
        else:
            membership = GroupMember(user_id=user_id, group_id=group_id)
            db.session.add(membership)
            db.session.commit()
            
            # Create notifications
            notify_group_member_added(group_id, user.id, current_user.id)
            
            flash(f'{user.username} has been added to the group', 'success')
        
        return redirect(url_for('group_chat', group_id=group_id))
    
    # Get current members
    current_members = User.query.join(GroupMember).filter(GroupMember.group_id == group_id).all()
    
    # Get users who are not members
    non_members = User.query.filter(~User.id.in_([member.id for member in current_members])).all()
    
    return render_template('add_member.html', group=group, non_members=non_members)


@app.route('/group_chat/<int:group_id>', methods=['GET', 'POST'])
@login_required
def group_chat(group_id):
    group = Group.query.get_or_404(group_id)
    
    # Check if user is a member
    is_member = GroupMember.query.filter_by(
        user_id=current_user.id, group_id=group_id
    ).first() is not None
    
    if not is_member:
        flash('You are not a member of this group', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Check if it's an AJAX request
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        
        content = request.form['message']
        if content:
            message = GroupMessage(
                sender_id=current_user.id,
                group_id=group_id,
                content=content
            )
            db.session.add(message)
            db.session.commit()
            
            # If AJAX request, return JSON response
            if is_ajax:
                return jsonify({
                    'success': True,
                    'message': {
                        'id': message.id,
                        'content': message.content,
                        'timestamp': message.timestamp.strftime('%H:%M | %b %d'),
                        'is_own': True,
                        'sender': 'You'
                    }
                })
    
    # Get all group messages with sender information
    messages = GroupMessage.query.filter_by(group_id=group_id).order_by(GroupMessage.timestamp).all()
    
    # Get all group members
    members = User.query.join(GroupMember).filter(GroupMember.group_id == group_id).all()
    
    # Get sender information for each message
    for message in messages:
        message.sender = User.query.get(message.sender_id)
    
    # Check if current user is the group creator
    is_creator = group.created_by == current_user.id
    
    return render_template('group_chat.html', group=group, messages=messages, members=members, is_creator=is_creator)

@app.route('/remove_member/<int:group_id>/<int:user_id>')
@login_required
def remove_member(group_id, user_id):
    # Get the group
    group = Group.query.get_or_404(group_id)
    
    # Check if current user is the creator of the group
    if group.created_by != current_user.id:
        flash('You do not have permission to remove members from this group', 'danger')
        return redirect(url_for('group_chat', group_id=group_id))
    
    # Check if the user to be removed exists
    user = User.query.get_or_404(user_id)
    
    # Check if the user to be removed is a member of the group
    membership = GroupMember.query.filter_by(user_id=user_id, group_id=group_id).first()
    if not membership:
        flash(f'{user.username} is not a member of this group', 'warning')
        return redirect(url_for('group_chat', group_id=group_id))
    
    # Before deleting, create notifications
    notify_group_member_removed(group_id, user_id, current_user.id)
    
    # Remove the member
    db.session.delete(membership)
    db.session.commit()
    
    flash(f'{user.username} has been removed from the group', 'success')
    return redirect(url_for('group_chat', group_id=group_id))


@app.route('/fetch_group_members/<int:group_id>', methods=['GET'])
@login_required
def fetch_group_members(group_id):
    """Fetch current members of a group"""
    # Check if the user is a member of the group
    is_member = GroupMember.query.filter_by(
        user_id=current_user.id, group_id=group_id
    ).first() is not None
    
    if not is_member:
        return jsonify({'error': 'Not a member of this group'}), 403
    
    # Get all group members
    members = User.query.join(GroupMember).filter(GroupMember.group_id == group_id).all()
    
    # Format member data for the response
    member_data = [
        {
            'id': member.id,
            'username': member.username,
            'is_creator': (member.id == Group.query.get(group_id).created_by)
        }
        for member in members
    ]
    
    return jsonify({'members': member_data, 'count': len(member_data)})

@app.context_processor
def inject_notification_count():
    """Add notification count to template context for all pages"""
    if current_user.is_authenticated:
        notification_count = Notification.query.filter_by(user_id=current_user.id, read=False).count()
        return {'notification_count': notification_count}
    return {'notification_count': 0}


@app.route('/notifications')
@login_required
def view_notifications():
    """View all notifications for the current user"""
    notifications = get_user_notifications(current_user.id, limit=50)
    return render_template('notifications.html', notifications=notifications)

@app.route('/fetch_notifications')
@login_required
def fetch_notifications():
    """API endpoint to fetch user's notifications"""
    unread_only = request.args.get('unread_only', 'false').lower() == 'true'
    limit = int(request.args.get('limit', 10))
    
    notifications = get_user_notifications(current_user.id, limit=limit, unread_only=unread_only)
    
    return jsonify({
        'notifications': [notif.to_dict() for notif in notifications],
        'unread_count': Notification.query.filter_by(user_id=current_user.id, read=False).count()
    })

@app.route('/mark_notification_read/<int:notification_id>', methods=['POST'])
@login_required
def mark_read(notification_id):
    """Mark a specific notification as read"""
    notification = Notification.query.get_or_404(notification_id)
    
    # Check that this notification belongs to the current user
    if notification.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    notification.read = True
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/mark_all_notifications_read', methods=['POST'])
@login_required
def mark_all_read():
    """Mark all of the current user's notifications as read"""
    Notification.query.filter_by(user_id=current_user.id, read=False).update({'read': True})
    db.session.commit()
    
    return jsonify({'success': True})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

    