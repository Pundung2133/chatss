from flask import Flask, render_template, redirect, url_for, request, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import json
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# JSON 파일 경로
USER_FILE = 'user.json'
CHAT_FILE = 'chat.json'

def load_users():
    if not os.path.exists(USER_FILE):
        return {}
    with open(USER_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USER_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def load_chats():
    if not os.path.exists(CHAT_FILE):
        return []
    with open(CHAT_FILE, 'r') as f:
        try:
            data = json.load(f)
            if isinstance(data, list):
                return data
            else:
                return []
        except json.JSONDecodeError:
            return []  # Return an empty list if JSON is invalid

def save_chats(chats):
    with open(CHAT_FILE, 'w') as f:
        json.dump(chats, f, indent=4)

def is_email_taken(email):
    users = load_users()
    return any(user_data['email'] == email for user_data in users.values())

class User(UserMixin):
    def __init__(self, id, email, password, name):
        self.id = id
        self.email = email
        self.password = password
        self.name = name

@login_manager.user_loader
def load_user(user_id):
    users = load_users()
    user_data = users.get(user_id)
    if user_data:
        return User(user_id, user_data['email'], user_data['password'], user_data['name'])
    return None

@app.route('/')
@login_required
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        users = load_users()
        for user_id, user_data in users.items():
            if user_data['email'] == email and bcrypt.check_password_hash(user_data['password'], password):
                user = User(user_id, email, user_data['password'], user_data['name'])
                login_user(user, remember=True)
                return redirect(url_for('home'))
        flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        
        # 중복 검사
        if is_email_taken(email):
            flash('Email already taken', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        users = load_users()
        user_id = str(len(users) + 1)  # Simple ID generation
        users[user_id] = {
            'email': email,
            'password': hashed_password,
            'name': name
        }
        save_users(users)
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/chat')
@login_required
def chat():
    chats = load_chats()
    return render_template('chat.html', user_name=current_user.name, chats=chats)

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    message = request.form.get('message')
    if message:
        chats = load_chats()
        new_message = {
            'user': current_user.name,  # Use current user's name
            'message': message
        }
        chats.append(new_message)
        save_chats(chats)
    return redirect(url_for('chat'))

if __name__ == '__main__':
    app.run(debug=True)
