from flask import Flask, request, jsonify, session, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, join_room, leave_room, emit
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from datetime import datetime
from sqlalchemy import inspect
from functools import wraps

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:ranjan1@44.204.81.59:5432/project?sslmode=require'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '63ad318a5562d4cc6cde059458bea290e473b0462a6f8b1809db58fac3796b3c'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 3600

db = SQLAlchemy(app)

# Dictionary to track online users
online_users = set()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    deleted_at = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)

class Project(db.Model):
    __tablename__ = 'projects'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    tl_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    deleted_at = db.Column(db.DateTime, nullable=True)

class Assignment(db.Model):
    __tablename__ = 'assignments'
    id = db.Column(db.Integer, primary_key=True)
    emp_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    assigned_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    deleted_at = db.Column(db.DateTime, nullable=True)

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    seen = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='sent')
    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])

def role_required(allowed_roles):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            user = User.query.filter_by(id=session['user_id'], deleted_at=None).first()
            if not user:
                session.clear()
                return redirect(url_for('login'))
            if user.role not in allowed_roles:
                return render_template('error.html', error_code=403, error_message="Access forbidden"), 403
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error.html', error_code=500, error_message="Internal server error"), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('error.html', error_code=403, error_message="Access forbidden"), 403

@app.errorhandler(401)
def unauthorized_error(error):
    return render_template('error.html', error_code=401, error_message="Unauthorized access"), 401

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        user = User.query.filter_by(id=session['user_id'], deleted_at=None).first()
        if user:
            return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            data = request.form
            username = data.get('username')
            password = data.get('password')
            
            if not username or not password:
                return render_template('login.html', error="Username and password are required")
                
            user = User.query.filter_by(username=username, deleted_at=None).first()
            
            if not user or not bcrypt.check_password_hash(user.password, password):
                return render_template('login.html', error="Invalid username or password")
                
            session['user_id'] = user.id
            session['role'] = user.role
            session.permanent = True
            user.last_login = datetime.utcnow()
            db.session.commit()
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            return render_template('login.html', error=f"An error occurred: {str(e)}")
            
    return render_template('login.html')

@app.route('/dashboard')
@role_required(['tl', 'employee'])
def dashboard():
    try:
        user = User.query.filter_by(id=session['user_id'], deleted_at=None).first()
        if not user:
            session.clear()
            return redirect(url_for('login'))

        if user.role == 'tl':
            employees_count = User.query.filter_by(role='employee', deleted_at=None).count()
            assigned_projects_count = Assignment.query.filter_by(deleted_at=None).count()
            employees = User.query.filter_by(role='employee', deleted_at=None).all()
            return render_template(
                'dashboard_tl.html',
                user=user,
                employees=employees,
                employees_count=employees_count,
                assigned_projects_count=assigned_projects_count
            )

        assignment = Assignment.query.filter_by(emp_id=user.id, deleted_at=None).first()
        project = Project.query.filter_by(id=assignment.project_id, deleted_at=None).first() if assignment else None
        return render_template('dashboard_employee.html', user=user, project=project)

    except Exception:
        return render_template('error.html', message="An error occurred while loading the dashboard.")

@app.route('/profile', methods=['GET'])
@role_required(['tl', 'employee'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(id=session['user_id'], deleted_at=None).first()
    if not user:
        session.clear()
        return redirect(url_for('login'))
    return render_template('profile.html', user=user)

@app.route('/my_project', methods=['GET'])
@role_required(['employee'])
def my_project():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    assignment = Assignment.query.filter_by(emp_id=session['user_id'], deleted_at=None).first()
    project = Project.query.filter_by(id=assignment.project_id, deleted_at=None).first() if assignment else None
    return render_template('my_project.html', project=project)

@app.route('/team_overview')
@role_required(['tl'])
def team_overview():
    employees = User.query.filter_by(role='employee', deleted_at=None).all()
    employees_with_projects = []
    for employee in employees:
        assignments = Assignment.query.filter_by(emp_id=employee.id, deleted_at=None).all()
        projects = [Project.query.get(assignment.project_id) for assignment in assignments if assignment.project_id]
        employees_with_projects.append({'employee': employee, 'projects': projects})
    return render_template('team_overview.html', employees_with_projects=employees_with_projects)

@app.route('/assign_project', methods=['GET', 'POST'])
@role_required(['tl'])
def assign_project():
    if request.method == 'GET':
        employees = User.query.filter_by(role='employee', deleted_at=None).all()
        return render_template('assign_project.html', employees=employees)
    
    data = request.form
    title = data.get('title')
    description = data.get('description')
    emp_id = data.get('emp_id')
    
    if not all([title, description, emp_id]):
        return jsonify({"success": False, "message": "All fields are required"}), 400
        
    try:
        new_project = Project(title=title, description=description, tl_id=session['user_id'])
        db.session.add(new_project)
        db.session.commit()
        
        new_assignment = Assignment(emp_id=int(emp_id), project_id=new_project.id, assigned_by=session['user_id'])
        db.session.add(new_assignment)
        db.session.commit()
        return jsonify({"success": True, "message": "Project assigned successfully!"})
    except Exception:
        db.session.rollback()
        return jsonify({"success": False, "message": "Failed to assign project"}), 500

@app.route('/filesharing')
@role_required(['employee'])
def filesharing():
    return render_template('filesharing.html')

@app.route('/instance')
@role_required(["employee"])
def instance():
    return render_template("instance.html")

# Socket.IO events
@socketio.on('join')
def handle_join(data):
    user_id = data.get('user_id')
    if user_id:
        join_room(str(user_id))
        online_users.add(int(user_id))
        emit('user_status', {'user_id': int(user_id), 'status': 'online'}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if 'user_id' in session:
        user_id = session['user_id']
        online_users.discard(user_id)
        emit('user_status', {'user_id': user_id, 'status': 'offline'}, broadcast=True)
        leave_room(str(user_id))

@socketio.on('send_message')
def handle_send_message(data):
    try:
        required_fields = ['receiver_id', 'message', 'sender_id']
        if not all(field in data for field in required_fields):
            emit('error', {'message': 'Missing required fields'})
            return

        sender_id = int(data['sender_id'])
        receiver_id = int(data['receiver_id'])
        message_text = data['message']

        new_message = Message(
            sender_id=sender_id,
            receiver_id=receiver_id,
            message=message_text
        )
        db.session.add(new_message)
        db.session.commit()

        message_data = {
            'sender_id': sender_id,
            'receiver_id': receiver_id,
            'message': new_message.message,
            'timestamp': new_message.timestamp.isoformat()
        }
        emit('receive_message', message_data, room=str(sender_id))
        emit('receive_message', message_data, room=str(receiver_id))

    except Exception as e:
        db.session.rollback()
        emit('error', {'message': str(e)})

@socketio.on('check_status')
def handle_check_status(data):
    user_id = data.get('user_id')
    if user_id in online_users:
        emit('user_status', {'user_id': int(user_id), 'status': 'online'}, broadcast=True)
    else:
        emit('user_status', {'user_id': int(user_id), 'status': 'offline'}, broadcast=True)

@app.route('/chat/history/<int:user1_id>/<int:user2_id>', methods=['GET'])
def get_chat_history(user1_id, user2_id):
    messages = Message.query.filter(
        ((Message.sender_id == user1_id) & (Message.receiver_id == user2_id)) |
        ((Message.sender_id == user2_id) & (Message.receiver_id == user1_id))
    ).order_by(Message.timestamp).all()
    
    return jsonify([{
        'sender_id': msg.sender_id,
        'receiver_id': msg.receiver_id,
        'message': msg.message,
        'timestamp': msg.timestamp.isoformat()
    } for msg in messages])

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    current_user_id = session['user_id']
    users = User.query.filter(
        User.id != current_user_id,
        User.deleted_at.is_(None)
    ).all()
    
    return render_template('chat.html', users=users, current_user_id=current_user_id, online_users=online_users)

@app.route('/logout')
@role_required(['tl', 'employee'])
def logout():
    socketio.emit('user_status', {'user_id': session['user_id'], 'status': 'offline'}, broadcast=True)
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin/add_user', methods=['POST'])
def add_user():
    if request.headers.get('X-Admin-Token') != 'a25e2f203bf484d57e28cfab9840aa30ccdcfc9990190827a0efdc039a215efa':
        return jsonify({'error': 'Unauthorized'}), 403
    data = request.json
    if not all(k in data for k in ('password', 'email', 'username')):
        return jsonify({'error': 'Missing required fields'}), 400
    existing_user = User.query.filter_by(email=data['email']).first()
    if existing_user:
        return jsonify({'error': 'Email already exists'}), 409
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(
        name=data.get('name', ''),
        email=data['email'],
        phone=data.get('phone', ''),
        role=data.get('role', ''),
        username=data['username'],
        password=hashed_password
    )
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User added successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Database error', 'details': str(e)}), 500

@app.route('/admin/delete_user/<int:user_id>', methods=['DELETE'])
@role_required(['admin'])
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    user.deleted_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'message': 'User soft-deleted'}), 200

if __name__ == '__main__':
    with app.app_context():
        inspector = inspect(db.engine)
        tables = {t.lower() for t in inspector.get_table_names()}
        required_tables = {'users', 'projects', 'assignments', 'messages'}
        if required_tables.issubset(tables):
            print("Tables already exist.")
        else:
            print("Recreating tables...")
            db.drop_all()
            db.create_all()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=False)