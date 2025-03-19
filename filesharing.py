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


@app.route('/filesharing')
def filesharing():
    return render_template('filesharing.html')