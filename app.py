from flask import Flask, render_template,url_for,redirect,session,request
from flask_socketio import join_room, leave_room, send, SocketIO,emit
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from datetime import datetime


app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app)

socketio2 = SocketIO(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'holyromanempire'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=True

# rooms = {"message":[]}



login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)

# class Message(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     sender = db.Column(db.String(50), nullable=False)
#     message = db.Column(db.String(200), nullable=False) 
#     timestamp = db.Column(db.DateTime, default=datetime.utcnow)
   

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login',methods=["GET","POST"])
def login():
    form =LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html',form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():   
    return render_template('dashboard.html')


@app.route('/logout',methods=["GET","POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/room1',methods=["GET","POST"])
def room1():
    return render_template('room1.html',current_user=current_user)

@socketio.on("join")
def handle_user_join(username):
    print(f"User {username} joined!")

@socketio.on("connect")
def handle_connect():
    print("Client connected!")


# def save_message(sender, message):
#    new_message = Message(sender=sender, message=message)
#   db.session.add(new_message)
#   db.session.commit()


@socketio.on("new_message")
def handle_new_message(message):
    print(f"New message: {message}")
    if current_user.is_authenticated:
        username = current_user.username
        #save_message(sender=username, message=message)
        
    emit("chat", {"message": message, "username": username}, broadcast=True)







@app.route('/room2',methods=["GET","POST"])
def room2():
    return render_template('room2.html',current_user=current_user)

@socketio2.on("join")
def handle_user_join(username):
    print(f"User {username} joined!")

@socketio2.on("connect")
def handle_connect():
    print("Client connected!")


# def save_message(sender, message):
#    new_message = Message(sender=sender, message=message)
#   db.session.add(new_message)
#   db.session.commit()


@socketio2.on("new_message")
def handle_new_message(message):
    print(f"New message: {message}")
    if current_user.is_authenticated:
        username = current_user.username
        #save_message(sender=username, message=message)
        
    emit("chat", {"message": message, "username": username}, broadcast=True)










# @socketio.on("message")
# def message(data):
#     print(data)
#    # username = data['username']
#     message = data
    
    
#     content = {
#         "name": current_user.username,
#         "message": message
#     }
#     send(content)
#     rooms["message"].append(content)
#     #rooms["messages"].append(content)
    

# @socketio.on('connect')
# def connect_handler():
#     if current_user.is_authenticated:
#         emit('my response',
#              {'message': '{0} has joined'.format(current_user.username)},
#              broadcast=True)
#     else:
#         return False  # not allowed here

# @socketio.on('disconnect')
# def test_disconnect():
#     print('Client disconnected')



# @socketio.on("join")
# def connect(data):
#     print(data)
#     username = 1
#     room = 1
#     print(username)
#     join_room(room)
#     emit(str(username) + ' has entered the room.', to=room,broadcast=True)

#     print(f"{username} joined room {room}")

# @socketio.on("leave")
# def disconnect(data):
#     username = data['username']
#     room = data['room']
#     leave_room(room)
    
#     send(username + ' has left the room.', to=room)
#     print(f"{username} has left the room {room}")




@app.route('/register',methods=["GET","POST"])
def register():
    form=RegisterForm() 

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    
    return render_template('register.html',form=form)

if __name__ == "__main__":
   db.create_all()
   socketio.run(app,debug=True)
   