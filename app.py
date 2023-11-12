from flask import Flask, render_template, request, redirect, url_for, flash
from flask_socketio import SocketIO, emit
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime


app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
socketio = SocketIO(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Definición del modelo de usuario
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_deleted = db.Column(db.Boolean, default=False)
    user = db.relationship('User', backref='messages', lazy=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Definición del formulario de registro
class RegistrationForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Registrarse')

# Definición del formulario de inicio de sesión
class LoginForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Iniciar sesión')

@app.route('/')
@login_required
def index():
    messages = Message.query.all()
    return render_template('index.html', username=current_user.username, messages=messages)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash('El usuario ya existe. Por favor, elige otro nombre de usuario.', 'danger')
        else:
            new_user = User(username=username, password=password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registro exitoso. ¡Ahora puedes iniciar sesión!', 'success')
            return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()

        if user and password == user.password:
            login_user(user)
            flash('Inicio de sesión exitoso.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Usuario o contraseña incorrectos. Por favor, inténtalo de nuevo.', 'danger')

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión correctamente.', 'success')
    return redirect(url_for('login'))

@socketio.on('logout')
@login_required
def handle_logout():
    logout_user()
    print('Usuario desconectado')  # Para depuración
    return redirect(url_for('login'))  # Redirigir a la página de inicio de sesión

@socketio.on('connect')
def handle_connect():
    messages = Message.query.all()
    emit('all_messages', [{'content': message.content, 'username': message.user.username} for message in messages])


@socketio.on('message')
@login_required
def handle_message(msg):
    new_message = Message(content=msg, user=current_user)
    db.session.add(new_message)
    db.session.commit()

    emit('message', {'msg': msg, 'username': current_user.username}, broadcast=True)
    


@socketio.on('logout')
@login_required
def handle_logout():
    username = current_user.username
    logout_user()
    emit('user_disconnected', {'username': username}, broadcast=True)

@socketio.on('delete_message')
@login_required
def handle_delete_message(data):
    message_id = data.get('messageId')
    message = Message.query.get(message_id)

    if message and message.user_id == current_user.id:
        message.is_deleted = True
        db.session.commit()

        emit('message_deleted', {'messageId': message_id}, broadcast=True)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        socketio.run(app, debug=True)

