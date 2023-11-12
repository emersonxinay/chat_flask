from flask import Flask, render_template, request, redirect, url_for, flash
from flask_socketio import SocketIO, emit
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
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


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    memberships = db.relationship('GroupMembership', back_populates='user', lazy='dynamic')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class GroupMembership(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    user = db.relationship('User', back_populates='memberships')
    group = db.relationship('Group', back_populates='members')


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    members = db.relationship('GroupMembership', back_populates='group', lazy='dynamic')
    messages = db.relationship('Message', back_populates='group', lazy='dynamic')


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    user = db.relationship('User')
    group = db.relationship('Group', back_populates='messages')


class RegistrationForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    group = SelectField('Grupo', coerce=int)
    submit = SubmitField('Registrarse')

    def __init__(self, *args, **kwargs):
        super(RegistrationForm, self).__init__(*args, **kwargs)
        groups = Group.query.all()
        self.group.choices = [(group.id, group.name) for group in groups]


class LoginForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Iniciar sesión')


@app.route('/')
@login_required
def index():
    user_groups = current_user.memberships.join(Group).all()
    return render_template('index.html', username=current_user.username, user_groups=user_groups)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        group_id = form.group.data

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash('El usuario ya existe. Por favor, elige otro nombre de usuario.', 'danger')
        else:
            new_user = User(username=username, password=password)

            group = Group.query.get(group_id)
            if group:
                membership = GroupMembership(user=new_user, group=group)
                db.session.add(membership)

            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)

            flash('Registro exitoso. ¡Ahora estás registrado y tu sesión ha comenzado!', 'success')
            return redirect(url_for('index'))

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


@socketio.on('message')
@login_required
def handle_message(msg):
    group_id = request.args.get('group_id', type=int)
    group = Group.query.get(group_id)

    if group and current_user in group.members:
        new_message = Message(content=msg, user=current_user, group=group)
        db.session.add(new_message)
        db.session.commit()
        emit('message', {'msg': msg, 'username': current_user.username}, room=group_id)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        socketio.run(app, debug=True)
