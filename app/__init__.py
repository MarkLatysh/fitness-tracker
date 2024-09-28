from flask import Flask, render_template, url_for, flash, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, current_user, logout_user, login_required, UserMixin
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from datetime import datetime
from werkzeug.security import generate_password_hash



app = Flask(__name__)
app.config['SECRET_KEY'] = 'ilgfsuyglsreufaur498wrywgfbrsf;oirv'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

db = SQLAlchemy(app)

migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

def change_password(email, new_password):
    with app.app_context():
        # Знайдіть користувача за email
        user = User.query.filter_by(email=email).first()

        if user:
            # Генеруємо новий хешований пароль
            hashed_password = generate_password_hash(new_password)
            user.password = hashed_password

            # Зберігаємо зміни в базі даних
            db.session.commit()
            print(f"Пароль для користувача з email {email} успішно змінено!")
        else:
            print("Користувача не знайдено")

        # Виклик функції безпосередньо
        if __name__ == '__main__':
            email_to_change = 'latysh.familytrip@gmail.com'  # Змініть на email користувача
            new_password = 'kaban'  # Змініть на новий пароль
            change_password(email_to_change, new_password)


class RegistrationForm(FlaskForm):
    __tablename__ = "registrationforms"

    id = StringField('Id', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')



    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        # user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')





class LoginForm(FlaskForm):
    __tablename__ = "loginforms"

    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class WorkoutForm(FlaskForm):
    __tablename__ = "workoutforms"

    title = StringField('Title', validators=[DataRequired()])



class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    workouts = db.relationship('Workout', backref='author', lazy=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"

class Workout(db.Model):
    __tablename__ = "workouts"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __repr__(self):
        return f"Workout('{self.title}', '{self.date_posted}')"

with app.app_context():
    db.create_all()



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))




@app.route('/user')
def user():
    user = session.get('user')
    return render_template('index.html', user=user)



# @app.route("/")
@app.route("/home")
def home():
    workouts = Workout.query.all()
    return render_template('index.html', workouts=workouts)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.password == form.password.data:
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))



@app.route("/workout/new", methods=['GET', 'POST'])
@login_required
def new_workout():
    form = WorkoutForm()
    if form.validate_on_submit():
        workout = Workout(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(workout)
        db.session.commit()
        flash('Your workout has been created!', 'success')
        return redirect(url_for('home'))
    return render_template('create_workout.html', title='New Workout', form=form)