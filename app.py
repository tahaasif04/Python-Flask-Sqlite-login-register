from flask import Flask, render_template, redirect, url_for, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, ValidationError
import sqlite3
import bcrypt
import os

app = Flask(__name__)
app.secret_key = "your_secret_key_here"
DATABASE = "users.db"


# ------------------ DATABASE SETUP ------------------
def init_db():
    if not os.path.exists(DATABASE):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

init_db()


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# ------------------ FORMS ------------------
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self, field):
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = ?", (field.data,))
        user = cursor.fetchone()
        conn.close()
        if user:
            raise ValidationError("Email already taken")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


# ------------------ ROUTES ------------------
@app.route('/')
def index():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.hashpw(
            form.password.data.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            (form.name.data, form.email.data, hashed_password)
        )
        conn.commit()
        conn.close()

        flash("Registration successful. Please login.")
        return redirect(url_for('login'))

    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE email = ?",
            (form.email.data,)
        )
        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.checkpw(
            form.password.data.encode('utf-8'),
            user['password'].encode('utf-8')
        ):
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password")

    return render_template("login.html", form=form)


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE id = ?",
        (session['user_id'],)
    )
    user = cursor.fetchone()
    conn.close()

    return render_template("dashboard.html", user=user)


@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully")
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
