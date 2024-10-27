from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import pymongo
import secrets
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
secret_key = secrets.token_hex(32)
app.secret_key = secret_key

# MongoDB Atlas Connection
app.config['MONGO_URI'] = 'mongodb+srv://<username>:<password>@cluster0.mongodb.net/<database_name>?retryWrites=true&w=majority
'
client = pymongo.MongoClient(app.config['MONGO_URI'])
db = client['students']

# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your-email-password'
app.config['MAIL_USE_TLS'] = True

mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = db.users.find_one({"email": email})
        
        if user and check_password_hash(user['password'], password):
            flash('Login Successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login Failed. Check your email and password.', 'danger')
    
    return render_template('login.html')

# Password Reset Request Route
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        
        user = db.users.find_one({"email": email})
        
        if user:
            token = s.dumps(user['email'], salt='reset-password')
            reset_link = url_for('reset_with_token', token=token, _external=True)
            msg = Message('Password Reset Request', sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f'Click the link to reset your password: {reset_link}'
            mail.send(msg)
            flash(f'Password reset link sent to {email}.', 'info')
        else:
            flash('Email not found.', 'danger')
    
    return render_template('reset_password.html')

# Password Reset Route with Token
@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    try:
        email = s.loads(token, salt='reset-password', max_age=3600)
    except Exception:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('reset_password'))
    
    if request.method == 'POST':
        new_password = request.form['password']
        hashed_password = generate_password_hash(new_password)
        
        db.users.update_one({"email": email}, {"$set": {"password": hashed_password}})
        
        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_with_token.html', token=token)

# Home Route (placeholder for successful login)
@app.route('/')
def home():
    return render_template("index.html")

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
