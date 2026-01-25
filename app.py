import os
import base64
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from twilio.rest import Client
from dotenv import load_dotenv
import requests

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or 'super-secret-change-me'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///eggs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# M-Pesa config from .env
MPESA_CONSUMER_KEY = os.getenv('MPESA_CONSUMER_KEY')
MPESA_CONSUMER_SECRET = os.getenv('MPESA_CONSUMER_SECRET')
MPESA_SHORTCODE = os.getenv('MPESA_SHORTCODE', '174379')
MPESA_PASSKEY = os.getenv('MPESA_PASSKEY')
MPESA_CALLBACK_URL = os.getenv('MPESA_CALLBACK_URL')

# Twilio config
TWILIO_SID = os.getenv('TWILIO_ACCOUNT_SID')
TWILIO_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
TWILIO_PHONE = os.getenv('TWILIO_PHONE_NUMBER')
ADMIN_PHONE = os.getenv('ADMIN_PHONE_NUMBER')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ---------------- Models ----------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    location = db.Column(db.String(200))
    phone = db.Column(db.String(15))  # Added for M-Pesa
    amount = db.Column(db.Integer)     # trays
    status = db.Column(db.String(50), default='Pending Payment')

class Price(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    egg_price = db.Column(db.Float, default=150.0)  # per tray, update as needed

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------- M-Pesa Helpers ----------------
from requests.auth import HTTPBasicAuth
def get_mpesa_access_token():
    """Get OAuth token from Safaricom Daraja 3.0 sandbox"""
    url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
    try:
        r = requests.get(
            url,
            auth=HTTPBasicAuth(MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET),
            timeout=10
        )
        r.raise_for_status()
        token = r.json().get('access_token')
        if token:
            print("M-Pesa Access Token obtained ✅")
        return token
    except Exception as e:
        print(f"Failed to get token: {e}")
        return None


def initiate_stk_push(phone_mpesa, amount_kes, order_id, customer_name, trays):
    """
    Send STK push request to Safaricom sandbox
    phone_mpesa: 2547XXXXXXXX format
    amount_kes: integer
    order_id: for account reference
    """
    token = get_mpesa_access_token()
    if not token:
        return None, "Failed to get M-Pesa token"

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    password_str = f"{MPESA_SHORTCODE}{MPESA_PASSKEY}{timestamp}"
    password = base64.b64encode(password_str.encode()).decode()

    payload = {
        "BusinessShortCode": MPESA_SHORTCODE,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": int(amount_kes),  # must be integer
        "PartyA": phone_mpesa,
        "PartyB": MPESA_SHORTCODE,
        "PhoneNumber": phone_mpesa,
        "CallBackURL": MPESA_CALLBACK_URL,
        "AccountReference": f"EGG{order_id}",
        "TransactionDesc": f"{trays} trays eggs - {customer_name}"
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    url = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"

    try:
        print("Sending STK push payload:", payload)
        r = requests.post(url, json=payload, headers=headers, timeout=15)
        r.raise_for_status()
        result = r.json()
        print("STK push response:", result)

        if result.get("ResponseCode") == "0":
            return result.get("CheckoutRequestID"), None
        return None, result.get("errorMessage") or result.get("ResponseDescription") or "STK failed"
    except Exception as e:
        return None, str(e)


# ---------------- Routes ----------------
@app.route('/', methods=['GET', 'POST'])
def index():
    price = Price.query.first().egg_price if Price.query.first() else 150.0

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        location = request.form.get('location', '').strip()
        phone = request.form.get('phone', '').strip()
        try:
            trays = int(request.form.get('amount', 0))
        except:
            trays = 0

        if not name or not location or not phone or trays < 1:
            flash('Please complete all fields correctly.', 'danger')
            return redirect(url_for('index'))

        if len(phone) != 10 or not phone.startswith('0'):
            flash('Use valid Kenyan phone (e.g. 0712345678)', 'danger')
            return redirect(url_for('index'))

        total = trays * price
        phone_mpesa = '254' + phone[1:]

        order = Order(name=name, location=location, phone=phone, amount=trays)
        db.session.add(order)
        db.session.commit()

        checkout_id, error = initiate_stk_push(phone_mpesa, total, order.id, name, trays)

        if checkout_id:
            flash(f'Payment prompt sent to {phone}! Complete on your phone.', 'success')
            # Later: store checkout_id if you add a column
        else:
            db.session.delete(order)
            db.session.commit()
            flash(f'Payment start failed: {error}', 'danger')

        return redirect(url_for('index'))

    return render_template('index.html', price=price)

@app.route('/mpesa_callback', methods=['POST'])
def mpesa_callback():
    try:
        data = request.get_json(force=True)
        print("CALLBACK:", data)  # Check your terminal/console

        if data.get('Body', {}).get('stkCallback', {}).get('ResultCode') == 0:
            print("PAYMENT SUCCESS!")
            # TODO: update order status to 'Paid'
            # Send SMS to admin
            if TWILIO_SID and TWILIO_TOKEN and ADMIN_PHONE:
                client = Client(TWILIO_SID, TWILIO_TOKEN)
                client.messages.create(
                    body="New paid egg order received!",
                    from_=TWILIO_PHONE,
                    to=ADMIN_PHONE
                )
        else:
            print("Payment failed/cancelled")

        return jsonify({"ResultCode": 0, "ResultDesc": "Accepted"}), 200
    except Exception as e:
        print(f"Callback error: {e}")
        return jsonify({"ResultCode": 1, "ResultDesc": "Error"}), 200

# ---------------- Admin Login ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('admin'))
        flash('Wrong username/password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if request.method == 'POST':
        if 'new_price' in request.form:
            try:
                new_p = float(request.form['new_price'])
                p = Price.query.first()
                p.egg_price = new_p
                db.session.commit()
                flash('Price updated', 'success')
            except:
                flash('Invalid price', 'danger')

        if 'delete' in request.form:
            oid = int(request.form.get('order_id'))
            o = Order.query.get(oid)
            if o:
                db.session.delete(o)
                db.session.commit()
                flash('Order deleted', 'info')

    orders = Order.query.all()
    price = Price.query.first().egg_price if Price.query.first() else 150.0
    return render_template('admin.html', orders=orders, price=price)

# ---------------- Init DB & Default Data ----------------
with app.app_context():
    db.create_all()
    if not User.query.first():
        admin = User(username='admin', password=generate_password_hash('admin123', method='pbkdf2:sha256'))
        db.session.add(admin)
    if not Price.query.first():
        db.session.add(Price(egg_price=150.0))
    db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)