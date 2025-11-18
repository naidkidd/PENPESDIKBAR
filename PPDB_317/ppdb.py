import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ===== KONFIGURASI =====
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-ubah-ini-dengan-random-string'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://ppdb_admin:PPdb317#@192.168.189.141:3306/ppdb_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# ===== INISIALISASI DATABASE =====
db = SQLAlchemy(app)

# ===== KONFIGURASI ENKRIPSI =====
# Generate key dari secret key (gunakan yang sama untuk konsistensi)
password = app.config['SECRET_KEY'].encode()
salt = b'ppdb_sma_317_salt'  # Salt yang fixed
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
)
key = base64.urlsafe_b64encode(kdf.derive(password))
cipher_suite = Fernet(key)

# ===== MODEL DATABASE =====
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='siswa')
    nama = db.Column(db.Text)  # Encrypted
    email = db.Column(db.String(120))
    tanggal_daftar = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')
    
    # Data pribadi (encrypted)
    tempat_lahir = db.Column(db.Text)
    tanggal_lahir = db.Column(db.Text)
    jenis_kelamin = db.Column(db.Text)
    agama = db.Column(db.Text)
    alamat = db.Column(db.Text)
    no_hp = db.Column(db.Text)
    
    # Data orang tua (encrypted)
    nama_ayah = db.Column(db.Text)
    nama_ibu = db.Column(db.Text)
    pekerjaan_ayah = db.Column(db.Text)
    pekerjaan_ibu = db.Column(db.Text)
    
    # Data akademik
    asal_sekolah = db.Column(db.Text)

class Pengumuman(db.Model):
    __tablename__ = 'pengumuman'
    id = db.Column(db.Integer, primary_key=True)
    judul = db.Column(db.String(200), nullable=False)
    isi = db.Column(db.Text, nullable=False)
    tanggal = db.Column(db.DateTime, default=datetime.utcnow)
    penulis = db.Column(db.String(100))

# ===== FUNGSI ENKRIPSI/DESKRIPSI =====
def encrypt_data(data):
    """Encrypt data sensitive"""
    if data is None:
        return None
    encrypted = cipher_suite.encrypt(data.encode())
    return base64.b64encode(encrypted).decode()

def decrypt_data(encrypted_data):
    """Decrypt data sensitive"""
    if encrypted_data is None:
        return None
    try:
        decrypted = cipher_suite.decrypt(base64.b64decode(encrypted_data))
        return decrypted.decode()
    except:
        return encrypted_data  # Return as-is if decryption fails

# ===== ROUTES =====
@app.route('/')
def home():
    """Halaman utama"""
    try:
        pengumuman_terbaru = Pengumuman.query.order_by(Pengumuman.tanggal.desc()).first()
        return render_template('index.html', pengumuman=pengumuman_terbaru)
    except Exception as e:
        # Fallback jika database error
        return render_template('index.html', pengumuman=None)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registrasi siswa baru"""
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            nama = request.form['nama']
            
            # Cek jika username sudah ada
            if User.query.filter_by(username=username).first():
                flash('Username sudah terdaftar!', 'error')
                return redirect(url_for('register'))
            
            # Buat user baru
            new_user = User(
                username=username,
                password_hash=generate_password_hash(password),
                nama=encrypt_data(nama),
                role='siswa',
                status='pending'
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            flash('Registrasi berhasil! Silakan login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            flash('Error saat registrasi: ' + str(e), 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login user"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            
            flash('Login berhasil!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Username atau password salah!', 'error')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    """Dashboard user"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user, decrypt_data=decrypt_data)

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    flash('Anda telah logout.', 'info')
    return redirect(url_for('home'))

# ===== PRODUCTION CONFIGURATION =====
def create_app():
    return app

if __name__ == '__main__':
    # Buat folder uploads jika belum ada
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    print("Starting Flask server...")
    print("Access URLs:")
    print("   http://localhost:5000")
    print("   http://192.168.189.140:5000")  # IP BARU
    print("   http://0.0.0.0:5000")
    
    # Run dengan debug=False dan port=5000
    app.run(debug=False, host='0.0.0.0', port=5000)
