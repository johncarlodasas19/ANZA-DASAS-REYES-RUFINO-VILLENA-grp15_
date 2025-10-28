import os, smtplib, ssl
from email.message import EmailMessage
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User, Item
from werkzeug.utils import secure_filename
from PIL import Image
import imagehash

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXT = {'png','jpg','jpeg','gif'}

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET','dev-secret-key')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db.init_app(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXT

def compute_phash(filepath):
    try:
        img = Image.open(filepath).convert('RGB').resize((256,256))
        h = imagehash.phash(img)
        return str(h)
    except Exception as e:
        print('phash error', e)
        return None

def find_similar(phash_hex, limit=3, threshold=40):
    results = []
    try:
        h1 = imagehash.hex_to_hash(phash_hex)
    except Exception:
        return results
    for it in Item.query.filter(Item.phash!=None).all():
        try:
            h2 = imagehash.hex_to_hash(it.phash)
            dist = h1 - h2
            max_bits = 64
            sim = max(0, 100 - int(dist*100/max_bits))
            if sim >= threshold:
                results.append((it, sim))
        except Exception:
            continue
    results.sort(key=lambda x: x[1], reverse=True)
    return results[:limit]

def send_email(subject, body, to_email):
    smtp_server = os.environ.get('SMTP_SERVER')
    smtp_port = int(os.environ.get('SMTP_PORT') or 0)
    smtp_user = os.environ.get('SMTP_USER')
    smtp_pass = os.environ.get('SMTP_PASS')
    smtp_from = os.environ.get('SMTP_FROM') or (smtp_user or 'noreply@example.com')

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = smtp_from
    msg['To'] = to_email
    msg.set_content(body)

    if smtp_server and smtp_port and smtp_user and smtp_pass:
        try:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as server:
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
            print(f"Email sent to {to_email} (via {smtp_server}:{smtp_port})")
            return True, 'sent'
        except Exception as e:
            print('SMTP send failed:', e)
            return False, str(e)
    else:
        print('\n--- EMAIL (demo) ---')
        print('To:', to_email)
        print('Subject:', subject)
        print('Body:\n', body)
        print('--- END EMAIL ---\n')
        return False, 'not-configured'

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method=='POST':
        name = request.form.get('name')
        email = request.form.get('email')
        pw = request.form.get('password')
        is_admin = True if request.form.get('admin')=='on' else False
        if not email or not pw:
            flash('Email and password required','warning'); return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered','warning'); return redirect(url_for('register'))
        u = User(name=name, email=email)
        u.set_password(pw)
        u.is_admin = is_admin
        db.session.add(u); db.session.commit()
        flash('Registered. Please login.','success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        email = request.form.get('email')
        pw = request.form.get('password')
        u = User.query.filter_by(email=email).first()
        if not u or not u.check_password(pw):
            flash('Invalid credentials','danger'); return redirect(url_for('login'))
        login_user(u)
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    q = request.args.get('q','').strip()
    if current_user.is_admin:
        items = Item.query.order_by(Item.id.desc()).all()
    else:
        items = Item.query.filter(Item.status!='deleted').order_by(Item.id.desc()).all()
    if q:
        items = [it for it in items if q.lower() in (it.name or '').lower() or q.lower() in (it.description or '').lower()]
    return render_template('dashboard.html', items=items, q=q)

@app.route('/items/new', methods=['GET','POST'])
@login_required
def new_item():
    if request.method=='POST':
        itype = request.form.get('type')
        name = request.form.get('name')
        description = request.form.get('description')
        location = request.form.get('location')
        file = request.files.get('photo')
        filename = None
        phash = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filename = f"{int(os.times()[4])}_{filename}"
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(save_path)
            phash = compute_phash(save_path)
        item = Item(type=itype, name=name, description=description, location=location, photo=filename, phash=phash, user_id=current_user.id)
        db.session.add(item); db.session.commit()
        flash('Item submitted','success')
        return redirect(url_for('view_item', item_id=item.id))
    return render_template('new_item.html')

@app.route('/match_preview', methods=['POST'])
@login_required
def match_preview():
    file = request.files.get('photo')
    if not file or not allowed_file(file.filename):
        return jsonify({'ok':False, 'error':'Invalid file'}), 400
    filename = secure_filename(file.filename)
    tmp_path = os.path.join('/tmp', filename)
    file.save(tmp_path)
    phash = compute_phash(tmp_path)
    matches = []
    if phash:
        sim = find_similar(phash, limit=5, threshold=30)
        for it,perc in sim:
            matches.append({'id': it.id, 'type': it.type, 'name': it.name, 'sim': perc, 'photo': url_for('static', filename='uploads/' + (it.photo or 'placeholder.jpg'))})
    try:
        os.remove(tmp_path)
    except Exception:
        pass
    return jsonify({'ok':True, 'matches':matches})

@app.route('/items/<int:item_id>')
@login_required
def view_item(item_id):
    item = Item.query.get_or_404(item_id)
    similar = []
    if item.phash:
        sim = find_similar(item.phash, limit=5, threshold=30)
        for it,perc in sim:
            similar.append({'id': it.id, 'name': it.name, 'type': it.type, 'sim': perc, 'photo': url_for('static', filename='uploads/' + (it.photo or 'placeholder.jpg'))})
    return render_template('view_item.html', item=item, similar=similar)

@app.route('/items/<int:item_id>/edit', methods=['GET','POST'])
@login_required
def edit_item(item_id):
    item = Item.query.get_or_404(item_id)
    if current_user.id != item.user_id and not current_user.is_admin:
        flash('Forbidden','danger'); return redirect(url_for('dashboard'))
    if request.method=='POST':
        item.name = request.form.get('name')
        item.description = request.form.get('description')
        item.location = request.form.get('location')
        file = request.files.get('photo')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filename = f"{int(os.times()[4])}_{filename}"
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(save_path)
            item.photo = filename
            item.phash = compute_phash(save_path)
        db.session.commit()
        flash('Updated','success'); return redirect(url_for('view_item', item_id=item.id))
    return render_template('edit_item.html', item=item)

@app.route('/items/<int:item_id>/delete', methods=['POST'])
@login_required
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    if current_user.id != item.user_id and not current_user.is_admin:
        flash('Forbidden','danger'); return redirect(url_for('dashboard'))
    db.session.delete(item); db.session.commit()
    flash('Deleted','info'); return redirect(url_for('dashboard'))

@app.route('/claim/<int:item_id>', methods=['POST'])
@login_required
def claim_item(item_id):
    item = Item.query.get_or_404(item_id)
    item.status = 'pending_claim'
    item.claimed_by = current_user.id
    db.session.commit()
    flash('Claim submitted (pending)','info')
    return redirect(url_for('view_item', item_id=item.id))

@app.route('/admin/claims')
@login_required
def admin_claims():
    if not current_user.is_admin:
        flash('Admin required','danger'); return redirect(url_for('dashboard'))
    pending = Item.query.filter_by(status='pending_claim').order_by(Item.id.desc()).all()
    returned = Item.query.filter_by(status='returned').order_by(Item.id.desc()).all()
    unresolved = Item.query.filter_by(status='unresolved').order_by(Item.id.desc()).all()
    return render_template('admin_claims.html', pending=pending, returned=returned, unresolved=unresolved)

@app.route('/admin/claim/<int:item_id>/<action>')
@login_required
def admin_claim_action(item_id, action):
    if not current_user.is_admin:
        flash('Admin required','danger'); return redirect(url_for('dashboard'))
    item = Item.query.get_or_404(item_id)
    if action == 'approve':
        item.status = 'returned'
    elif action == 'reject':
        item.status = 'unresolved'
    elif action == 'delete':
        item.status = 'deleted'
    db.session.commit()

    reporter = User.query.get(item.user_id) if item.user_id else None
    claimant = User.query.get(item.claimed_by) if item.claimed_by else None
    subject = f"Claim update for item: {item.name} — {item.status}"
    body = f"Hello,\n\nThe claim status for the item '{item.name}' has been updated to: {item.status}.\n\nItem details:\nName: {item.name}\nType: {item.type}\nLocation: {item.location}\n\nIf you have questions please contact the admin.\n\nRegards,\nCampus Lost & Found"

    if reporter and reporter.email:
        send_email(subject, body, reporter.email)
    if claimant and claimant.email and claimant.id != (reporter.id if reporter else None):
        send_email(subject, body, claimant.email)

    flash('Action applied (notifications sent or logged).','success')
    return redirect(url_for('admin_claims'))

@app.cli.command('initdb')
def initdb_command():
    db.drop_all(); db.create_all()
    print('Initialized DB.')

@app.cli.command('seeddb')
def seeddb_command():
    db.drop_all(); db.create_all()
    admin = User(name='Admin Demo', email='admin@campus.local'); admin.set_password('admin123'); admin.is_admin=True
    user1 = User(name='Alice Student', email='alice@campus.local'); user1.set_password('alice123')
    user2 = User(name='Bob Student', email='bob@campus.local'); user2.set_password('bob123')
    db.session.add_all([admin, user1, user2]); db.session.commit()

    placeholder = os.path.join(app.config['UPLOAD_FOLDER'], 'placeholder.jpg')
    ph = compute_phash(placeholder) if os.path.exists(placeholder) else None
    it1 = Item(type='found', name='Black Wallet', description='Found near library entrance', location='Library', photo='placeholder.jpg', phash=ph, user_id=admin.id)
    it2 = Item(type='lost', name='Silver Ring', description='Lost in Canteen area', location='Canteen', photo='placeholder.jpg', phash=ph, user_id=user1.id)
    it3 = Item(type='found', name='Red Umbrella', description='Left at Lecture Hall 2', location='Lecture Hall 2', photo='placeholder.jpg', phash=ph, user_id=user2.id)
    db.session.add_all([it1, it2, it3]); db.session.commit()

    print('Seeded DB: admin@campus.local/admin123, alice@campus.local/alice123, bob@campus.local/bob123')


@app.route('/reset_password', methods=['GET','POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        pw1 = request.form.get('new_password')
        pw2 = request.form.get('confirm_password')
        if pw1 != pw2:
            flash('Passwords do not match','danger')
            return redirect(url_for('reset_password'))
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Email not found','danger')
            return redirect(url_for('reset_password'))
        user.password = pw1
        db.session.commit()
        flash('Password updated successfully','success')
        return redirect(url_for('login'))
    return render_template('reset_password.html')


@app.route('/my_claims')
@login_required
def my_claims():
    claims = Item.query.filter_by(claimed_by=current_user.id).order_by(Item.id.desc()).all()
    return render_template('my_claims.html', claims=claims)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
