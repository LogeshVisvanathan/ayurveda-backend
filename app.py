"""
Ayurvedic Herbal Traceability System — Backend v6
FIXES:
  1. DB auto-migration: safely adds new columns to existing users table
  2. Admin register: separate endpoint /api/auth/admin-register with secret key
  3. Farmers/Lab/Consumer BLOCKED from login until admin approves them
  4. application-status uses COALESCE so it works on old/new DB
  5. Blockchain audit on every important action
"""
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import psycopg2, psycopg2.extras, jwt, bcrypt, os, uuid, qrcode, io, base64, hashlib, json
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.utils import secure_filename

app = Flask(__name__)
from flask_cors import CORS
CORS(app)
app.config['SECRET_KEY']    = os.environ.get('SECRET_KEY',    'ayurveda-secret-2026')
app.config['ADMIN_SECRET']  = os.environ.get('ADMIN_SECRET',  'ayurveda-admin-2026')
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
ALLOWED = {'png','jpg','jpeg','gif','pdf'}

# def get_db():
#     return psycopg2.connect(
#         dbname=os.environ.get('DB_NAME','ayurveda_db'),
#         user=os.environ.get('DB_USER','postgres'),
#         password=os.environ.get('DB_PASSWORD','postgres123'),
#         host=os.environ.get('DB_HOST','localhost'),
#         port=os.environ.get('DB_PORT','5432'))

import psycopg2
import os

def get_db():
    return psycopg2.connect(os.environ.get("DATABASE_URL"))

def serialize(row):
    return {k:(v.isoformat() if hasattr(v,'isoformat') else v) for k,v in row.items()}

def allowed_file(fn): return '.' in fn and fn.rsplit('.',1)[1].lower() in ALLOWED

def save_file(f, pfx=''):
    if f and f.filename and allowed_file(f.filename):
        fname = secure_filename(f"{pfx}{uuid.uuid4().hex}_{f.filename}")
        f.save(os.path.join(app.config['UPLOAD_FOLDER'], fname))
        return f"/uploads/{fname}"
    return None

def make_qr(data):
    qr = qrcode.QRCode(version=1,box_size=10,border=5,error_correction=qrcode.constants.ERROR_CORRECT_L)
    qr.add_data(data); qr.make(fit=True)
    img = qr.make_image(fill_color='black',back_color='white')
    buf = io.BytesIO(); img.save(buf,format='PNG')
    return base64.b64encode(buf.getvalue()).decode()

def record_audit(conn, event, actor, etype, eid, payload):
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT block_hash FROM audit_log ORDER BY sequence DESC LIMIT 1")
        last = cur.fetchone(); prev = last['block_hash'] if last else '0'*64
        ts  = datetime.utcnow().isoformat()
        ds  = f"{prev}|{event}|{actor}|{eid}|{json.dumps(payload,sort_keys=True)}|{ts}"
        bhash = hashlib.sha256(ds.encode()).hexdigest()
        cur.execute("INSERT INTO audit_log(event_type,actor_id,entity_type,entity_id,payload,prev_hash,block_hash,created_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
                    (event,str(actor),etype,str(eid),json.dumps(payload),prev,bhash,ts))
        cur.close()
    except Exception as e:
        print(f"Audit note: {e}")


# ── DB Init + Migration ────────────────────────────────────────────────────────
def init_db():
    conn = get_db(); cur = conn.cursor()

    # STEP 1 — Create all tables (safe, idempotent)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL,
        full_name VARCHAR(255), phone VARCHAR(20), address TEXT,
        created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS registration_documents(
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        doc_type VARCHAR(100) NOT NULL, doc_label VARCHAR(255),
        file_url TEXT NOT NULL, uploaded_at TIMESTAMP DEFAULT NOW(), verified BOOLEAN DEFAULT FALSE
    );
    CREATE TABLE IF NOT EXISTS user_profiles(
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        land_area_acres DECIMAL(10,2), land_survey_no VARCHAR(255),
        land_district VARCHAR(255), land_state VARCHAR(255), farming_type VARCHAR(100),
        lab_name VARCHAR(255), lab_licence_no VARCHAR(255),
        lab_accreditation VARCHAR(255), lab_address TEXT,
        govt_id_type VARCHAR(100), govt_id_number VARCHAR(100),
        notes TEXT, updated_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS audit_log(
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        sequence BIGSERIAL, event_type VARCHAR(100) NOT NULL,
        actor_id VARCHAR(255), entity_type VARCHAR(100), entity_id VARCHAR(255),
        payload JSONB, prev_hash VARCHAR(64) NOT NULL,
        block_hash VARCHAR(64) NOT NULL UNIQUE, created_at TIMESTAMP NOT NULL
    );
    CREATE TABLE IF NOT EXISTS herb_batches(
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        batch_id VARCHAR(100) UNIQUE NOT NULL, farmer_id UUID REFERENCES users(id),
        herb_species VARCHAR(255) NOT NULL, quantity_kg DECIMAL(10,2),
        moisture_level DECIMAL(5,2), harvest_date DATE, farming_practices TEXT,
        gps_lat DECIMAL(10,8), gps_lng DECIMAL(11,8), location_name VARCHAR(255),
        image_url TEXT, notes TEXT, status VARCHAR(50) DEFAULT 'collected',
        created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS processing_records(
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        batch_id VARCHAR(100) REFERENCES herb_batches(batch_id),
        processor_id UUID REFERENCES users(id),
        drying_method VARCHAR(100), drying_duration_hours INTEGER,
        drying_temperature DECIMAL(5,2), grinding_status BOOLEAN DEFAULT FALSE,
        grinding_particle_sz VARCHAR(100), storage_temperature DECIMAL(5,2),
        storage_humidity DECIMAL(5,2), storage_location VARCHAR(255),
        chain_of_custody TEXT, notes TEXT, processed_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS lab_tests(
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        batch_id VARCHAR(100) REFERENCES herb_batches(batch_id),
        lab_id UUID REFERENCES users(id),
        moisture_content DECIMAL(5,2), moisture_report_url TEXT,
        pesticide_residue_result VARCHAR(80), pesticide_report_url TEXT,
        dna_auth_result VARCHAR(80), dna_certificate_url TEXT,
        heavy_metal_result VARCHAR(80), microbial_count VARCHAR(100),
        overall_status VARCHAR(50) DEFAULT 'pending',
        tested_by VARCHAR(255), tested_at TIMESTAMP DEFAULT NOW(), notes TEXT
    );
    CREATE TABLE IF NOT EXISTS products(
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        product_id VARCHAR(100) UNIQUE NOT NULL, batch_id VARCHAR(100) REFERENCES herb_batches(batch_id),
        qr_code_data TEXT, product_name VARCHAR(255), description TEXT,
        manufacturing_date DATE, expiry_date DATE, is_public BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS consumer_scans(
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        product_id VARCHAR(100) REFERENCES products(product_id),
        scanned_at TIMESTAMP DEFAULT NOW(), user_agent TEXT, ip_address VARCHAR(50)
    );
    """)
    conn.commit()

    # STEP 2 — SAFE migration: add new columns to existing users table
    # ADD COLUMN IF NOT EXISTS is idempotent — runs fine even if column already exists
    migrations = [
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS approval_status VARCHAR(20) DEFAULT 'pending'",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS approved_by UUID",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS rejection_note TEXT",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT FALSE",
    ]
    for sql in migrations:
        try:
            cur.execute(sql); conn.commit()
        except Exception as e:
            conn.rollback(); print(f"Migration note: {e}")

    # STEP 3 — Fix NULL values left in column after migration
    try:
        # Admins are always approved+active
        cur.execute("UPDATE users SET approval_status='approved', is_active=TRUE WHERE role='admin'")
        # Users that existed before the approval system → grandfather as approved
        cur.execute("""
            UPDATE users SET approval_status='approved', is_active=TRUE
            WHERE role != 'admin' AND approval_status IS NULL
        """)
        conn.commit()
    except Exception as e:
        conn.rollback(); print(f"Fix note: {e}")

    # STEP 4 — Seed default admin if none exists
    try:
        cur.execute("SELECT id FROM users WHERE role='admin' LIMIT 1")
        if not cur.fetchone():
            pw = bcrypt.hashpw(b'admin123', bcrypt.gensalt()).decode()
            cur.execute("INSERT INTO users(email,password_hash,role,full_name,approval_status,is_active) VALUES('admin@ayurveda.com',%s,'admin','System Admin','approved',TRUE)", (pw,))
            conn.commit()
            print("  Default admin: admin@ayurveda.com / admin123")
    except Exception as e:
        conn.rollback(); print(f"Seed note: {e}")

    cur.close(); conn.close()
    print("✓ Database ready.")


# ── Auth decorators ────────────────────────────────────────────────────────────
def token_required(f):
    @wraps(f)
    def d(*a,**kw):
        tok = request.headers.get('Authorization','').replace('Bearer ','').strip()
        if not tok: return jsonify({'error':'Token required'}),401
        try: payload = jwt.decode(tok,app.config['SECRET_KEY'],algorithms=['HS256'])
        except jwt.ExpiredSignatureError: return jsonify({'error':'Token expired'}),401
        except: return jsonify({'error':'Invalid token'}),401
        return f(payload,*a,**kw)
    return d

def role_required(*roles):
    def dec(f):
        @wraps(f)
        def d(cu,*a,**kw):
            if cu['role'] not in roles: return jsonify({'error':f'Requires: {"/".join(roles)}'}),403
            return f(cu,*a,**kw)
        return d
    return dec


# ══════════════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════════════

@app.route('/api/auth/admin-register', methods=['POST'])
def admin_register():
    """Admin-only register. Needs secret key. No docs, no approval wait."""
    data = request.get_json() or {}
    if data.get('admin_secret') != app.config['ADMIN_SECRET']:
        return jsonify({'error':'Invalid admin secret key. Contact your system administrator.'}),403
    for field in ('email','password','full_name'):
        if not data.get(field): return jsonify({'error':f'"{field}" is required'}),400
    if len(data['password'])<6: return jsonify({'error':'Password min 6 chars'}),400
    pw = bcrypt.hashpw(data['password'].encode(),bcrypt.gensalt()).decode()
    try:
        conn = get_db(); cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("INSERT INTO users(email,password_hash,role,full_name,phone,approval_status,is_active) VALUES(%s,%s,'admin',%s,%s,'approved',TRUE) RETURNING id,email,role,full_name",
                    (data['email'],pw,data['full_name'],data.get('phone')))
        user = dict(cur.fetchone())
        record_audit(conn,'ADMIN_REGISTERED',str(user['id']),'user',str(user['id']),{'email':data['email'],'name':data['full_name']})
        conn.commit(); cur.close(); conn.close()
        token = jwt.encode({'user_id':str(user['id']),'email':user['email'],'role':'admin','exp':datetime.utcnow()+timedelta(days=7)},app.config['SECRET_KEY'],algorithm='HS256')
        return jsonify({'message':f'Admin account created. Welcome, {data["full_name"]}!','token':token,'user':user}),201
    except psycopg2.IntegrityError: return jsonify({'error':'Email already registered'}),409
    except Exception as e: return jsonify({'error':str(e)}),500


@app.route('/api/auth/register', methods=['POST'])
def register():
    """Farmer / Lab / Consumer register. Documents required. Starts as PENDING."""
    data = request.form
    for field in ('email','password','role','full_name'):
        if not data.get(field): return jsonify({'error':f'"{field}" is required'}),400
    role = data['role']
    if role == 'admin':
        return jsonify({'error':'Admin accounts use the /admin-register page with a secret key'}),400
    if role not in ('farmer','consumer','lab'):
        return jsonify({'error':'Role must be: farmer, consumer, or lab'}),400
    if len(data['password'])<6: return jsonify({'error':'Password min 6 chars'}),400

    # Document validation
    if role=='farmer':
        if not request.files.get('land_document'): return jsonify({'error':'Land ownership document is required'}),400
        if not data.get('land_district') or not data.get('land_state'): return jsonify({'error':'Land district and state are required'}),400
    elif role=='lab':
        if not request.files.get('lab_licence'): return jsonify({'error':'Laboratory licence document is required'}),400
        if not data.get('lab_licence_no'): return jsonify({'error':'Lab licence number is required'}),400
    elif role=='consumer':
        if not request.files.get('govt_id'): return jsonify({'error':'Government ID document is required'}),400
        if not data.get('govt_id_type') or not data.get('govt_id_number'): return jsonify({'error':'Govt ID type and number are required'}),400

    pw = bcrypt.hashpw(data['password'].encode(),bcrypt.gensalt()).decode()
    try:
        conn = get_db(); cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("INSERT INTO users(email,password_hash,role,full_name,phone,address,approval_status,is_active) VALUES(%s,%s,%s,%s,%s,%s,'pending',FALSE) RETURNING id,email,role,full_name",
                    (data['email'],pw,role,data['full_name'],data.get('phone'),data.get('address')))
        user = dict(cur.fetchone()); uid = user['id']

        # Profile
        try:
            cur.execute("INSERT INTO user_profiles(user_id,land_area_acres,land_survey_no,land_district,land_state,farming_type,lab_name,lab_licence_no,lab_accreditation,lab_address,govt_id_type,govt_id_number,notes) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                        (uid,data.get('land_area_acres') or None,data.get('land_survey_no'),data.get('land_district'),data.get('land_state'),data.get('farming_type'),data.get('lab_name'),data.get('lab_licence_no'),data.get('lab_accreditation'),data.get('lab_address'),data.get('govt_id_type'),data.get('govt_id_number'),data.get('notes')))
        except Exception: pass

        # Documents
        for fname,(label,pfx) in [('land_document',('Land Ownership Doc','land_')),('lab_licence',('Lab Licence','lab_')),('govt_id',('Govt ID','govtid_')),('extra_document',('Extra Doc','extra_'))]:
            url = save_file(request.files.get(fname),pfx)
            if url:
                try: cur.execute("INSERT INTO registration_documents(user_id,doc_type,doc_label,file_url) VALUES(%s,%s,%s,%s)",(uid,fname,label,url))
                except Exception: pass

        try: record_audit(conn,'USER_REGISTERED',str(uid),'user',str(uid),{'email':data['email'],'role':role,'name':data['full_name']})
        except Exception: pass

        conn.commit(); cur.close(); conn.close()
        return jsonify({
            'message': f'Registration submitted! Your application is pending admin review. Track your status using your email: {data["email"]}',
            'status': 'pending',
            'application_email': data['email']
        }), 201
    except psycopg2.IntegrityError: return jsonify({'error':'Email already registered'}),409
    except Exception as e: return jsonify({'error':str(e)}),500


@app.route('/api/auth/application-status', methods=['GET'])
def application_status():
    """Public — user checks registration status by email. Uses COALESCE for old DB compat."""
    email = request.args.get('email','').strip().lower()
    if not email: return jsonify({'error':'Email is required'}),400
    try:
        conn = get_db(); cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        # COALESCE handles old DB where columns might be NULL
        cur.execute("""
            SELECT u.id, u.email, u.role, u.full_name, u.phone, u.created_at,
                   COALESCE(u.approval_status,'pending') AS approval_status,
                   u.approved_at, u.rejection_note,
                   COALESCE(u.is_active,FALSE) AS is_active,
                   up.land_district, up.land_state, up.farming_type,
                   up.lab_name, up.lab_licence_no, up.govt_id_type
            FROM users u
            LEFT JOIN user_profiles up ON u.id=up.user_id
            WHERE LOWER(u.email)=%s AND u.role!='admin'
        """, (email,))
        user = cur.fetchone()
        if not user: cur.close(); conn.close(); return jsonify({'error':'No registration found for this email'}),404
        user = dict(user); uid = user['id']

        try:
            cur.execute("SELECT doc_type,doc_label,uploaded_at,verified FROM registration_documents WHERE user_id=%s",(uid,))
            docs = [serialize(dict(d)) for d in cur.fetchall()]
        except Exception: docs = []

        try:
            cur.execute("SELECT event_type,payload,created_at,block_hash FROM audit_log WHERE entity_type='user' AND entity_id=%s ORDER BY created_at ASC",(str(uid),))
            audit = [serialize(dict(a)) for a in cur.fetchall()]
        except Exception: audit = []

        cur.close(); conn.close()
        labels = {
            'pending':  {'label':'Under Review 🔍','desc':'Your application is being reviewed. You can log in once an admin approves your account.'},
            'approved': {'label':'Approved ✓','desc':'Your account is active! You can now log in with your email and password.'},
            'rejected': {'label':'Rejected ✗','desc':'Your application was not approved. See the reason below.'},
        }
        return jsonify({'application':serialize(user),'documents':docs,'audit_trail':audit,'status_info':labels.get(user['approval_status'],labels['pending'])})
    except Exception as e: return jsonify({'error':str(e)}),500


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    if not data.get('email') or not data.get('password'): return jsonify({'error':'Email and password required'}),400
    try:
        conn = get_db(); cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM users WHERE LOWER(email)=LOWER(%s)",(data['email'],))
        user = cur.fetchone(); cur.close(); conn.close()
        if not user or not bcrypt.checkpw(data['password'].encode(),user['password_hash'].encode()):
            return jsonify({'error':'Invalid email or password'}),401
        if data.get('role') and user['role']!=data['role']:
            return jsonify({'error':f'This account is registered as "{user["role"]}", not "{data["role"]}"'}),403

        # ── Approval gate (non-admin only) ──────────────────────────────────
        if user['role'] != 'admin':
            status = user.get('approval_status') or 'pending'
            active = user.get('is_active') or False
            if status == 'pending':
                return jsonify({
                    'error':'Your registration is pending admin approval. You will receive access once an administrator reviews your application.',
                    'approval_status':'pending',
                    'hint':'Track your status at /application-status'
                }),403
            if status == 'rejected':
                reason = user.get('rejection_note') or 'No reason provided.'
                return jsonify({'error':f'Your registration was rejected. Reason: {reason}','approval_status':'rejected'}),403
            if not active:
                return jsonify({'error':'Your account is not active. Contact the administrator.'}),403

        token = jwt.encode({'user_id':str(user['id']),'email':user['email'],'role':user['role'],'exp':datetime.utcnow()+timedelta(days=7)},app.config['SECRET_KEY'],algorithm='HS256')
        return jsonify({'token':token,'user':{'id':str(user['id']),'email':user['email'],'role':user['role'],'full_name':user['full_name']}})
    except Exception as e: return jsonify({'error':str(e)}),500


@app.route('/api/auth/me', methods=['GET'])
@token_required
def get_me(u): return jsonify(u)


# ══════════════════════════════════════════════════════════════════
# ADMIN — Registration management
# ══════════════════════════════════════════════════════════════════

@app.route('/api/admin/registrations', methods=['GET'])
@token_required
@role_required('admin')
def admin_registrations(cu):
    sf=request.args.get('status','all'); rf=request.args.get('role','all')
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        conds=["u.role!='admin'"]; params=[]
        if sf!='all': conds.append("COALESCE(u.approval_status,'pending')=%s"); params.append(sf)
        if rf!='all': conds.append("u.role=%s"); params.append(rf)
        cur.execute(f"""
            SELECT u.id,u.email,u.role,u.full_name,u.phone,u.address,
                   COALESCE(u.approval_status,'pending') AS approval_status,
                   u.approved_at,u.rejection_note,u.created_at,
                   COALESCE(u.is_active,FALSE) AS is_active,
                   up.land_area_acres,up.land_district,up.land_state,up.farming_type,
                   up.lab_name,up.lab_licence_no,up.lab_accreditation,
                   up.govt_id_type,up.govt_id_number,
                   adm.full_name AS approved_by_name,
                   (SELECT COUNT(*) FROM registration_documents rd WHERE rd.user_id=u.id) AS doc_count
            FROM users u
            LEFT JOIN user_profiles up ON u.id=up.user_id
            LEFT JOIN users adm ON u.approved_by=adm.id
            WHERE {' AND '.join(conds)}
            ORDER BY CASE COALESCE(u.approval_status,'pending') WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END, u.created_at DESC
        """, params)
        regs=[serialize(dict(r)) for r in cur.fetchall()]
        cur.close(); conn.close()
        return jsonify({'registrations':regs,'total':len(regs)})
    except Exception as e: return jsonify({'error':str(e)}),500


@app.route('/api/admin/registrations/<uid>/documents', methods=['GET'])
@token_required
@role_required('admin')
def admin_user_docs(cu, uid):
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT rd.*,u.full_name,u.email,u.role FROM registration_documents rd JOIN users u ON rd.user_id=u.id WHERE rd.user_id=%s ORDER BY rd.uploaded_at",(uid,))
        docs=[serialize(dict(d)) for d in cur.fetchall()]
        cur.execute("SELECT * FROM user_profiles WHERE user_id=%s",(uid,))
        profile=cur.fetchone()
        cur.close(); conn.close()
        return jsonify({'documents':docs,'profile':serialize(dict(profile)) if profile else {}})
    except Exception as e: return jsonify({'error':str(e)}),500


@app.route('/api/admin/registrations/<uid>/approve', methods=['POST'])
@token_required
@role_required('admin')
def admin_approve(cu, uid):
    data=request.get_json() or {}
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM users WHERE id=%s AND role!='admin'",(uid,))
        user=cur.fetchone()
        if not user: cur.close(); conn.close(); return jsonify({'error':'User not found'}),404
        if (user.get('approval_status') or 'pending')=='approved': cur.close(); conn.close(); return jsonify({'error':'Already approved'}),400
        cur.execute("UPDATE users SET approval_status='approved',is_active=TRUE,approved_by=%s,approved_at=NOW(),rejection_note=NULL WHERE id=%s RETURNING email,full_name,role",(cu['user_id'],uid))
        upd=dict(cur.fetchone())
        cur.execute("UPDATE registration_documents SET verified=TRUE WHERE user_id=%s",(uid,))
        record_audit(conn,'REGISTRATION_APPROVED',cu['user_id'],'user',uid,{'email':upd['email'],'role':upd['role'],'by':cu.get('email','')})
        conn.commit(); cur.close(); conn.close()
        return jsonify({'message':f'✓ {upd["full_name"]} ({upd["role"]}) approved. They can now log in.','user':upd})
    except Exception as e: return jsonify({'error':str(e)}),500


@app.route('/api/admin/registrations/<uid>/reject', methods=['POST'])
@token_required
@role_required('admin')
def admin_reject(cu, uid):
    data=request.get_json() or {}
    reason=data.get('reason','').strip()
    if not reason: return jsonify({'error':'Rejection reason is required'}),400
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM users WHERE id=%s AND role!='admin'",(uid,))
        user=cur.fetchone()
        if not user: cur.close(); conn.close(); return jsonify({'error':'User not found'}),404
        cur.execute("UPDATE users SET approval_status='rejected',is_active=FALSE,approved_by=%s,approved_at=NOW(),rejection_note=%s WHERE id=%s RETURNING email,full_name,role",(cu['user_id'],reason,uid))
        upd=dict(cur.fetchone())
        record_audit(conn,'REGISTRATION_REJECTED',cu['user_id'],'user',uid,{'email':upd['email'],'role':upd['role'],'reason':reason})
        conn.commit(); cur.close(); conn.close()
        return jsonify({'message':f'✗ {upd["full_name"]} rejected.','user':upd})
    except Exception as e: return jsonify({'error':str(e)}),500


@app.route('/api/admin/audit-log', methods=['GET'])
@token_required
@role_required('admin')
def audit_log(cu):
    page=int(request.args.get('page',1)); pp=int(request.args.get('per_page',50))
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT COUNT(*) FROM audit_log"); total=cur.fetchone()['count']
        cur.execute("SELECT al.*,u.full_name AS actor_name,u.email AS actor_email FROM audit_log al LEFT JOIN users u ON al.actor_id::uuid=u.id ORDER BY al.sequence DESC LIMIT %s OFFSET %s",(pp,(page-1)*pp))
        logs=[serialize(dict(r)) for r in cur.fetchall()]
        cur.close(); conn.close()
        return jsonify({'logs':logs,'total':total,'page':page,'pages':(total+pp-1)//pp})
    except Exception as e: return jsonify({'error':str(e)}),500


@app.route('/api/admin/audit-log/verify', methods=['GET'])
@token_required
@role_required('admin')
def verify_chain(cu):
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM audit_log ORDER BY sequence ASC")
        logs=cur.fetchall(); cur.close(); conn.close()
        prev='0'*64; broken=None
        for i,log in enumerate(logs):
            pl=json.loads(log['payload']) if log['payload'] else {}
            ts=log['created_at'].isoformat() if hasattr(log['created_at'],'isoformat') else str(log['created_at'])
            ds=f"{prev}|{log['event_type']}|{log['actor_id']}|{log['entity_id']}|{json.dumps(pl,sort_keys=True)}|{ts}"
            if hashlib.sha256(ds.encode()).hexdigest()!=log['block_hash']: broken=i; break
            prev=log['block_hash']
        return jsonify({'chain_valid':broken is None,'total_blocks':len(logs),'broken_at':broken,
                        'message':'✓ Blockchain integrity verified.' if broken is None else f'⚠ Chain broken at block {broken}!'})
    except Exception as e: return jsonify({'error':str(e)}),500


@app.route('/api/admin/stats', methods=['GET'])
@token_required
@role_required('admin')
def admin_stats(cu):
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        s={}
        for k,q in [
            ('total_users',"SELECT COUNT(*) FROM users WHERE role!='admin'"),
            ('pending_registrations',"SELECT COUNT(*) FROM users WHERE COALESCE(approval_status,'pending')='pending' AND role!='admin'"),
            ('approved_users',"SELECT COUNT(*) FROM users WHERE approval_status='approved' AND role!='admin'"),
            ('rejected_users',"SELECT COUNT(*) FROM users WHERE approval_status='rejected' AND role!='admin'"),
            ('pending_farmers',"SELECT COUNT(*) FROM users WHERE COALESCE(approval_status,'pending')='pending' AND role='farmer'"),
            ('pending_labs',"SELECT COUNT(*) FROM users WHERE COALESCE(approval_status,'pending')='pending' AND role='lab'"),
            ('pending_consumers',"SELECT COUNT(*) FROM users WHERE COALESCE(approval_status,'pending')='pending' AND role='consumer'"),
            ('total_batches',"SELECT COUNT(*) FROM herb_batches"),
            ('approved_batches',"SELECT COUNT(*) FROM lab_tests WHERE overall_status='approved'"),
            ('total_products',"SELECT COUNT(*) FROM products"),
            ('total_audit_events',"SELECT COUNT(*) FROM audit_log"),
        ]:
            try: cur.execute(q); s[k]=cur.fetchone()['count']
            except Exception: s[k]=0
        cur.close(); conn.close()
        return jsonify({'stats':s})
    except Exception as e: return jsonify({'error':str(e)}),500


@app.route('/api/admin/users', methods=['GET'])
@token_required
@role_required('admin')
def admin_users(cu):
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT id,email,role,full_name,phone,created_at,COALESCE(is_active,FALSE) AS is_active,COALESCE(approval_status,'pending') AS approval_status FROM users ORDER BY created_at DESC")
        users=[serialize(dict(u)) for u in cur.fetchall()]
        cur.close(); conn.close(); return jsonify({'users':users})
    except Exception as e: return jsonify({'error':str(e)}),500


@app.route('/api/admin/batches', methods=['GET'])
@token_required
@role_required('admin')
def admin_batches(cu):
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT hb.*,u.full_name AS farmer_name,lt.overall_status AS lab_status,p.product_id FROM herb_batches hb LEFT JOIN users u ON hb.farmer_id=u.id LEFT JOIN lab_tests lt ON hb.batch_id=lt.batch_id LEFT JOIN products p ON hb.batch_id=p.batch_id ORDER BY hb.created_at DESC")
        batches=[serialize(dict(b)) for b in cur.fetchall()]
        cur.close(); conn.close(); return jsonify({'batches':batches})
    except Exception as e: return jsonify({'error':str(e)}),500


# ══════════════════════════════════════════════════════════════════
# FARMER
# ══════════════════════════════════════════════════════════════════

@app.route('/api/farmer/batches', methods=['POST'])
@token_required
@role_required('farmer','admin')
def create_batch(cu):
    data=request.form
    if not data.get('herb_species'): return jsonify({'error':'Herb species required'}),400
    if not data.get('harvest_date'): return jsonify({'error':'Harvest date required'}),400
    img=save_file(request.files.get('image'),'herb_')
    bid=f"BATCH-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("INSERT INTO herb_batches(batch_id,farmer_id,herb_species,quantity_kg,moisture_level,harvest_date,farming_practices,gps_lat,gps_lng,location_name,image_url,notes) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *",
                    (bid,cu['user_id'],data.get('herb_species'),data.get('quantity_kg') or None,data.get('moisture_level') or None,data.get('harvest_date'),data.get('farming_practices') or None,data.get('gps_lat') or None,data.get('gps_lng') or None,data.get('location_name'),img,data.get('notes')))
        batch=serialize(dict(cur.fetchone()))
        record_audit(conn,'BATCH_REGISTERED',cu['user_id'],'batch',bid,{'herb':data.get('herb_species')})
        conn.commit(); cur.close(); conn.close()
        return jsonify({'batch':batch,'message':f'Batch {bid} registered!'}),201
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/farmer/batches', methods=['GET'])
@token_required
@role_required('farmer','admin')
def list_batches(cu):
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        if cu['role']=='admin':
            cur.execute("SELECT hb.*,u.full_name AS farmer_name,lt.overall_status AS lab_status,p.product_id FROM herb_batches hb LEFT JOIN users u ON hb.farmer_id=u.id LEFT JOIN lab_tests lt ON hb.batch_id=lt.batch_id LEFT JOIN products p ON hb.batch_id=p.batch_id ORDER BY hb.created_at DESC")
        else:
            cur.execute("SELECT hb.*,lt.overall_status AS lab_status,p.product_id FROM herb_batches hb LEFT JOIN lab_tests lt ON hb.batch_id=lt.batch_id LEFT JOIN products p ON hb.batch_id=p.batch_id WHERE hb.farmer_id=%s ORDER BY hb.created_at DESC",(cu['user_id'],))
        batches=[serialize(dict(b)) for b in cur.fetchall()]
        cur.close(); conn.close(); return jsonify({'batches':batches})
    except Exception as e: return jsonify({'error':str(e)}),500


# ══════════════════════════════════════════════════════════════════
# PROCESSING
# ══════════════════════════════════════════════════════════════════

@app.route('/api/processing', methods=['POST'])
@token_required
@role_required('admin','lab')
def create_processing(cu):
    data=request.get_json() or {}; bid=data.get('batch_id','').strip()
    if not bid: return jsonify({'error':'batch_id required'}),400
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT batch_id,status FROM herb_batches WHERE batch_id=%s",(bid,))
        batch=cur.fetchone()
        if not batch: cur.close(); conn.close(); return jsonify({'error':f'Batch {bid} not found'}),404
        if batch['status']=='rejected': cur.close(); conn.close(); return jsonify({'error':'Cannot process rejected batch'}),400
        cur.execute("SELECT id FROM processing_records WHERE batch_id=%s",(bid,))
        if cur.fetchone():
            cur.execute("UPDATE processing_records SET drying_method=%s,drying_duration_hours=%s,drying_temperature=%s,grinding_status=%s,grinding_particle_size=%s,storage_temperature=%s,storage_humidity=%s,storage_location=%s,chain_of_custody=%s,notes=%s,processed_at=NOW() WHERE batch_id=%s RETURNING *",
                        (data.get('drying_method'),data.get('drying_duration_hours') or None,data.get('drying_temperature') or None,data.get('grinding_status',False),data.get('grinding_particle_size'),data.get('storage_temperature') or None,data.get('storage_humidity') or None,data.get('storage_location'),data.get('chain_of_custody'),data.get('notes'),bid))
        else:
            cur.execute("INSERT INTO processing_records(batch_id,processor_id,drying_method,drying_duration_hours,drying_temperature,grinding_status,grinding_particle_size,storage_temperature,storage_humidity,storage_location,chain_of_custody,notes) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *",
                        (bid,cu['user_id'],data.get('drying_method'),data.get('drying_duration_hours') or None,data.get('drying_temperature') or None,data.get('grinding_status',False),data.get('grinding_particle_size'),data.get('storage_temperature') or None,data.get('storage_humidity') or None,data.get('storage_location'),data.get('chain_of_custody'),data.get('notes')))
        rec=serialize(dict(cur.fetchone()))
        cur.execute("UPDATE herb_batches SET status='processing' WHERE batch_id=%s",(bid,))
        record_audit(conn,'BATCH_PROCESSING',cu['user_id'],'batch',bid,{'method':data.get('drying_method')})
        conn.commit(); cur.close(); conn.close()
        return jsonify({'record':rec,'message':'Processing saved!'}),201
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/processing/<bid>', methods=['GET'])
@token_required
def get_processing(cu, bid):
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM processing_records WHERE batch_id=%s ORDER BY processed_at DESC",(bid,))
        recs=[serialize(dict(r)) for r in cur.fetchall()]
        cur.close(); conn.close(); return jsonify({'records':recs})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/processing/list', methods=['GET'])
@token_required
@role_required('admin','lab')
def list_processing(cu):
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT pr.*,hb.herb_species,hb.status AS batch_status,u.full_name AS farmer_name FROM processing_records pr JOIN herb_batches hb ON pr.batch_id=hb.batch_id LEFT JOIN users u ON hb.farmer_id=u.id ORDER BY pr.processed_at DESC")
        recs=[serialize(dict(r)) for r in cur.fetchall()]
        cur.close(); conn.close(); return jsonify({'records':recs})
    except Exception as e: return jsonify({'error':str(e)}),500


# ══════════════════════════════════════════════════════════════════
# LAB
# ══════════════════════════════════════════════════════════════════

@app.route('/api/lab/batches', methods=['GET'])
@token_required
@role_required('lab','admin')
def lab_batches(cu):
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT hb.batch_id,hb.herb_species,hb.quantity_kg,hb.harvest_date,hb.status,hb.created_at,u.full_name AS farmer_name,lt.overall_status AS lab_status,pr.drying_method,p.product_id FROM herb_batches hb LEFT JOIN users u ON hb.farmer_id=u.id LEFT JOIN lab_tests lt ON hb.batch_id=lt.batch_id LEFT JOIN processing_records pr ON hb.batch_id=pr.batch_id LEFT JOIN products p ON hb.batch_id=p.batch_id WHERE hb.status!='rejected' ORDER BY hb.created_at DESC")
        batches=[serialize(dict(b)) for b in cur.fetchall()]
        cur.close(); conn.close(); return jsonify({'batches':batches})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/lab/tests', methods=['POST'])
@token_required
@role_required('lab','admin')
def create_lab_test(cu):
    data=request.form; bid=data.get('batch_id','').strip(); ost=data.get('overall_status','pending')
    if not bid: return jsonify({'error':'batch_id required'}),400
    if ost not in ('pending','approved','rejected'): return jsonify({'error':'Invalid status'}),400
    furls={}
    for fn in ('moisture_report','pesticide_report','dna_certificate'):
        url=save_file(request.files.get(fn),f'{fn}_')
        if url: furls[f'{fn}_url']=url
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT batch_id FROM herb_batches WHERE batch_id=%s",(bid,))
        if not cur.fetchone(): cur.close(); conn.close(); return jsonify({'error':f'Batch {bid} not found'}),404
        cur.execute("SELECT id FROM lab_tests WHERE batch_id=%s",(bid,))
        if cur.fetchone():
            cur.execute("UPDATE lab_tests SET moisture_content=%s,moisture_report_url=COALESCE(%s,moisture_report_url),pesticide_residue_result=%s,pesticide_report_url=COALESCE(%s,pesticide_report_url),dna_auth_result=%s,dna_certificate_url=COALESCE(%s,dna_certificate_url),heavy_metal_result=%s,microbial_count=%s,overall_status=%s,tested_by=%s,notes=%s,tested_at=NOW() WHERE batch_id=%s RETURNING *",
                        (data.get('moisture_content') or None,furls.get('moisture_report_url'),data.get('pesticide_residue_result') or None,furls.get('pesticide_report_url'),data.get('dna_auth_result') or None,furls.get('dna_certificate_url'),data.get('heavy_metal_result') or None,data.get('microbial_count') or None,ost,data.get('tested_by'),data.get('notes'),bid))
        else:
            cur.execute("INSERT INTO lab_tests(batch_id,lab_id,moisture_content,moisture_report_url,pesticide_residue_result,pesticide_report_url,dna_auth_result,dna_certificate_url,heavy_metal_result,microbial_count,overall_status,tested_by,notes) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *",
                        (bid,cu['user_id'],data.get('moisture_content') or None,furls.get('moisture_report_url'),data.get('pesticide_residue_result') or None,furls.get('pesticide_report_url'),data.get('dna_auth_result') or None,furls.get('dna_certificate_url'),data.get('heavy_metal_result') or None,data.get('microbial_count') or None,ost,data.get('tested_by'),data.get('notes')))
        test=serialize(dict(cur.fetchone()))
        ns={'approved':'approved','rejected':'rejected'}.get(ost,'testing')
        cur.execute("UPDATE herb_batches SET status=%s WHERE batch_id=%s",(ns,bid))
        record_audit(conn,f'LAB_TEST_{ost.upper()}',cu['user_id'],'batch',bid,{'status':ost,'by':data.get('tested_by')})
        conn.commit(); cur.close(); conn.close()
        return jsonify({'test':test,'message':f'Lab results saved. Batch → {ns}'}),201
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/lab/tests/<bid>', methods=['GET'])
@token_required
@role_required('lab','admin')
def get_lab_test(cu, bid):
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM lab_tests WHERE batch_id=%s ORDER BY tested_at DESC LIMIT 1",(bid,))
        row=cur.fetchone(); cur.close(); conn.close()
        return jsonify({'test':serialize(dict(row)) if row else None})
    except Exception as e: return jsonify({'error':str(e)}),500


# ══════════════════════════════════════════════════════════════════
# QR + CONSUMER
# ══════════════════════════════════════════════════════════════════

@app.route('/api/products/generate-qr', methods=['POST'])
@token_required
@role_required('lab','admin')
def gen_qr(cu):
    data=request.get_json() or {}; bid=data.get('batch_id','').strip()
    if not bid: return jsonify({'error':'batch_id required'}),400
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM herb_batches WHERE batch_id=%s",(bid,))
        batch=cur.fetchone()
        if not batch: cur.close(); conn.close(); return jsonify({'error':f'Batch {bid} not found'}),404
        cur.execute("SELECT overall_status FROM lab_tests WHERE batch_id=%s ORDER BY tested_at DESC LIMIT 1",(bid,))
        lab=cur.fetchone()
        if not lab or lab['overall_status']!='approved': cur.close(); conn.close(); return jsonify({'error':'QR only for lab-APPROVED batches'}),400
        cur.execute("SELECT product_id FROM products WHERE batch_id=%s",(bid,))
        ex=cur.fetchone()
        if ex: cur.close(); conn.close(); return jsonify({'error':'QR already exists','product_id':ex['product_id']}),409
        pid=f"PROD-{uuid.uuid4().hex[:10].upper()}"; scan=f"http://localhost:5173/consumer-portal?pid={pid}"; qr=make_qr(scan)
        cur.execute("INSERT INTO products(product_id,batch_id,qr_code_data,product_name,description,manufacturing_date,expiry_date) VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING *",
                    (pid,bid,f"data:image/png;base64,{qr}",data.get('product_name') or f"Herb - {batch['herb_species']}",data.get('description'),data.get('manufacturing_date') or datetime.now().date(),data.get('expiry_date')))
        product=serialize(dict(cur.fetchone()))
        record_audit(conn,'QR_GENERATED',cu['user_id'],'product',pid,{'batch_id':bid,'product_id':pid})
        conn.commit(); cur.close(); conn.close()
        return jsonify({'product':product,'product_id':pid,'qr_code':f"data:image/png;base64,{qr}",'scan_url':scan,'message':f'QR generated. Product ID: {pid}'}),201
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/products', methods=['GET'])
@token_required
@role_required('lab','admin')
def list_products(cu):
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT p.product_id,p.product_name,p.qr_code_data,p.created_at,hb.batch_id,hb.herb_species,hb.status FROM products p JOIN herb_batches hb ON p.batch_id=hb.batch_id ORDER BY p.created_at DESC")
        products=[serialize(dict(r)) for r in cur.fetchall()]
        cur.close(); conn.close(); return jsonify({'products':products})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/products/<pid>/scan', methods=['GET'])
def scan_product(pid):
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""SELECT p.product_id,p.product_name,p.description,p.manufacturing_date,p.expiry_date,p.qr_code_data,p.created_at,
            hb.batch_id,hb.herb_species,hb.quantity_kg,hb.moisture_level,hb.harvest_date,hb.farming_practices,hb.gps_lat,hb.gps_lng,hb.location_name,hb.image_url AS herb_image,
            u.full_name AS farmer_name,u.address AS farm_address,
            pr.drying_method,pr.drying_duration_hours,pr.grinding_status,pr.grinding_particle_size,pr.storage_temperature,pr.storage_humidity,pr.storage_location,pr.chain_of_custody,
            lt.moisture_content,lt.pesticide_residue_result,lt.pesticide_report_url,lt.dna_auth_result,lt.dna_certificate_url,lt.heavy_metal_result,lt.microbial_count,lt.overall_status AS lab_status,lt.tested_by,lt.tested_at,lt.moisture_report_url
            FROM products p JOIN herb_batches hb ON p.batch_id=hb.batch_id
            LEFT JOIN users u ON hb.farmer_id=u.id
            LEFT JOIN processing_records pr ON hb.batch_id=pr.batch_id
            LEFT JOIN lab_tests lt ON hb.batch_id=lt.batch_id
            WHERE p.product_id=%s AND p.is_public=TRUE""",(pid,))
        row=cur.fetchone()
        if row:
            try:
                cur.execute("INSERT INTO consumer_scans(product_id,user_agent,ip_address) VALUES(%s,%s,%s)",(pid,request.headers.get('User-Agent','')[:500],request.remote_addr))
                conn.commit()
            except: pass
        cur.close(); conn.close()
        if not row: return jsonify({'error':f'Product {pid} not found'}),404
        return jsonify({'product':serialize(dict(row))})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/consumer/search', methods=['GET'])
def search_product():
    q=request.args.get('q','').strip()
    if not q: return jsonify({'results':[],'count':0})
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT p.product_id,p.product_name,p.created_at,hb.herb_species,hb.harvest_date,lt.overall_status FROM products p JOIN herb_batches hb ON p.batch_id=hb.batch_id LEFT JOIN lab_tests lt ON hb.batch_id=lt.batch_id WHERE(p.product_id ILIKE %s OR p.product_name ILIKE %s OR hb.batch_id ILIKE %s OR hb.herb_species ILIKE %s)AND p.is_public=TRUE ORDER BY p.created_at DESC LIMIT 20",(f'%{q}%',)*4)
        results=[serialize(dict(r)) for r in cur.fetchall()]
        cur.close(); conn.close(); return jsonify({'results':results,'count':len(results)})
    except Exception as e: return jsonify({'error':str(e)}),500


# ══════════════════════════════════════════════════════════════════
# STATIC + HEALTH
# ══════════════════════════════════════════════════════════════════

@app.route('/uploads/<path:fn>')
def serve_upload(fn): return send_from_directory(app.config['UPLOAD_FOLDER'],fn)

@app.route('/api/health', methods=['GET'])
def health():
    try: conn=get_db(); conn.close(); db=True
    except: db=False
    return jsonify({'status':'ok' if db else 'db_error','db':'connected' if db else 'disconnected','timestamp':datetime.now().isoformat()})


if __name__=='__main__':
    print("="*55)
    print(" Ayurvedic Traceability System — Backend v6")
    print("="*55)
    try: init_db()
    except Exception as e: print(f"DB warning: {e}")
    app.run(debug=True,port=5000,host='0.0.0.0')
