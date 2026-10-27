import os, sqlite3, secrets, functools, csv, io, re
from pathlib import Path
from datetime import timedelta
import click
from flask import Flask, render_template, request, redirect, url_for, session, abort, flash, Response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
store = Path(os.environ.get('DATA_DIR', str(Path(__file__).parent / 'instance')))
store.mkdir(parents=True, exist_ok=True)
keyfile = store / 'secret.key'
if not keyfile.exists():
    try:
        fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f: f.write(secrets.token_hex(32))
    except FileExistsError: pass
app.config.update(SECRET_KEY=os.environ.get('SECRET_KEY') or keyfile.read_text(), SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE') == '1', PERMANENT_SESSION_LIFETIME=timedelta(hours=2), MAX_CONTENT_LENGTH=65536)
CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, storage_uri=os.environ.get('RATELIMIT_STORAGE_URI', 'memory://'), default_limits=['300 per hour'])
def db():
    c = sqlite3.connect(store / 'pesantren.sqlite3', timeout=20)
    c.row_factory = sqlite3.Row
    return c
with db() as c:
    c.executescript("""CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT);
CREATE TABLE IF NOT EXISTS news(id INTEGER PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL, created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS applicants(id INTEGER PRIMARY KEY, code TEXT UNIQUE, name TEXT, gender TEXT, guardian TEXT, phone TEXT, address TEXT, program TEXT, status TEXT DEFAULT 'Baru', created TEXT DEFAULT CURRENT_TIMESTAMP);""")
    defaults={'name':'Pondok Pesantren Sabilunnajat','tagline':'Ruang tumbuh dalam ilmu dan akhlak','profile':'Profil resmi pesantren belum diisi. Pengelola dapat memperbaruinya melalui panel admin.','programs':'Informasi program belum diisi','address':'Alamat belum diisi','whatsapp':'','registration':'closed','requirements':'Persyaratan dan jadwal belum diisi. Silakan hubungi pengelola.'}
    c.executemany('INSERT OR IGNORE INTO settings VALUES (?,?)',defaults.items())
@app.context_processor
def common():
    with db() as c: settings=dict(c.execute('SELECT key,value FROM settings').fetchall())
    return dict(s=settings)
def admin_required(fn):
    @functools.wraps(fn)
    def wrapped(*a,**kw):
        if not session.get('admin'): return redirect(url_for('login'))
        return fn(*a,**kw)
    return wrapped
@app.after_request
def headers(r):
    r.headers['X-Content-Type-Options']='nosniff'
    r.headers['X-Frame-Options']='DENY'
    r.headers['Referrer-Policy']='same-origin'
    r.headers['Content-Security-Policy']="default-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    if request.path.startswith('/admin') or request.path.startswith('/daftar'): r.headers['Cache-Control']='no-store'
    return r
@app.route('/')
def home():
    with db() as c: news=c.execute('SELECT * FROM news ORDER BY id DESC LIMIT 6').fetchall()
    return render_template('home.html',news=news)
@app.route('/berita/<int:id>')
def article(id):
    with db() as c: n=c.execute('SELECT * FROM news WHERE id=?',(id,)).fetchone()
    if not n: abort(404)
    return render_template('article.html',n=n)
@app.route('/daftar',methods=['GET','POST'])
@limiter.limit('10 per hour',methods=['POST'])
def register():
    settings=common()['s']
    if request.method=='POST':
        if settings['registration']!='open': abort(403)
        data={k:request.form.get(k,'').strip() for k in ['name','gender','guardian','phone','address','program']}
        if any(not v or len(v)>1000 for v in data.values()) or data['gender'] not in ['Putra','Putri'] or not re.fullmatch(r'[+0-9 ()-]{8,25}',data['phone']) or request.form.get('consent')!='yes':
            flash('Periksa isian, nomor WhatsApp, dan persetujuan.'); return render_template('register.html'),400
        code='SN-'+secrets.token_hex(6).upper()
        with db() as c: c.execute('INSERT INTO applicants(code,name,gender,guardian,phone,address,program) VALUES (?,?,?,?,?,?,?)',(code,*data.values()))
        return render_template('success.html',code=code)
    return render_template('register.html')
@app.route('/admin/login',methods=['GET','POST'])
@limiter.limit('5 per minute',methods=['POST'])
def login():
    if request.method=='POST':
        with db() as c: u=c.execute('SELECT * FROM admins WHERE username=?',(request.form.get('username',''),)).fetchone()
        if u and check_password_hash(u['password'],request.form.get('password','')):
            session.clear(); session['admin']=u['id']; session.permanent=True
            return redirect(url_for('dashboard'))
        flash('Username atau kata sandi salah.')
    return render_template('login.html')
@app.post('/admin/logout')
@admin_required
def logout():
    session.clear(); return redirect(url_for('home'))
@app.route('/admin')
@admin_required
def dashboard():
    q=request.args.get('q','')[:100]
    with db() as c:
        people=c.execute('SELECT * FROM applicants WHERE name LIKE ? OR code LIKE ? ORDER BY id DESC',('%'+q+'%','%'+q+'%')).fetchall()
        news=c.execute('SELECT * FROM news ORDER BY id DESC').fetchall()
    return render_template('admin.html',people=people,news=news,q=q)
@app.post('/admin/settings')
@admin_required
def settings_save():
    values={k:request.form.get(k,'').strip()[:10000] for k in defaults}
    if values['registration'] not in ['open','closed']: abort(400)
    if values['whatsapp'] and not re.fullmatch(r'[0-9]{8,16}',values['whatsapp']):
        flash('WhatsApp harus berupa angka kode negara, contoh 628123456789.'); return redirect(url_for('dashboard'))
    with db() as c: c.executemany('UPDATE settings SET value=? WHERE key=?',[(v,k) for k,v in values.items()])
    flash('Pengaturan disimpan.'); return redirect(url_for('dashboard'))
@app.route('/admin/news',methods=['GET','POST'])
@app.route('/admin/news/<int:id>',methods=['GET','POST'])
@admin_required
def edit_news(id=None):
    with db() as c:
        n=c.execute('SELECT * FROM news WHERE id=?',(id,)).fetchone() if id else None
        if id and not n: abort(404)
        if request.method=='POST':
            title=request.form.get('title','').strip()[:200]; body=request.form.get('body','').strip()[:20000]
            if not title or not body: abort(400)
            if id: c.execute('UPDATE news SET title=?,body=? WHERE id=?',(title,body,id))
            else: c.execute('INSERT INTO news(title,body) VALUES (?,?)',(title,body))
            return redirect(url_for('dashboard'))
    return render_template('editor.html',n=n)
@app.post('/admin/news/<int:id>/delete')
@admin_required
def delete_news(id):
    with db() as c: c.execute('DELETE FROM news WHERE id=?',(id,))
    return redirect(url_for('dashboard'))
@app.post('/admin/applicants/<int:id>')
@admin_required
def change_applicant(id):
    action=request.form.get('action')
    with db() as c:
        if action=='delete': c.execute('DELETE FROM applicants WHERE id=?',(id,))
        elif request.form.get('status') in ['Baru','Diverifikasi','Diterima','Tidak diterima']:
            c.execute('UPDATE applicants SET status=? WHERE id=?',(request.form['status'],id))
        else: abort(400)
    return redirect(url_for('dashboard'))
@app.get('/admin/export')
@admin_required
def export():
    out=io.StringIO(); w=csv.writer(out)
    with db() as c:
        cur=c.execute('SELECT * FROM applicants ORDER BY id DESC'); w.writerow([d[0] for d in cur.description])
        for row in cur:
            w.writerow(["'"+v if isinstance(v,str) and v.lstrip().startswith(('=','+','-','@','\t','\r')) else v for v in row])
    return Response('\ufeff'+out.getvalue(),mimetype='text/csv',headers={'Content-Disposition':'attachment; filename=pendaftar.csv'})
@app.route('/admin/password',methods=['GET','POST'])
@admin_required
def password():
    if request.method=='POST':
        with db() as c:
            u=c.execute('SELECT * FROM admins WHERE id=?',(session['admin'],)).fetchone()
            new=request.form.get('new','')
            if not u or not check_password_hash(u['password'],request.form.get('old','')) or len(new)<12:
                flash('Kata sandi lama salah atau kata sandi baru kurang dari 12 karakter.')
            else:
                c.execute('UPDATE admins SET password=? WHERE id=?',(generate_password_hash(new),u['id']))
                session.clear(); flash('Kata sandi diganti. Silakan login kembali.'); return redirect(url_for('login'))
    return render_template('password.html')
@app.cli.command('create-admin')
@click.option('--username',prompt=True)
@click.password_option(confirmation_prompt=True)
def create_admin(username,password):
    if len(password)<12: raise click.ClickException('Gunakan minimal 12 karakter.')
    try:
        with db() as c: c.execute('INSERT INTO admins(username,password) VALUES (?,?)',(username,generate_password_hash(password)))
    except sqlite3.IntegrityError: raise click.ClickException('Username sudah digunakan.')
    click.echo('Admin berhasil dibuat.')
if __name__=='__main__': app.run(host='127.0.0.1',port=5000)
