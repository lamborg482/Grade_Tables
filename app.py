from flask import Flask, render_template, request, redirect, url_for, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, current_user, login_required, UserMixin, LoginManager, logout_user
import psycopg2
from functools import wraps
from psycopg2.extensions import AsIs

app = Flask(__name__)
app.static_folder = 'static'
app.secret_key = 'My_secret_KEY_Is_1sb23j3482*@*$U@#881oaf*@*efjn*@3r28hUHUH@jn1hu*@njnj2kmsdr,gp,@#<r<PFWE232r3f"":{@#<RLM@kwfksmdkoc2k3lr3plM@M#RKM@o3rmk2mfwfwf}dvfdvefbv4}}}}}{}{}{wef23f3f}dvedvefvwfv'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def get_db_connection():
    conn = psycopg2.connect(
            host='localhost',
            dbname='postgres',
            user='postgres',
            password='1639',
            port=6666
        )
    return conn

class Users(UserMixin):
    def __init__(self, id, username, password_hash, role):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role = role 

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if current_user.role not in roles:
                return redirect(url_for('main_reg'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''SELECT id, username, password_hash, role FROM users WHERE id = %s''',
                (user_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    if user:
        return Users(*user)
    return None     

@app.route("/") 
@app.route("/main_noreg", methods=["GET", "POST"])
def main_noreg():
    return render_template("main_noreg.html")

@app.route("/save_she", methods=['POST', 'GET'])
def save_she():
    data = request.json
    table = data['table']
    rows = data['data']
    table = str(table)
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        for row in rows:
            cur.execute(
                "UPDATE %s SET time = %s, object = %s, room = %s WHERE id = %s",
                (AsIs(table), row['time'], row['object'], row['room'], row['id'])
            )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        print(f"Error: {e}")
        return jsonify({'success': False, 'error': str(e)})
    
@app.route("/save_use", methods=['POST', 'GET'])
def save_use():
    data = request.json
    rows = data['data']
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        for row in rows:
            print(
                "UPDATE users SET email = %s, username = %s, role = %s WHERE id = %s",
                (row['email'], row['username'], row['role'], row['id'])
            )
            cur.execute(
                "UPDATE users SET email = %s, username = %s, role = %s WHERE id = %s",
                (row['email'], row['username'], row['role'], row['id'])
            )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        print(f"Error: {e}")
        return jsonify({'success': False, 'error': str(e)})
    
@app.route("/main_reg")
@login_required
def main_reg():
    return render_template("main_reg.html")
    
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        conn = get_db_connection()
        cur = conn.cursor()
        username = request.form.get("username")
        password = request.form.get("password")
        cur.execute("SELECT id, username, password_hash, role FROM users WHERE username=%s",
                    (username,))
        hash = cur.fetchone()
        cur.close()
        conn.close()
        if hash and Users(*hash).check_password(password):
                user = Users(*hash)
                login_user(user)
                if user.role == 'admin':
                    return redirect(url_for("main_adm"))
                elif user.role == 'moder':
                    return redirect(url_for("main_mod"))
                else:
                    return redirect(url_for("main_reg"))
        return redirect("/login ")
    return render_template("login.html")


@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == 'POST':
        conn = get_db_connection()
        cur = conn.cursor()
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        role = "user"
        hash = generate_password_hash(password)
        cur.execute('''INSERT INTO users (username, password_hash, email, role) VALUES (%s, %s, %s, %s)''',
                    (username, hash, email, role))
        conn.commit()
        cur.close()
        conn.close()
        return redirect(url_for("main_reg"))
    return render_template("register.html")

@app.route("/about_us")
def about_us():
    return render_template("about_us.html")

@app.route("/appoint", methods=["GET", "POST"])
@login_required
@role_required(['admin'])
def appoint():
    query = '''SELECT * FROM users'''
    conn = get_db_connection()
    cur = conn.cursor()
    search = request.form.get("search")
    cur.execute(query, (f"%{search}%",))
    post = cur.fetchall()
    print(f"Tables found: {post}")
    if post:
        cur.close()
        conn.close()
        return render_template("appoint.html", post=post, search=search)
    cur.close()
    conn.close()
    return redirect('/appoint')

@app.route("/main_mod", methods=["GET", "POST"])
@login_required
@role_required(['admin', 'moder'])
def main_mod():
    return render_template("main_mod.html")

@app.route("/main_adm")
@login_required
@role_required(['admin'])
def main_adm():
    return render_template("main_adm.html")

@app.route("/all_edit_schedule_adm", methods=["GET", "POST"])
@login_required
@role_required(['admin', 'moder'])
def all_edit_schedule_adm():
    query = '''SELECT tablename FROM pg_tables WHERE tablename LIKE %s '''
    conn = get_db_connection()
    cur = conn.cursor()
    search = request.form.get("search")
    cur.execute(query, (f"%{search}%",))
    post = cur.fetchall()
    print(f"Tables found: {post}")
    if post:
        table_name_1 = post[0][0]
        table_name_2 = post[1][0]
        table_name_3 = post[2][0]
        table_name_4 = post[3][0]
        table_name_5 = post[4][0]
        query = f'''SELECT * FROM "{table_name_1}" ''' 
        cur.execute(query)
        rows1 = cur.fetchall()
        query = f'''SELECT * FROM "{table_name_2}" ''' 
        cur.execute(query)
        rows2 = cur.fetchall()
        query = f'''SELECT * FROM "{table_name_3}" ''' 
        cur.execute(query)
        rows3 = cur.fetchall()
        query = f'''SELECT * FROM "{table_name_4}" ''' 
        cur.execute(query)
        rows4 = cur.fetchall()
        query = f'''SELECT * FROM "{table_name_5}" ''' 
        cur.execute(query)
        rows5 = cur.fetchall()
        cur.close()
        conn.close()
        return render_template("all_edit_schedule_adm.html", post=post, search=search, rows1=rows1, rows2=rows2, rows3=rows3, rows4=rows4, rows5=rows5)
    cur.close()
    conn.close()
    return redirect('/main_adm')

@app.route("/all_edit_schedule_mod", methods=["GET", "POST"])
@login_required
@role_required(['admin', 'moder'])
def all_edit_schedule_mod():
    query = '''SELECT tablename FROM pg_tables WHERE tablename LIKE %s '''
    conn = get_db_connection()
    cur = conn.cursor()
    search = request.form.get("search")
    cur.execute(query, (f"%{search}%",))
    post = cur.fetchall()
    print(f"Tables found: {post}")
    if post:
        table_name_1 = post[0][0]
        table_name_2 = post[1][0]
        table_name_3 = post[2][0]
        table_name_4 = post[3][0]
        table_name_5 = post[4][0]
        query = f'''SELECT * FROM "{table_name_1}" ''' 
        cur.execute(query)
        rows1 = cur.fetchall()
        query = f'''SELECT * FROM "{table_name_2}" ''' 
        cur.execute(query)
        rows2 = cur.fetchall()
        query = f'''SELECT * FROM "{table_name_3}" ''' 
        cur.execute(query)
        rows3 = cur.fetchall()
        query = f'''SELECT * FROM "{table_name_4}" ''' 
        cur.execute(query)
        rows4 = cur.fetchall()
        query = f'''SELECT * FROM "{table_name_5}" ''' 
        cur.execute(query)
        rows5 = cur.fetchall()
        cur.close()
        conn.close()
        return render_template("all_edit_schedule_mod.html", post=post, search=search, rows1=rows1, rows2=rows2, rows3=rows3, rows4=rows4, rows5=rows5)
    cur.close()
    conn.close()
    return redirect('/main_mod')

@app.route("/all_schedule", methods=["POST", "GET"])
@login_required
def all_schedule():
    query = '''SELECT tablename FROM pg_tables WHERE tablename LIKE %s '''
    conn = get_db_connection()
    cur = conn.cursor()
    search = request.form.get("search")
    cur.execute(query, (f"%{search}%",))
    post = cur.fetchall()
    if post:
        table_name_1 = post[0][0]
        table_name_2 = post[1][0]
        table_name_3 = post[2][0]
        table_name_4 = post[3][0]
        table_name_5 = post[4][0]
        query = f'''SELECT * FROM "{table_name_1}" ''' 
        cur.execute(query)
        rows1 = cur.fetchall()
        query = f'''SELECT * FROM "{table_name_2}" ''' 
        cur.execute(query)
        rows2 = cur.fetchall()
        query = f'''SELECT * FROM "{table_name_3}" ''' 
        cur.execute(query)
        rows3 = cur.fetchall()
        query = f'''SELECT * FROM "{table_name_4}" ''' 
        cur.execute(query)
        rows4 = cur.fetchall()
        query = f'''SELECT * FROM "{table_name_5}" ''' 
        cur.execute(query)
        rows5 = cur.fetchall()
        cur.close()
        conn.close()
        return render_template("all_schedule.html", post=post, search=search, rows1=rows1, rows2=rows2, rows3=rows3, rows4=rows4, rows5=rows5)
    cur.close()
    conn.close()
    return redirect('/main_reg')
    
@app.route("/exit")
@login_required
def exit():
    logout_user()
    return redirect(url_for('main_noreg'))  

if __name__ == "__main__":
    app.run(debug=True)