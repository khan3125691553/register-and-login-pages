from flask import Flask, render_template, redirect, request, url_for, session
from flask_mysqldb import MySQL
import bcrypt


app = Flask(__name__)
#database information stored
app.secret_key = "YOUR SECRET KEY"
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'flask_users'

mysql = MySQL(app)
#link creating
@app.route('/')
def index():
   if 'username' in session:   #username present than goto page
    return render_template('index.html', username=session['username'])
   else:
    return render_template('index.html')
   #another page creating
@app.route('/login', methods=['GET','POST']) #methode for page 
def login():
  if request.method == "POST": #if check username and password our database and select and goto render page
    username = request.form['username'] #username in database checking
    pwd = request.form['password'] #password checking
    salt = bcrypt.gensalt(rounds=15)
    hashed_password = bcrypt.hashpw(pwd, salt)
    checkpassword = bcrypt.checkpw(pwd.encode("utf-8"), hashed_password.encode('utf-8'))
    
    # new = hashlib.new("SHA256")
    # new.update(user.encode())
    # newpassword = new.hexdigest()
    cur = mysql.connection.cursor() #mysql Connection starting
    # cur.execute(f"select username, password from tbl_users where username ='{username}'")
    cur.execute(f"SELECT `username`, `password` FROM `tbl_users` WHERE `username` ='{username}' AND `password` ='{checkpassword}'")
    user = cur.fetchone() #find in database table and then login
    cur.close() #database connection Closed
    if user and pwd == user[1]: #if user is present 
      session['username'] = user[0] #if user not present
      return redirect(url_for('index'))
    else:
      return render_template('login.html', error = "INVALID USER & PASSWORD")
  else: 
    return render_template('login.html')
#Creating a new page user Register page 
@app.route('/register', methods=['GET','POST'])
def reister():
  if request.method == "POST":
    username = request.form['username']
    pwd = request.form['password']
    salt = bcrypt.gensalt(rounds=15)
    hashed_password = bcrypt.hashpw(pwd.encode('utf-8'), salt.decode('utf-8'))
    
    # new = hashlib.new("SHA256")
    # new.update(user.encode())
    # newpassword = new.hexdigest()

    cur = mysql.connection.cursor()
    cur.execute(f"INSERT INTO tbl_users (username, password) VALUES ('{username}', '{hashed_password}')") #user inserting in database table
    mysql.connection.commit()
    cur.close()
    return redirect(url_for('login'))
  return render_template('register.html')
#another page creating and destory the session
@app.route('/logout')
def logout():
  session.pop('username', None)
  return redirect(url_for('index'))

if (__name__) == '__main__':
  app.run(debug=True, port=2000)