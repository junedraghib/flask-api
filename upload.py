from flask import Flask, render_template, request, make_response, jsonify
from werkzeug import secure_filename
from datetime import timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
import datetime


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key'
limiter = Limiter(app, key_func=get_remote_address)

def error_handler():
    return render_template("upload.html")
@app.route("/")
def index():
    return render_template("index.html", data={'token':"no token issues", 'message':"no message"})

@app.route("/login", methods=['GET', 'POST'])
def login():

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
    # auth = request.authorization
    if username == 'testuser'and password == 'password':
        token = jwt.encode({'user': username, 'exp': datetime.datetime.utcnow()
        + datetime.timedelta(minutes=2)}, app.config['SECRET_KEY'])
        app.config['token'] = token
        return render_template("index.html", data={'token':app.config['token'], 'message':"no message"})
    
    return make_response("could not verify", 401, {'WWW-Authenticate' : 'Basic realm="login required"'})
     
@app.route("/auth", methods=['GET', 'POST'])
def auth():
    if  request.method == 'POST':
        token = request.form['token']

        if not token:
            return render_template("index.html", message="Token is missing")
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            if data['user'] == 'testuser':
                return render_template("upload.html")
        except:
            return render_template("index.html", data={'token':app.config['token'], 'message':"token is invalid or expired"})

@app.route("/uploader", methods = ['GET', 'POST'])
@limiter.limit("5 per minute", error_message=error_handler)
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        f.save(secure_filename(f.filename)) 
        return render_template("result.html", filename=f.filename)

@app.route("/end")
def end():
    return render_template("index.html", data={'token':app.config['token'], 'message':"no message"})        
          
if __name__ == '__main__':
     app.run(debug = True)
