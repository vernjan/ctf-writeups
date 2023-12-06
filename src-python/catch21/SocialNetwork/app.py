"""my superprofile app"""

import os

from flask import flash, Flask, redirect, render_template, request, session, url_for


FLAG = os.environ.get('FLAG', 'admin')
USERS = {'admin': FLAG}

app = Flask(__name__)
app.secret_key = 'f3cfe9ed8fae309f02079dbf'


@app.before_request
def before_request():
    """before request handler"""

    if 'username' not in session:
        session['username'] = None


@app.route('/')
def index():
    """login route"""

    return render_template('index.html', username=session.get('username'), data=FLAG)


@app.route('/login', methods=['POST'])
def login():
    """login route"""

    if request.method == 'POST':
        if USERS.get(request.form.get('username')) == request.form.get('password'):
            session['username'] = request.form['username']
        else:
            flash('invalid credentials')

    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    """logout route"""

    session.pop('username', None)
    return redirect(url_for('index'))