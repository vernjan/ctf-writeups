"""attendance evidence app"""

import os

from flask import Flask


FLAG = 'atestflag'
SECRET_KEY = 'selohtibbaraebthgimereht'
PASSWORD_POLICY = 30
DATABASE_HOST = 'dbserver'
DATABASE_NAME = 'attendance'
DATABASE_USER = 'attendance'
DATABASE_PASSWORD = 'ATTENDANCEPASSWORD'


def create_app(test_config=None):
    """Create and configure an instance of the Flask application."""
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get('SECRET_KEY', SECRET_KEY),
        FLAG=os.environ.get('FLAG', FLAG),
        PASSWORD_POLICY=PASSWORD_POLICY,
        DATABASE_HOST=DATABASE_HOST,
        DATABASE_NAME=DATABASE_NAME,
        DATABASE_USER=DATABASE_USER,
        DATABASE_PASSWORD=os.environ.get('DATABASE_PASSWORD', DATABASE_PASSWORD)
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile("config.py", silent=True)
    else:
        # load the test config if passed in
        app.config.update(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    @app.route("/hello")
    def hello():
        return "Hello, World!"

    # register the database commands
    from flaskr import db  # pylint: disable=import-outside-toplevel

    db.init_app(app)

    # apply the blueprints to the app
    from flaskr import auth, blog  # pylint: disable=import-outside-toplevel

    app.register_blueprint(auth.bp)
    app.register_blueprint(blog.bp)

    # make url_for('index') == url_for('blog.index')
    # in another app, you might define a separate main index here with
    # app.route, while giving the blog blueprint a url_prefix, but for
    # the tutorial the blog will be the main index
    app.add_url_rule("/", endpoint="index")

    return app
