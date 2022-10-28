"""database module"""

import mysql.connector

import click
from flask import current_app
from flask import g
from flask.cli import with_appcontext


def get_db():
    """Connect to the application's configured database. The connection
    is unique for each request and will be reused if this is called
    again.
    """
    if "db" not in g:
        g.db = mysql.connector.connect(
            host=current_app.config['DATABASE_HOST'],
            database=current_app.config['DATABASE_NAME'],
            user=current_app.config['DATABASE_USER'],
            password=current_app.config['DATABASE_PASSWORD'],
            autocommit=True
        )

    return g.db


def close_db(e=None):  # pylint: disable=unused-argument
    """If this request connected to the database, close the
    connection.
    """
    db = g.pop("db", None)

    if db is not None:
        db.close()


def init_db():
    """Clear existing data and create new tables."""

    db = get_db()
    with current_app.open_resource("schema.sql") as f:
        for line in f.read().decode("utf8").splitlines():
            db.cursor().execute(line)
    db.commit()


@click.command("init-db")
@with_appcontext
def init_db_command():
    """Clear existing data and create new tables."""
    init_db()
    click.echo("Initialized the database.")


def init_app(app):
    """Register database functions with the Flask app. This is called by
    the application factory.
    """
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
