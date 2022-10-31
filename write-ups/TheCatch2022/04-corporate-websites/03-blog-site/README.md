# Blog site

Hi, packet inspector,

a simple blog webpage was created where all employees can write their suggestions for improvements. It is one part of
the optimization plan designed by our allmighty AI.

Examine the web http://blog.mysterious-delivery.tcc:20000/ and find any interesting information.

May the Packet be with you!

---

- users can be enumerated on login page
- dirb output
- git dump
    - source code
    - git forencics?
- /settings - I need admin role
    - would R/O SQLi help in any way? I dont think so
    - or I need to read env variables but that's probably not the goal
- SECRET_KEY = selohtibbaraebthgimereht - theremightbearabbitholes
- DB
  DATABASE_HOST = 'dbserver'
  DATABASE_NAME = 'attendance'
  DATABASE_USER = 'attendance'
  DATABASE_PASSWORD = 'ATTENDANCEPASSWORD'
- g.db = mysql.connector.connect(user='ctfb5', password='56843437e5c747a2c9c08e4b79f109c3', database='ctfb5',
  autocommit=True)
- flask-unsignefd
  https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/flask
- https://github.com/pallets/flask/issues/4714