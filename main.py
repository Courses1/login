import webapp2
import os
import jinja2
import re
import hashlib
import random
import string
import hmac
from google.appengine.ext import db


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader= jinja2.FileSystemLoader(template_dir), autoescape=True)

SEPERATOR = "|"
SECRET_KEY = 'SomeSecretKey!'
USER_COOKIE_NAME = 'user-id'

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_secure_val(value):
    value = str(value)
    encoded_value = hmac.new(value + SECRET_KEY).hexdigest()
    return '%s%s%s' % (value, SEPERATOR, encoded_value)

def check_secure_val(encoded_value):
    value = encoded_value.split(SEPERATOR)[0]
    hash_value = encoded_value.split(SEPERATOR)[1]
    derived_value = make_secure_val(value)
    if(derived_value == encoded_value):
        return True
    else:
        return False

def make_password_secure(username, password):
    h = hashlib.sha256(username + password + SECRET_KEY).hexdigest()
    return '%s' % (h)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t= jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val);
        self.response.headers.add_header('Set-Cookie','%s=%s; Path=/' %(name,cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)

        if(cookie_val and check_secure_val(cookie_val)):
            return cookie_val
        else:
            return None

    def set_login_cookie(self, user):
        user_id = user.key().id()
        self.set_secure_cookie(USER_COOKIE_NAME, user_id)

    def remove_login_cookie(self):
        self.response.headers.add_header('Set-Cookie','%s=; Path=/' %(USER_COOKIE_NAME))



def verify_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return USER_RE.match(username)

def verify_password(password):
    PASSWORD_RE = re.compile(r"^.{3,20}$")
    return PASSWORD_RE.match(password)

def check_password_match(password, verify_password):
    return password == verify_password

def verify_email(email):
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
    return EMAIL_RE.match(email)

def validate_data(username, password, another_password, email):
        error = {}
        if not verify_username(username):
            error["username_error"]= "That's not valid username!"

        if not verify_password(password):
            error["password_error"] = "That's not valid password!"

        if email:
            if not verify_email(email):
                error["email_error"]= "That's not valid email!"

        if password and another_password:
            if not check_password_match(password, another_password):
                error["password_match_error"] = "Password did not match!"

        if(User._byname(username) != None):
            error["username_error"] = "User already exists!"

        return error

class User(db.Model):
   username = db.StringProperty(required = True)
   password = db.StringProperty(required = True)
   email = db.StringProperty(required = False)

   @classmethod
   def _byname(cls, name):
        u = User.all().filter('username =',name).get()
        return u

   @classmethod
   def _byid(cls, id):
        u = User.get_by_id(long(id))
        print "***user", u
        return u

   @classmethod
   def register_user(cls, username, password, email):
        return User(username = username, password = make_password_secure(username, password), email = email)

   @classmethod
   def login(cls, username, password):
        user = User._byname(username)
        if user :
            password_hash = make_password_secure(username, password)
            if(password_hash == user.password):
                return user
        else:
            return None


class SignUpFormHandler(Handler):
    def get(self):
        self.render("signup.html", error="", form_data= "")

    def post(self):
        form_data = {}

        username = self.request.get("username")
        password = self.request.get("password")
        another_password = self.request.get("verify")
        email = self.request.get("email")

        form_data["username"] = username
        form_data["email"]  = email

        error = validate_data(username = username, password = password, another_password = another_password,  email= email)


        if not error:
            user = User.register_user(username, password, email)
            user.put()
            self.set_login_cookie(user)
            self.redirect('/welcome')
        else:
            self.render("signup.html", error= error, form_data = form_data)

class WelcomeHandler(Handler):
    def get(self):
        cookie_value = self.read_secure_cookie(USER_COOKIE_NAME)
        if(cookie_value):
            id = cookie_value.split(SEPERATOR)[0]
            user = User._byid(id)
            self.render("welcome.html", username = user.username)
        else:
            self.redirect("/signup")

class LoginHandler(Handler):
    def get(self):
        self.render("login.html", error="", username = "")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")

        print "Username: %s, password: %s" % (username, password)

        if not username or not password:
            error = "Please, enter username and password!"
        else:
            user = User.login(username = username, password = password)
            if(user != None ):
                self.set_login_cookie(user)
                self.redirect("/welcome")
            else:
                self.render("login.html", error= "Invalid login!", username="")

class LogoutHandler(Handler):
    def get(self):
        self.remove_login_cookie()
        self.redirect('/signup')


app = webapp2.WSGIApplication([
    ('/signup', SignUpFormHandler),
    ('/welcome', WelcomeHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler)
    ],
    debug=True)
