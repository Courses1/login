import webapp2
import os
import jinja2
import re

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader= jinja2.FileSystemLoader(template_dir), autoescape=True)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t= jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

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


class SignUpFormHandler(Handler):
    def get(self):
        self.render("signup.html", error="", form_data= "")

    def post(self):
        error = {}
        form_data = {}

        username = self.request.get("username")
        password = self.request.get("password")
        another_password = self.request.get("verify")
        email = self.request.get("email")

        form_data["username"] = username
        form_data["email"]  = email

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

        if not error:
            self.render("welcome.html", username= username)
        else:
            self.render("signup.html", error= error, form_data = form_data)
        # verify_username(username)


app = webapp2.WSGIApplication([
    ('/', SignUpFormHandler)],
    debug=True)
