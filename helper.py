import hmac
import os
import jinja2
import re

try:
    template_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                'templates')
    # os.path.join(os.path.dirname(_file_), 'templates')
except NameError:  # We are the main py2exe script, not a module
    import sys

    template_dir = os.path.join(os.path.dirname(sys.argv[0]), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# These functions are used for authentication
secret = "narrate"


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


# These functions are used for validating user information
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return USERNAME_RE.match(username)


PASSWORD_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return PASSWORD_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)