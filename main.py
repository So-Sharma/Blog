#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re

import logging
import webapp2
import jinja2
import hmac
import random
import hashlib
from string import letters
from google.appengine.ext import db

try:
    template_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'templates')
    # os.path.join(os.path.dirname(_file_), 'templates')
except NameError:  # We are the main py2exe script, not a module
    import sys

    template_dir = os.path.join(os.path.dirname(sys.argv[0]), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

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


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

        # to be modified

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(**params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def login(self, user):
        self.set_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


# User information
def make_salt(len=5):
    return ''.join(random.choice(letters) for x in range(len))


def hash_pw(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    hash = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, hash)


def valid_pw(name, password, saved_hash):
    salt = saved_hash.split(',')[0]
    new_hash = hash_pw(name, password, salt)
    if new_hash == saved_hash:
        return True
    else:
        return False


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    username = db.StringProperty(required=True)
    password_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @staticmethod
    def get_user_key(username):
        key = db.Key.from_path('User', username, parent=users_key())
        return key

    @classmethod
    def by_name(cls, name):
        user = User.all().filter('username =', name).get()
        return user

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = hash_pw(name, pw)
        return User(parent=users_key(),
                    username=name,
                    password_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        user = cls.by_name(name)
        if user:
            if valid_pw(name, pw, user.password_hash):
                return user


USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return USERNAME_RE.match(username)


PASSWORD_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return PASSWORD_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(Handler):
    def get(self):
        self.render("registration.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        is_errors = False

        params = dict(username=username,
                      email=email)

        if not valid_username(username):
            params['error_username'] = "The username is not valid"
            is_errors = True

        if not valid_password(password):
            params['error_password'] = "The password is not valid"
            is_errors = True
        elif password != verify:
            params['error_verify'] = "The passwords didn't match"
            is_errors = True

        if not valid_email(email):
            params['error_email'] = "The email is not valid"
            is_errors = True

        if is_errors:
            self.render('registration.html', **params)
        else:
            user = User.by_name(username)
            if user:
                params['error_user'] = "This user already exists"
                self.render('registration.html', **params)
            else:
                u = User.register(username, password, email)
                u.put()
                self.login(u)
                self.redirect('/welcome?username=' + username)


class Welcome(Handler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render("welcome.html", username=username)
        else:
            self.redirect('/signup')


class Login(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        user = User.login(username, password)
        if user:
            self.login(user)
            self.redirect('/welcome?username=' + username)
        else:
            error_message = 'Invalid login id and password'
            self.render('login.html', error=error_message)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    likes_count = db.IntegerProperty(default=0)
    list_users_likes = db.StringListProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

    @staticmethod
    def get_post_key(post_id, username):
        # key = db.Key.from_path('Post', int(post_id), parent=users_key())
        key = db.Key.from_path('Post', int(post_id), parent=User.get_user_key(username))
        return key


class Comments(db.Model):
    comment = db.StringProperty(required=True)
    username = db.StringProperty(required=True)

    @staticmethod
    def get_comments_key_by_post(post_id, username):
        key = db.Key.from_path('Comments', parent=Post.get_post_key(post_id, username))
        return key


class NewPost(Handler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        if not self.user:
            self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post = Post(parent=User.get_user_key(self.user.username),
                        subject=subject,
                        content=content,
                        likes_count=0)
            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            params = dict(subject=subject,
                          content=content)
            params['error'] = "Please enter the subject and content"
            self.render('newpost.html', **params)


class PostDetails(Handler):
    def get(self, post_id):
        key = Post.get_post_key(post_id, self.user.username)
        post = db.get(key)
        comments = db.GqlQuery('Select * from Comments where ancestor is :1', key)

        if not post:
            self.error(404)
            return
        self.render("permalink.html", post=post, comments=comments, user=self.user)

    def post(self, post_id):
        action = self.request.get('submit')
        key = Post.get_post_key(post_id, self.user.username)

        if action == 'Delete Post':
            # Delete Post
            db.delete(key)

            # Delete associated comments
            # comments_key = Comments.get_comments_key_by_post(post_id)
            # db.delete(comments_key)
            self.redirect('/blog/?')
            # logging.info("** Delete called with post id {}! **".format(comments_key))
        elif action == 'Like':
            post = db.get(key)
            post.likes_count += 1
            list_likes = post.list_users_likes
            list_likes.append(self.user.username)
            post.list_users_likes = list_likes
            post.put()

            logging.info("** Like called with post id {}! **".format(self.user.username))
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            comment = self.request.get('comment')
            comments = Comments(comment=comment,
                                username=self.user.username,
                                parent=key)
            comments.put()
            post = db.get(key)
            self.redirect('/blog/%s' % str(post.key().id()))


class BlogsLanding(Handler):
    def get(self):
        posts = db.GqlQuery("Select * from Post order by created desc limit 10")
        self.render('blogslanding.html', posts=posts, user=self.user)


class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/signup')


app = webapp2.WSGIApplication([
    ('/signup', Signup),
    ('/welcome', Welcome),
    ('/login', Login),
    ('/blog/?', BlogsLanding),
    ('/blog/newpost', NewPost),
    ('/blog/([0-9]+)', PostDetails),
    ('/logout', Logout),
],
    debug=True)
