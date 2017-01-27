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
import logging

import webapp2
from google.appengine.ext import db

from comments import Comments
from helper import *
from post import Post
from user import User


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


# This is for registering a new user
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

            # If username exists, display error message to the user
            # Else, register the new user
            if user:
                params['error_user'] = "This user already exists"
                self.render('registration.html', **params)
            else:
                u = User.register(username, password, email)
                u.put()
                self.login(u)
                self.redirect('/blog')


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
            # self.redirect('/welcome?username=' + username)
            self.redirect('/blog')
        else:
            error_message = 'Invalid login id and password'
            self.render('login.html', error=error_message)


# This is for adding a new post to the DB
class NewPost(Handler):
    def get(self):
        self.render("newpost.html", user=self.user)

    def post(self):
        if not self.user:
            self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            # Add the post to DB
            post = Post(author=self.user.username,
                        subject=subject,
                        content=content,
                        likes_count=0)
            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            # If subject or content missing, display error message
            params = dict(subject=subject,
                          content=content,
                          user=self.user)
            params['error'] = "Please enter the subject and content"
            self.render('newpost.html', **params)


# This is for displaying the details of a particular post
class PostDetails(Handler):
    def get(self, post_id):
        # Retrieve Post details and comments for the selected post
        key = Post.get_post_key(post_id)
        post = db.get(key)
        comments = db.GqlQuery('Select * from Comments where ancestor is :1',
                               key)

        if not post:
            self.error(404)
            return

        if self.user:
            username = self.user.username
            if username in post.list_users_likes:
                is_liked=True
            else:
                is_liked=False
        else:
            is_liked = False

        self.render("permalink.html",
                    post=post,
                    comments=comments,
                    user=self.user,
                    is_liked=is_liked)

    def post(self, post_id):
        if not self.user:
            self.redirect('/login')

        action = self.request.get('submit')
        key = Post.get_post_key(post_id)

        if action == 'Delete Post':
            # Delete Post
            db.delete(key)

            # Delete associated comments
            # comments_key = Comments.get_comments_key_by_post(post_id)
            # db.delete(comments_key)
            self.redirect('/blog')
        elif action == 'Like':
            post = db.get(key)
            post.likes_count += 1
            list_likes = post.list_users_likes
            list_likes.append(self.user.username)
            post.list_users_likes = list_likes
            post.put()

            self.redirect('/blog/%s' % str(post.key().id()))
        elif action == 'Unlike':
            post = db.get(key)
            post.likes_count -= 1
            list_likes = post.list_users_likes
            list_likes.remove(self.user.username)
            post.list_users_likes = list_likes
            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            comment = self.request.get('comment')

            if comment:
                comments = Comments(comment=comment,
                                    username=self.user.username,
                                    parent=key)
                comments.put()
                post = db.get(key)
                self.redirect('/blog/%s' % str(post.key().id()))
            else:
                error = "Please enter the comment"
                post = db.get(key)
                comments = db.GqlQuery(
                    'Select * from Comments where ancestor is :1', key)
                self.render("permalink.html", post=post, comments=comments,
                            error=error, user=self.user)


# This displays the the most recent 10 posts on the blogs landing page
class BlogsLanding(Handler):
    def get(self):
        posts = db.GqlQuery(
            "Select * from Post order by created desc limit 10")
        self.render('blogslanding.html', posts=posts, user=self.user)


# This is used to edit an existing post
class EditPost(Handler):
    def get(self):
        post_id = self.request.get('post_id')
        key = Post.get_post_key(post_id)
        post = db.get(key)

        if not post:
            self.error(404)
            return
        self.render("editpost.html", post=post, user=self.user)

    def post(self):
        if not self.user:
            self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')

        # Get the post which user wants to update
        post_id = self.request.get('post_id')
        key = Post.get_post_key(post_id)
        post = db.get(key)

        # Update post details in the DB if subject and content provided.
        # Else, display error message to user if subject or content missing
        if subject and content:
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            params = dict(subject=subject,
                          content=content,
                          post=post,
                          user=self.user)
            params['error'] = "Please enter the subject and content"
            self.render('editpost.html', **params)


# This is used to edit an existing comment
class EditComment(Handler):
    def get(self):
        comment_id = self.request.get('comment_id')
        post_id = self.request.get('post_id')
        comment = Comments.get_comment_by_id(comment_id, post_id)

        if not comment:
            self.error(404)
            return
        self.render("editcomment.html", comment=comment,
                    post_id=post_id, user=self.user)

    def post(self):
        if not self.user:
            self.redirect('/login')

        new_comment = self.request.get('comment')

        # Get the comment which needs to be updated
        comment_id = self.request.get('comment_id')
        post_id = self.request.get('post_id')
        comment = Comments.get_comment_by_id(comment_id, post_id)

        # Update comment details in the DB.
        # Else, display error message to the user if comment missing
        if new_comment:
            comment.comment = new_comment
            comment.put()
            self.redirect('/blog/%s' % str(post_id))
        else:
            error = "Please enter the comment"
            self.render("editcomment.html", comment=comment,
                        error=error, user=self.user)


# This is used to delete an existing comment
class DeleteComment(Handler):
    def get(self):
        comment_id = self.request.get('comment_id')
        post_id = self.request.get('post_id')
        key = Comments.get_comment_key(comment_id, post_id)
        db.delete(key)
        self.redirect('/blog/%s' % str(post_id))


# This is for logging out the user from the application
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
    ('/blog/editpost/?', EditPost),
    ('/blog/editcomment/?', EditComment),
    ('/blog/deletecomment/?', DeleteComment),
    ('/logout', Logout),
],
    debug=True)
