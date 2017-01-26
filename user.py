from google.appengine.ext import db
import hashlib
import random
from string import letters


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

# User information
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