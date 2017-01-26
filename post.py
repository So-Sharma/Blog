from google.appengine.ext import db
from helper import *


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    likes_count = db.IntegerProperty(default=0)
    list_users_likes = db.StringListProperty()
    author = db.StringProperty(required=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

    @staticmethod
    def get_post_key(post_id):
        key = db.Key.from_path('Post', int(post_id))
        return key