from google.appengine.ext import db
from post import Post


class Comments(db.Model):
    comment = db.StringProperty(required=True)
    username = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @staticmethod
    def get_comments_key_by_post(post_id, username):
        key = db.Key.from_path('Comments', parent=Post.get_post_key(post_id))
        return key

    @classmethod
    def get_comment_by_id(cls, comment_id, post_id):
        return Comments.get_by_id(int(comment_id), parent=Post.get_post_key(post_id))

    @classmethod
    def get_comment_key(cls, comment_id, post_id):
        key = db.Key.from_path('Comments', int(comment_id), parent=Post.get_post_key(post_id))
        return key