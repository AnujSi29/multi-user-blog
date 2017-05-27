import os
import re
import random
import hashlib
import hmac
from string import letters


import webapp2
import jinja2

import logging
import time

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'fart'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

# 
class MainPage(BlogHandler):
    def get(self):
        self.write('Hello, Udacity!')

class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            return self.redirect('/signup')

class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            return self.redirect('/unit2/signup')

###### Unit 2 HW's
class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)


# Code related to user functionality
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)

# The user model
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# code related to the posts and comments
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

# the Post model
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    author_id = db.IntegerProperty(required=True)
    liked = db.ListProperty(int, required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def by_id(cls, pid):
        return Post.get_by_id(pid, parent=blog_key())

    def render(self, user, permalink):
        self._render_text = self.content.replace('\n', '<br>')
        self.liked_count = len(self.liked)
        return render_str("post.html", p=self, user=user,
                          author=User.by_id(int(self.author_id)),
                          permalink=permalink)

# the comment Model
class Comment(db.Model):
    author_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    content = db.TextProperty(required=True)
    liked = db.ListProperty(int, required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, pid):
        return Comment.get_by_id(pid, parent=blog_key())

    def render(self, user):
        self._render_text = self.content.replace('\n', '<br>')
        self.liked_count = len(self.liked)
        return render_str("comment.html", c=self, user=user,
                          author=User.by_id(int(self.author_id)))

# Use this function to remove all users, posts and comments
class ResetDatastore(BlogHandler):
    def get(self):
        self.logout()
        users = User.all()
        self.write("users: " + str(users.count()))
        posts = Post.all()
        self.write("<br>posts: " + str(posts.count()))
        comments = Comment.all()
        self.write("<br>comments: " + str(comments.count()))

        for u in users:
            u.delete()

        for p in posts:
            p.delete()

        for c in comments:
            c.delete()

        self.write("<br><br>deleting data...<br><br>")
        time.sleep(2)

        users = User.all()
        self.write("users: " + str(users.count()))
        posts = Post.all()
        self.write("<br>posts: " + str(posts.count()))
        comments = Comment.all()
        self.write("<br>comments: " + str(comments.count()))

# Render the blog front page
class BlogFront(BlogHandler):
    def get(self):
        posts = Post.all().order('-created')
        self.render('front.html', posts=posts, user=self.user)

# Render the single post view
class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        comments = Comment.all().filter(
            'post_id =', int(post_id)).order('created')

        self.render("permalink.html", post=post, comments=comments)

# Handle post creation
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            return self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject,
                     content=content, author_id=self.user.key().id())
            p.put()
            return self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)



# Handle post deletion
class DeletePost(BlogHandler):
    def get(self):
        if self.user:
            post_id = int(self.request.get('post_id'))
            post = Post.by_id(post_id)

            if not post:
                self.error(404)
                return

            if post.author_id != self.user.key().id():
                return self.redirect("/blog")

            self.render("deletepost.html", post=post)
        else:
            return self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/blog')

        post_id = int(self.request.get('post_id'))
        post = Post.by_id(post_id)
        if post is not None:
            if post.author_id != self.user.key().id():
                return self.redirect("/blog")

            post.delete()
            time.sleep(0.5)
            return self.redirect('/blog')
        else:
            self.error(404)
# Handle comment creation
class NewComment(BlogHandler):
    def post(self):
        if not self.user:
            return self.redirect('/blog')

        post_id = int(self.request.get('post_id'))
        content = self.request.get('content')

        if post_id and content:
            c = Comment(parent=blog_key(), post_id=post_id, content=content,
                        author_id=self.user.key().id())
            c.put()

        return self.redirect('/blog/%s' % str(post_id))

# Handle comment edit
class EditComment(BlogHandler):
    def get(self):
        if self.user:
            comment_id = int(self.request.get('comment_id'))
            comment = Comment.by_id(comment_id)

            if not comment:
                self.error(404)
                return

            if comment.author_id != self.user.key().id():
                return self.redirect("/blog")

            self.render("editcomment.html", comment=comment)
        else:
            return self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/blog')

        comment_id = int(self.request.get('comment_id'))
        comment = Comment.by_id(comment_id)
        if comment is not None:
            if comment.author_id != self.user.key().id():
                return self.redirect("/blog")

            content = self.request.get('content')

            if content:
                comment.content = content

                comment.put()
                return self.redirect('/blog/%s' % str(comment.post_id))
            else:
                error = "content, please!"
                self.render("editcomment.html", comment=comment,
                        error=error)
        else:
            self.error(404)

# Handle post edits
class EditPost(BlogHandler):
    def get(self):
        if self.user:
            post_id = int(self.request.get('post_id'))
            post = Post.by_id(post_id)

            if not post:
                self.error(404)
                return

            if post.author_id != self.user.key().id():
                return self.redirect("/blog")

            self.render("editpost.html", post=post)
        else:
            return self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/blog')

        post_id = int(self.request.get('post_id'))
        post = Post.by_id(post_id)
        if not post:
            self.error(404)
            return
        if post.author_id != self.user.key().id():
                return self.redirect("/blog")

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post.subject = subject
            post.content = content

            post.put()
            return self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "subject and content, please!"
            self.render("editpost.html", post=post,
                        error=error)

# Handle comment deletion
class DeleteComment(BlogHandler):
    def get(self):
        if self.user:
            comment_id = int(self.request.get('comment_id'))
            comment = Comment.by_id(comment_id)

            if not comment:
                self.error(404)
                return

            if comment.author_id != self.user.key().id():
                return self.redirect("/blog")

            self.render("deletecomment.html", comment=comment)
        else:
            return self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/blog')

        comment_id = int(self.request.get('comment_id'))
        comment = Comment.by_id(comment_id)
        if not comment:
                self.error(404)
                return
        if comment.author_id != self.user.key().id():
                return self.redirect("/blog")

        comment.delete()
        time.sleep(0.5)
        return self.redirect('/blog/%s' % str(comment.post_id))

# Handle the functionality of liking a post
class Like(BlogHandler):
    def get(self):
        if self.user:
            if self.request.get('post_id'):
                item_id = post_id = int(self.request.get('post_id'))
                
                item = Post.by_id(item_id)
                if not item:
                    self.error(404)
            elif self.request.get('comment_id'):
                item_id = int(self.request.get('comment_id'))
                item = Comment.by_id(item_id)
                if not item:
                    self.error(404)
                post_id = item.post_id

            uid = self.user.key().id()
            if uid != item.author_id and uid not in item.liked:
                item.liked.append(uid)
                item.put()
                time.sleep(0.5)

            if self.request.get('permalink') == 'True':
                return self.redirect('/blog/%s' % str(post_id))
            else:
                return self.redirect('/blog')

        else:
            return self.redirect("/login")





USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)

# Handle user account creation
class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError




# Handle user account login
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            return self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)
            
            
# Handle the functionality of disliking a post
class Dislike(BlogHandler):
    def get(self):
        if self.user:
            if self.request.get('post_id'):
                item_id = post_id = int(self.request.get('post_id'))
                item = Post.by_id(item_id)
                if not item:
                    self.error(404)
            elif self.request.get('comment_id'):
                item_id = int(self.request.get('comment_id'))
                item = Comment.by_id(item_id)
                if not item:
                    self.error(404)
                post_id = item.post_id

            uid = self.user.key().id()
            if uid in item.liked:
                item.liked.remove(uid)
                item.put()
                time.sleep(0.5)

            if self.request.get('permalink') == 'True':
                return self.redirect('/blog/%s' % str(post_id))
            else:
                return self.redirect('/blog')
        else:
            return self.redirect("/login")
            

# Handle user account logout
class Logout(BlogHandler):
    def get(self):
        self.logout()
        return self.redirect('/blog')
class Unit2Signup(Signup):
    def done(self):
        return self.redirect('/unit2/welcome?username=' + self.username)

class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            return self.redirect('/blog')


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/rot13', Rot13),
                               ('/unit2/signup', Unit2Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/newcomment', NewComment),
                               ('/blog/editpost', EditPost),
                               ('/blog/deletepost', DeletePost),
                               ('/blog/editcomment', EditComment),
                               ('/blog/deletecomment', DeleteComment),
                               ('/blog/like', Like),
                               ('/blog/dislike', Dislike),
                               ('/blog/reset', ResetDatastore),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/blog/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ],
                              debug=True)
