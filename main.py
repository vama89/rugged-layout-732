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

#Template Jinja Imports and Fresh Startup
import webapp2
import jinja2
import os

#Sign-in import Code will go here:
import re
import random
import hashlib
import hmac
from string import letters

#Database Addition
from google.appengine.ext import db
from google.appengine.api import oauth

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

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


class MainHandler(BlogHandler):
	def get(self):
		#if logged-in
			#go to the welcome.html
		#else:
			#go to home.html
		self.render("home.html")

class CreateEvent(BlogHandler):
	def render_front(self, 	event = "",
							date_frame_open="",
							date_frame_close="",
							friend1="",
							friend2="",
							friend3="",
							friend4="",
							friend5="",
							date1="",
							time1="",
							place1="",
							date2="",
							time2="",
							place2="",
							date3="",
							time3="",
							place3=""):

		self.render("create.html", 	event = event,
									date_frame_open=date_frame_open,
									date_frame_close=date_frame_close,
									friend1=friend1,
									friend2=friend2,
									friend3=friend3,
									friend4=friend4,
									friend5=friend5,
									date1=date1,
									time1=time1,
									place1=place1,
									date2=date2,
									time2=time2,
									place2=place2,
									date3=date3,
									time3=time3,
									place3=place3)
	def get(self):
		self.render_front()

	def post(self):
		event = self.request.get("event")

		date_frame_open = self.request.get("date_frame_open")
		date_frame_close = self.request.get("date_frame_close")

		friend1 = self.request.get("friend1")
		friend2 = self.request.get("friend2")
		friend3 = self.request.get("friend3")
		friend4 = self.request.get("friend4")
		friend5 = self.request.get("friend5")
		
		date1 = self.request.get("date1") 
		time1 = self.request.get("time1")
		place1 = self.request.get("place1")

		date2 = self.request.get("date2")
		time2 = self.request.get("time2")
		place2 = self.request.get("place2")

		date3 = self.request.get("date3")
		time3 = self.request.get("time3")
		place3 = self.request.get("place3")

		try:
			hangout = Event(event = event,
							date_frame_open=date_frame_open,
							date_frame_close=date_frame_close,
							friend1=friend1,
							friend2=friend2,
							friend3=friend3,
							friend4=friend4,
							friend5=friend5,
							date1=date1,
							time1=time1,
							place1=place1,
							date2=date2,
							time2=time2,
							place2=place2,
							date3=date3,
							time3=time3,
							place3=place3)
		
			event.put()
			self.redirect('/')

		except:
			self.render("create.html", 	event = event,
										date_frame_open=date_frame_open,
										date_frame_close=date_frame_close,
										friend1=friend1,
										friend2=friend2,
										friend3=friend3,
										friend4=friend4,
										friend5=friend5,
										date1=date1,
										time1=time1,
										place1=place1,
										date2=date2,
										time2=time2,
										place2=place2,
										date3=date3,
										time3=time3,
										place3=place3 )

		#self.redirect("/CreateEvent")

class Vote(BlogHandler):
	def get(self):
		self.render("vote.html")

class Welcome(BlogHandler):
	def get(self):
		self.render("welcome.html")


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

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

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')

class Login(BlogHandler):
    def get(self):
    	if self.request.cookies:
    		self.render("welcome.html")
    	else:
    		self.render("register.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.render("welcome.html")
        else:
            msg = 'Invalid login'
            self.render('register.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')


#DataBase Addition
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

class Event(db.Model):
	eventName = db.StringProperty(required = True)

	timeFrameOpen = db.StringProperty(required=True)
	timeFrameClose = db.StringProperty(required=True)

	hang1VoteCount = db.IntegerProperty(required = True)
	hang2VoteCount = db.IntegerProperty(required = True)
	hang3VoteCount = db.IntegerProperty(required = True)

	userNumberTotal= db.IntegerProperty(required = True)

	user1Vote = db.BooleanProperty(required = True)
	user2Vote = db.BooleanProperty(required = True)
	user3Vote = db.BooleanProperty(required = True)
	user4Vote = db.BooleanProperty(required = True)
	user5Vote = db.BooleanProperty(required = True)

	user1 = db.StringProperty(required=True)
	user2 = db.StringProperty(required=True)
	user3 = db.StringProperty(required=True)
	user4 = db.StringProperty(required=True)
	user5 = db.StringProperty(required=True)

	date1 = db.DateProperty(required = True)
	time1 = db.TimeProperty(required = True)
	place1 = db.StringProperty(required = True)

	date2 = db.DateProperty(required = True)
	time2 = db.TimeProperty(required = True)
	place2 = db.StringProperty(required = True)

	date3 = db.DateProperty(required = True)
	time3 = db.TimeProperty(required = True)
	place3 = db.StringProperty(required = True)

app = webapp2.WSGIApplication([
	('/', MainHandler),
	('/Login', Login),
	('/Register', Register),
	('/Logout', Logout),
	('/CreateEvent', CreateEvent),
	('/Vote', Vote),
	('/Welcome', Welcome)
], debug=True)
