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

#Database Addition
from google.appengine.ext import ndb
from google.appengine.api import oauth

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))


class MainHandler(Handler):
	def get(self):
		self.render("welcome.html")
	def post(self):
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

		self.redirect("/")

class Login(Handler):
	def get(self):
		self.render("signup-form.html")

class Register(Handler):
	def get(self):
		self.render("welcome.html")

#DataBase Addition
class User(ndb.Model):
	name = ndb.StringProperty(required = True)
	pw_hash = ndb.StringProperty(required = True)
	email = ndb.StringProperty(required = True)

class Event(ndb.Model):
	date = ndb.DateProperty(required = True)
	time = ndb.TimeProperty(required = True)
	place = ndb.StringProperty(required = True)

class Group(ndb.Model):
	admin = ndb.StringProperty(required = True)
	name1 = ndb.StringProperty(required = True)
	name2 = ndb.StringProperty(required = True)
	name3 = ndb.StringProperty(required = True)
	name4 = ndb.StringProperty(required = True)
	name5 = ndb.StringProperty(required = True)



app = webapp2.WSGIApplication([
	('/', MainHandler),
	('/Login', Login),
	('/Register', Register)
], debug=True)
