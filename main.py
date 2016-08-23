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

import webapp2
import cgi
import re

page_header = """
<!DOCTYPE html>
<html>
<head>
    <title>Signup</title>
    <style type="text/css">
        .error {
            color: red;
        }
    </style>
</head>
<body>
    <h1>Signup</h1>
    <form method="post">
    <table>
        <tr>
            <td>Username: </td>
            <td><input type="text" name="user_name" value="%(user_name)s"/></td>
            <td><span class = "error">%(error_user)s</span></td>
        </tr>
        <tr>
            <td>Password: </td>
            <td><input type="password" name="password"/></td>
            <td><span class = "error">%(error_pass)s</span></td>
        </tr>
        <tr>
            <td>Verify Password: </td>
            <td><input type="password" name="verify_password"/></td>
            <td><span class = "error">%(error_verify)s</span></td>
        </tr>
        <tr>
            <td>Email (optional): </td>
            <td><input type="text" name="email" value="%(email)s"/></td>
            <td><span class = "error">%(error_email)s</span></td>
        </tr>
        <tr><td><input type="submit"/><td></tr>
    </table
    </form>


"""
page_footer = """
</body>
</html>
"""

welcome_page = """
<!DOCTYPE html>
<html>
    <head>
        <title>Signup</title>
    </head>
        <body>
            <h1>Welcome, %s</h1>
        </body>
    </head>
</html>
"""

class Index(webapp2.RequestHandler):
    def write_form(self, user_name="", password="", verify_password="", email="", error_user="", error_pass="", error_verify="", error_email=""):
        self.response.write(page_header % {'user_name':user_name, 'password': password, 'verify_password':verify_password, 'email':email, 'error_user': error_user, 'error_pass': error_pass, 'error_verify': error_verify, 'error_email': error_email})

    def get(self):

        self.write_form()

    def post(self):

        user_name = self.request.get("user_name")
        password = self.request.get("password")
        verify_password = self.request.get("verify_password")
        email = self.request.get("email")
        error_user = ""
        error_pass = ""
        error_verify = ""
        error_email = ""


        USER_RE=re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        PASS_RE=re.compile(r"^.{3,20}$")
        EMAIL_RE=re.compile(r"^[\S]+@[\S]+.[\S]+$")

        def valid_username(username):
            return USER_RE.match(user_name)

        def valid_password(password):
            return PASS_RE.match(password)

        def valid_email(email):
            return EMAIL_RE.match(email)

        if not valid_username(user_name):
            error_user = "Not a valid User Name."

        if not valid_password(password):
            error_pass = "Not a valid Password."

        elif password != verify_password:
            error_verify = "Passwords don't match."

        if email == "":
            error_email = ""

        elif not valid_email(email):
            error_email = "Not a valid email address."

        if valid_username(user_name) and valid_password(password) and (valid_email(email) or email == "") and verify_password == password:
            self.redirect("/welcome?user_name=%s" % user_name)
            return

        else:
            self.write_form(user_name, password, verify_password, email, error_user, error_pass, error_verify, error_email)




class Welcome(webapp2.RequestHandler):
    def get(self):
        user_name = self.request.get("user_name")
        self.response.out.write(welcome_page % user_name)

app = webapp2.WSGIApplication([
    ('/', Index),
    ('/welcome', Welcome)
], debug=True)
