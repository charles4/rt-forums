from flask import Flask, render_template, session, redirect, url_for, abort, request, flash
from flask.ext.sqlalchemy import SQLAlchemy
from flaskext.bcrypt import Bcrypt 

from sqlalchemy import exc

from functools import wraps
import time
from datetime import datetime

import hashlib
import random

#### session management stuff
from simplekv.memory import DictStore
from flaskext.kvsession import KVSessionExtension

store = DictStore()

### email
from flask_mail import Mail
from flask_mail import Message


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
app.secret_key = 'W\xa8\x01\x83c\t\x06\x07p\x9c\xed\x13 \x98\x17\x0f\xf9\xbe\x18\x8a|I\xf4U'


bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
mail = Mail(app)

# this will replace the app's session handling
KVSessionExtension(store, app)


###### define database structure ####

class School(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	schoolname = db.Column(db.String(128))
	country = db.Column(db.String(64))
	created = db.Column(db.DateTime)

	def __init__(self, schoolname, country, create_date=None):
		self.schoolname = schoolname
		self.country = country
		if create_date is None:
			create_date = datetime.utcnow()
		self.created = create_date


	def __repr__(self):
		return '<school ' + self.schoolname + ">"

class Teacher(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	firstname = db.Column(db.String(32))
	lastname = db.Column(db.String(32))
	email = db.Column(db.String(128), unique=True)
	phash = db.Column(db.String(64))
	isAdmin = db.Column(db.String(5))
	created = db.Column(db.DateTime)
	secretquestion = db.Column(db.String(256))
	secretanswer = db.Column(db.String(256))
	onetimekey = db.Column(db.String(64))

	### db relationships
	school_id = db.Column(db.Integer, db.ForeignKey('school.id'))
	school = db.relationship('School', backref=db.backref('teachers', lazy='dynamic'))

	def __init__(self, email=None, school=None, key=None, firstname=None, lastname=None, password=None, secretquestion=None, secretanswer=None, isAdmin=False, create_date=None):
		self.firstname = firstname
		self.lastname = lastname
		self.email = email
		self.phash = bcrypt.generate_password_hash(password, 14)
		self.isAdmin = isAdmin
		if create_date is None:
			create_date = datetime.utcnow()
		self.created = create_date
		self.school = school
		self.secretquestion = secretquestion
		self.secretanswer = secretanswer
		self.onetimekey = key


	def __repr__(self):
		return '<Teacher %r>' % (self.firstname + " " + self.lastname)

class Grade(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	numeric_repr = db.Column(db.Integer)
	name = db.Column(db.String(32))

	### relationships
	school_id = db.Column(db.Integer, db.ForeignKey('school.id'))
	school = db.relationship('School', backref=db.backref('grades', lazy='dynamic'))

	def __init__(self, name, numeric_repr, school):
		self.name = name
		self.numeric_repr = numeric_repr
		self.school = school

	def __repr__(self):
		return '<grade: %r>' % self.name

class Student(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	firstname = db.Column(db.String(32))
	lastname = db.Column(db.String(32))
	created = db.Column(db.DateTime)

	### relationships
	grade_id = db.Column(db.Integer, db.ForeignKey('grade.id'))
	grade = db.relationship('Grade', backref=db.backref('students',lazy='dynamic'))

	def __init__(self, firstname, lastname, grade, create_date=None):
		self.firstname = firstname
		self.lastname = lastname
		self.grade = grade
		if create_date is None:
			create_date = datetime.utcnow()
		self.created = create_date

	def __repr__(self):
		return "<student %r>" % (self.firstname + " " + self.lastname)

class Post(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(256))
	created = db.Column(db.DateTime)

	## relationships
	author_id = db.Column(db.Integer, db.ForeignKey('teacher.id'))
	author = db.relationship('Teacher', backref=db.backref('posts',lazy='dynamic'))

	student_id = db.Column(db.Integer, db.ForeignKey('student.id'))
	student = db.relationship('Student', backref=db.backref('posts', lazy='dynamic'))

	def __init__(self, title, teacher, student, create_date=None):
		self.title = title
		self.author = teacher
		self.student = student
		if create_date is None:
			create_date = datetime.utcnow()
		self.created = create_date

	def __repr__(self):
		return "<post %r>" % self.title

class Comment(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	created = db.Column(db.DateTime)
	content = db.Column(db.String)

	### relationships
	author_id = db.Column(db.Integer, db.ForeignKey('teacher.id'))
	author = db.relationship('Teacher', backref=db.backref('comments', lazy='dynamic'))

	post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
	post = db.relationship('Post', backref=db.backref('comments',lazy='dynamic'))

	def __init__(self, content, teacher, post, create_date=None):
		self.content = content
		self.author = teacher
		self.post = post
		if create_date is None:
			create_date = datetime.utcnow()
		self.created = create_date

		### for each teacher create a unviewed comment
		teachers = Teacher.query.filter_by(school_id=session['user'].school_id)
		for t in teachers:
			if t.id != session['user'].id:
				uvc = UnviewedComment(self, t)
				db.session.add(uvc)
		db.session.commit()

	def __repr__(self):
		return "<comment %r>" % self.content

class UnviewedComment(db.Model):
	id = db.Column(db.Integer, primary_key=True)

	### relationships
	comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'))
	comment = db.relationship('Comment', backref=db.backref('unviewed', lazy='dynamic'))

	teacher_id = db.Column(db.Integer, db.ForeignKey('teacher.id'))
	teacher = db.relationship('Teacher', backref=db.backref('unviewed', lazy='dynamic'))

	def __init__(self, comment, teacher):
		self.comment=comment
		self.teacher=teacher

	def __repr__(self):
		return "<UnviewedComment %r>" % self.id

class PermissionToken(db.Model):
	id = db.Column(db.Integer, primary_key=True)

	### relationships
	student_id = db.Column(db.Integer, db.ForeignKey('student.id'))
	student = db.relationship('Student', backref=db.backref('tokens', lazy='dynamic'))

	teacher_id = db.Column(db.Integer, db.ForeignKey('teacher.id'))
	teacher = db.relationship('Teacher', backref=db.backref('tokens', lazy='dynamic'))

	def __init__(self, student, teacher):
		self.student = student
		self.teacher = teacher

	def __repr__(self):
		return "<PermissionToken %r>" % self.id

#### wrappers ####

def methodTimer(function):
	@wraps(function)
	def decorated_view(*args, **kwargs):
		t = time.time()
		result = function(*args, **kwargs)
		print function.__name__ + " took " + str(time.time() - t) + " seconds."
		return result
	return decorated_view

def requireLogin(fn):
	@wraps(fn)
	def decorated(*args, **kwargs):
		if 'user' in session:
			return fn(*args, **kwargs)
		return redirect(url_for("route_login"))
	return decorated

def requireAdmin(fn):
	@wraps(fn)
	def decorated(*args, **kwargs):
		if "user" in session:
			if session["user"].isAdmin == "1":
				return fn(*args, **kwargs)
		abort(401)

	return decorated

def requirePermission(fn):
	@wraps(fn)
	def decorated(*args, **kwargs):
		print kwargs
		teacher = session['user']
		db.session.add(teacher)
		allowed = teacher.tokens.all()
		for token in allowed:
			if str(token.student_id) == str(kwargs["student_id"]):
				return fn(*args, **kwargs)
		flash("You don't have permission to view the forum belonging to that student. Your school's admin can fix that.")
		return redirect(url_for("route_home_grade", grade=kwargs["grade"]))
	return decorated

### General Methods ###

def logout():
	session.pop('user', None)

def createGrades(school):
	db.session.add(Grade("Kindergarden", 0, school))
	db.session.add(Grade("First Grade", 1, school))
	db.session.add(Grade("Second Grade", 2, school))
	db.session.add(Grade("Third Grade", 3, school))
	db.session.add(Grade("Fourth Grade", 4, school))
	db.session.add(Grade("Fifth Grade", 5, school))
	db.session.add(Grade("Sixth Grade", 6, school))
	db.session.add(Grade("Seventh Grade", 7, school))
	db.session.add(Grade("Eighth Grade", 8, school))
	db.session.add(Grade("Ninth Grade", 9, school))
	db.session.add(Grade("Tenth Grade", 10, school))
	db.session.add(Grade("Eleventh Grade", 11, school))
	db.session.add(Grade("Twelfth Grade", 12, school))
	db.session.add(Grade("Graduated", 13, school))
	try:
		db.session.commit()
	except exc.SQLAlchemyError, e:
		print str(e)


### routes ###

@app.route("/", methods=['GET', 'POST'])
def route_login():
	if request.method == "POST":
		user = Teacher.query.filter_by(email=request.form['email']).first()
		if user != None:
			if bcrypt.check_password_hash(user.phash, request.form['password']):
				session['user'] = user
				session['grades'] = Grade.query.filter_by(school_id=session['user'].school_id).all()
				session['school'] = School.query.filter_by(id=session['user'].school_id).first()
				print session['school']
				return redirect(url_for('route_home'))

			else:
				flash('You entered an incorrect password.')
				return render_template("template_login.html")
		else:
			flash("The email address you entered was not found.")
			return render_template("template_login.html")
	else:
		return render_template("template_login.html")

@app.route("/login/")
def route_login_redirect():
	return redirect(url_for("route_login"))

@app.route("/logout/")
def route_logout():
	logout()
	return redirect(url_for('route_login'))

@app.route("/passwordreset/", methods=['GET'])
def route_passwordreset_step1():
	### generate onetime unique key
	base = "abcdefghijklmnopqrstuvwxyz123456789.!@#$%^"
	salt = ''.join(random.sample(base, len(base)))
	session['skey'] = hashlib.sha256(salt).hexdigest()

	return render_template("template_resetpassword_step1.html", secret_key=session['skey'])

@app.route("/passwordreset/step2/", methods=['GET', 'POST'])
def route_passwordreset_step2():
	
	if request.method == "POST":
		if request.form['secret_key']:
			if request.form['secret_key'] == session['skey']:
				### check if email is registered with us
				t = Teacher.query.filter_by(email=request.form['email']).first()
				if t != None:
					### generate a code and email it to the user
					### store email in session
					session['email_for_password_reset'] = request.form['email']
					return render_template("template_resetpassword_step2.html", email=request.form['email'], secret_key=session['skey'])
				else:
					flash("The email you entered does not appear to belong to an Round Table Forum account.")
					return redirect(url_for("route_passwordreset_step1"))

	return redirect(url_for("route_passwordreset_step1"))

@app.route("/passwordreset/step3/", methods=['GET', 'POST'])
def route_passwordreset_step3():

	if request.method == "POST":
		if request.form['secret_key']:
			if request.form['code']:
				if request.form['secret_key'] == session['skey']:
					#if request.form['code'] == session['code']:
					if request.form["code"] == "123":
						return render_template("template_resetpassword_step3.html", secret_key=session['skey'], code='123')

	return redirect(url_for("route_passwordreset_step1"))

@app.route("/passwordreset/process/", methods=['POST'])
def route_password_reset_process():

	if request.form['secret_key']:
		if request.form['code']:
			if request.form['secret_key'] == session['skey']:
				#if request.form['code'] == session['code']:
				if request.form["code"] == "123":
					if request.form["password1"] == request.form["password2"]:
						t = Teacher.query.filter_by(email=session['email_for_password_reset']).first()
						t.phash = bcrypt.generate_password_hash(request.form['password1'], 14)
						db.session.commit()

						return redirect(url_for("route_login"))

					else:
						flash("The confirm password line did not match the first password line.")
						return render_template("template_resetpassword_step3.html", secret_key=session['skey'], code='123')

	flash("There was a problem changing your password.")
	return redirect(url_for("route_passwordreset_step3"))


@app.route("/signup/", methods=['GET', 'POST'])
def route_register():
	if request.method == "POST":
		### validate forms
		if not request.form['schoolname']:
			flash("Please enter the name of your school.")
			return render_template("template_registration.html")

		if not request.form['country']:
			flash("Please enter the country your school is based in.")
			return render_template("template_registration.html")

		if not request.form['firstname']:
			flash("Please enter your firstname.")
			return render_template("template_registration.html")

		if not request.form['lastname']:
			flash("Please enter your lastname.")
			return render_template("template_registration.html")

		if not request.form['secretquestion']:
			flash("Please enter a secret question.")
			return render_template("template_registration.html")

		if not request.form['secretanswer']:
			flash("Please enter a answer to your secret question.")
			return render_template("template_registration.html")

		if not request.form['email']:
			flash("Please enter your email address.")
			return render_template("template_registration.html")

		if not request.form['password']:
			flash("Please enter a password.")
			return render_template("template_registration.html")

		### setup db entries
		s = School(schoolname=request.form['schoolname'], 
					country=request.form['country'])
		db.session.add(s)
		t = Teacher(firstname=request.form['firstname'], 
					lastname=request.form['lastname'], 
					email=request.form['email'], 
					password=request.form['password'],
					school=s,
					secretquestion=request.form['secretquestion'],
					secretanswer=request.form['secretanswer'], 
					isAdmin=True)
		db.session.add(t)

		### try to commit changes to the db
		try:
			db.session.commit()
		except exc.SQLAlchemyError, e:
			db.session.delete(s)
			db.session.delete(t)
			flash("I'm sorry, the email address you entered is already registered. Details: " + str(e))
			return render_template("template_registration.html")

		### try to create grades for the school
		createGrades(s)

		### log user in and redirect to homepage
		user = Teacher.query.filter_by(email=t.email).first()
		session['user'] = user
		session['school'] = School.query.filter_by(id=s.id).first()
		return redirect(url_for('route_home'))

	return render_template("template_registration.html")

@app.route("/invite/<email>/", methods=['GET', 'POST'])
@methodTimer
def route_invited_signup(email):
	#### check if valid email
	t = Teacher.query.filter_by(email=email).first()

	if not t:
		abort(404)

	if not t.onetimekey:
		abort(404)

	if not request.args.get("key"):
		abort(404)

	if request.args.get("key") != t.onetimekey:
		abort(401)


	#### add verification of invite ####

	if request.method == "POST":
		if not request.form['firstname']:
			flash("Please enter your firstname.")
			return render_template("template_registration.html")
		if not request.form['lastname']:
			flash("Please enter your lastname.")
			return render_template("template_registration.html")
		if not request.form['secretquestion']:
			flash("Please enter a secret question.")
			return render_template("template_registration.html")
		if not request.form['secretanswer']:
			flash("Please enter a answer to your secret question.")
			return render_template("template_registration.html")
		if not request.form['password']:
			flash("Please enter a password.")
			return render_template("template_registration.html")

		s = School.query.filter_by(id=t.school_id).first()

		t.firstname = request.form["firstname"]
		t.lastname = request.form["lastname"]
		t.password = bcrypt.generate_password_hash(request.form['password'], 14)
		t.isAdmin = False
		t.secretquestion = request.form["secretquestion"]
		t.secretanswer = request.form["secretanswer"]

		### try to commit changes to the db
		try:
			db.session.commit()
		except exc.SQLAlchemyError, e:
			flash("I'm sorry, the email address you entered is already registered. Details: " + str(e))
			return render_template("template_registration.html")

		### log user in and redirect to homepage
		user = Teacher.query.filter_by(email=t.email).first()
		session['user'] = user
		session['school'] = School.query.filter_by(id=s.id).first()
		return redirect(url_for('route_home'))


	return render_template("template_invited_user_registration.html", emailaddress=email)


@app.route("/home/")
@methodTimer
@requireLogin
def route_home():
	unviewed = UnviewedComment.query.filter_by(teacher_id=session['user'].id).order_by(UnviewedComment.id.desc())
	grades = Grade.query.filter_by(school_id=session['user'].school_id).all()

	### only show grades that the user has students they are allowed to view in
	shown_grades = []
	for grade in grades:
		show_grade = False

		students = grade.students.all()
		teacher = session['user']
		db.session.add(teacher)
		tokens = teacher.tokens.all()

		allowed_ids = []
		for t in tokens:
			allowed_ids.append(t.student_id)

		for student in students:
			if student.id in allowed_ids:
				show_grade = True
				break

		if show_grade == True:
			shown_grades.append(grade)

	return render_template("template_home.html", grades=shown_grades, unviewed=unviewed)


@app.route("/home/<grade>/")
@methodTimer
@requireLogin
def route_home_grade(grade):
	g = Grade.query.filter_by(name=grade, school_id=session['user'].school_id).first()
	students = Student.query.filter_by(grade=g).all()

	### only show students teacher has permission to view
	teacher = session['user']
	db.session.add(teacher)
	tokens = teacher.tokens.all()

	list_of_allowed_student_ids = []
	for token in tokens:
		list_of_allowed_student_ids.append(token.student_id)

	allowed_students = []
	for student in students:
		if student.id in list_of_allowed_student_ids:
			allowed_students.append(student)

	### sort here to ensure something doesn't get misordered by for loops
	return render_template("template_home_grade.html", grade=g, students=sorted(allowed_students, key=lambda student:student.lastname))

@app.route("/home/<grade>/<student_id>/", methods=['GET'])
@methodTimer
@requireLogin
@requirePermission
def route_home_grade_student(grade, student_id):
	s = Student.query.filter_by(id=student_id).first()
	g = Grade.query.filter_by(name=grade)
	posts = Post.query.filter_by(student_id=student_id).order_by(Post.id.desc())

	return render_template("template_home_grade_student.html", student=s, grade=g, posts=posts)

@app.route("/home/<grade>/<student_id>/<post_id>/", methods=['GET', 'POST'])
@methodTimer
@requireLogin
@requirePermission
def route_home_grade_student_post(grade, student_id, post_id):
	s = Student.query.filter_by(id=student_id).first()
	g = Grade.query.filter_by(name=grade).first()
	p = Post.query.filter_by(id=post_id).first()
	comments = Comment.query.filter_by(post_id=post_id).all()
	
	if request.method == "POST":

		if not request.form['comment']:
			flash("The comment you attempted to enter was blank.")
			return render_template("template_home_grade_student_post.html", post=p, comments=comments)

		c = Comment(content=request.form['comment'], teacher=session['user'], post=p)
		db.session.add( c )

		try:
			db.session.commit()
		except exc.SQLAlchemyError, e:
			flash("There was an error adding your comment: " + str(e))
			return render_template("template_home_grade_student_post.html", post=p, comments=comments)

	## requery comments to pick up the newly posted one (if there is one)
	## not sure this step is necessary
	comments = Comment.query.filter_by(post_id=post_id).all()

	### remove all relevant comments from the unviewed comments table
	for comment in comments:
		uvc = UnviewedComment.query.filter_by(comment=comment).first()
		if uvc:
			  db.session.delete(uvc)
	db.session.commit()

	return render_template("template_home_grade_student_post.html", post=p, comments=comments)

@app.route("/home/<grade>/<student_id>/<post_id>/<comment_id>/edit", methods=['GET', 'POST'])
@methodTimer
@requireLogin
def route_home_grade_student_post_comment_edit(grade, student_id, post_id, comment_id):
	s = Student.query.filter_by(id=student_id).first()
	g = Grade.query.filter_by(name=grade).first()
	p = Post.query.filter_by(id=post_id).first()
	c = Comment.query.filter_by(id=comment_id).first()

	if request.method == "POST":
		if not request.form['comment']:
			flash("The comment you entered was blank.")
			return render_template("template_home_grade_student_post_comment.html", comment=c)

		c.content = request.form['comment']

		try:
			db.session.commit()
		except exc.SQLAlchemyError, e:
			flash("There was an error editing your comment: " + str(e))
			return render_template("template_home_grade_student_post_comment.html", comment=c)

		return redirect(url_for("route_home_grade_student_post", grade=grade, student_id=student_id, post_id=post_id))

	return render_template("template_home_grade_student_post_comment.html", comment=c, student=s, post=p)



@app.route("/home/<grade>/<student_id>/compose/", methods=['GET', 'POST'])
@methodTimer
@requireLogin
@requirePermission
def route_home_grade_student_compose(grade, student_id):
	s = Student.query.filter_by(id=student_id).first()
	g = Grade.query.filter_by(name=grade)

	if request.method == "POST":
		if not request.form['title']:
			flash("Please include a title for your new post.")
			return render_template("template_home_grade_student_compose.html", student=s)
		if not request.form['body']:
			flash("Please include something in the body of your new post.")
			return render_template("template_home_grade_student_compose.html", student=s)

		p = Post(title=request.form['title'], teacher=session['user'], student=s)
		db.session.add( p )

		c = Comment(content=request.form['body'], teacher=session['user'], post=p)
		db.session.add( c )

		try:
			db.session.commit()
		except exc.SQLAlchemyError, e:
			flash("There was an error creating your post: " + str(e))
			return render_template("template_home_grade_student_compose.html", student=s)


		return redirect(url_for('route_home_grade_student', grade=grade, student_id=student_id))

	return render_template("template_home_grade_student_compose.html", student=s)

@app.route("/home/admin/")
@methodTimer
@requireLogin
@requireAdmin
def route_home_admin():
	return render_template("template_admin.html")

@app.route("/home/admin/teachers/", methods=["GET", "POST"])
@methodTimer
@requireLogin
@requireAdmin
def route_home_admin_teachers():

	teachers = Teacher.query.filter_by(school_id=session['user'].school_id)

	if request.method == "POST":
		if request.form["teachers"]:
			emails = request.form['teachers'].split(",")
			for email in emails:
				### check if email already exists in db
				check = Teacher.query.filter_by(email=email).first()
				if check:
					flash("That email has already been used.")
					return render_template("template_admin_teachers.html",teachers=teachers)

				### generate onetime unique key
				base = "abcdefghijklmnopqrstuvwxyz123456789.!@#$%^"
				salt = ''.join(random.sample(base, len(base)))
				key = hashlib.sha256(salt).hexdigest()

				school = School.query.filter_by(id=session['user'].school_id).first()
				t = Teacher(email=email, school=school, password="123", key=key)
				db.session.add(t)
				try:
					db.session.commit()
				except exc.SQLAlchemyError, e:
					flash("There was an error creating a teacher " + str(e))
					return render_template("template_admin_teachers.html", teachers=teachers)

				### after adding the initial teacher object to db
				### send email invite with unique key
				### a partial teacher object is added so that permissions can be assigned
				### without waiting for the teacher to accept the invite
				subjectline = "You have been invited to join Round Table Forums by " + session['user'].firstname + " " + session['user'].lastname + "."

				msg = Message(subjectline,
                  sender="invite@roundtableforums.net",
                  recipients=[email])
				msg.body = """
					Go to the following address to create your account:
					http://roundtableforums.net/invite/%s/?key=%s
				""" % (t.email, t.onetimekey)

				mail.send(msg)

	teachers = Teacher.query.filter_by(school_id=session['user'].school_id)
	return render_template("template_admin_teachers.html", teachers=teachers)

@app.route("/home/admin/teachers/delete/", methods=['POST'])
@methodTimer
@requireLogin
@requireAdmin
def route_home_admin_teachers_delete():
	### check teacher exists
	t = Teacher.query.filter_by(id=request.form['teacher_id'])
	if not t:
		abort(404)

	db.session.delete(t)
	db.session.commit()

	flash("%s has been deleted." % t.email )
	return redirect(url_for("route_home_admin_teachers"))

@app.route("/home/admin/teachers/resend/", methods=['POST'])
@methodTimer
@requireLogin
@requireAdmin
def route_home_admin_teachers_resend():
	t = Teacher.query.filter_by(id=request.form['teacher_id']).first()

	subjectline = "You have been invited to join Round Table Forums by " + session['user'].firstname + " " + session['user'].lastname + "."

	msg = Message(subjectline,
      sender="invite@roundtableforums.net",
      recipients=[t.email])
	msg.body = """
		Go to the following address to create your account:
		https://roundtableforums.net/invite/%s/?key=%s
	""" % (t.email, t.onetimekey)

	mail.send(msg)

	flash("An invite for %s has been sent. " % t.email )
	return redirect(url_for("route_home_admin_teachers"))

@app.route("/home/admin/teachers/<teacher_id>/", methods=['POST', 'GET'])
@methodTimer
@requireLogin
@requireAdmin
def route_home_admin_teachers_teacher(teacher_id):
	teacher = Teacher.query.filter_by(id=teacher_id, school_id=session['user'].school_id).first()
	if not teacher:
		abort(404)
	grades = Grade.query.filter_by(school_id=session['user'].school_id).all()

	if request.method == "POST":
		print str(request.form)
		### clear out users previous permissions
		pts = teacher.tokens.all()
		for p in pts:
			db.session.delete(p)
		db.session.commit()

		### iterate through form
		for entry in request.form:
			splitted = entry.split("-")
			if splitted[0] == "student":
				studentid = splitted[1]
				student = Student.query.filter_by(id=studentid).first()
				token = PermissionToken(student=student, teacher=teacher)
				db.session.add(token)
				db.session.commit()

			if splitted[0] == "allowall":
				### find all students in grade, create token for each one
				gradeid = splitted[1]
				students = Student.query.filter_by(grade_id=gradeid).all()
				for student in students:
					token = PermissionToken(student=student, teacher=teacher)
					db.session.add(token)
				db.session.commit()

		pts = teacher.tokens.all()



	### setup list of allowed/not allowed
	class Permission(object):
		def __init__(self, student):
			self.student=student
			### determine if allowed or denied
			token = PermissionToken.query.filter_by(student=student, teacher_id=teacher_id).first()
			print str(token)
			if token != None:
				self.allowed = True
			else:
				self.allowed = False

	class GradeBag(object):
		def __init__(self, grade, permissions):
			self.grade = grade
			self.permissions = permissions


	gradelist = []
	for grade in grades:
		gb = GradeBag(grade, [])
		students = grade.students.order_by(Student.lastname)
		for student in students:
			gb.permissions.append( Permission( student ) )
		gradelist.append(gb)

	return render_template("template_admin_teachers_teacher.html", teacher=teacher, grades=gradelist)

@app.route("/home/admin/students/", methods=['GET', 'POST'])
@methodTimer
@requireLogin
@requireAdmin
def route_home_admin_students():
	if request.method == "POST":
		### parse input to create new students
		students = request.form['students'].split(",")
		for student in students:
			bits = student.split()
			grade = Grade.query.filter_by(school_id=session['user'].school_id, numeric_repr=bits[2]).first()
			db.session.add(Student(firstname=bits[1], lastname=bits[0], grade=grade))
			flash(bits[0] + ", " + bits[1] + " added to " + grade.name + ".")
		try:
			db.session.commit()
		except exc.SQLAlchemyError, e:
			print str(e)

	### create an array of students by grade
	class GradeBag(object):
		def __init__(self, grade):
			self.grade = grade
			self.numeric_repr = grade.numeric_repr
			self.students = grade.students.order_by(Student.lastname)

		def __repr__(self):
			return "<gradebag " + str(self.grade) + " : " + str(self.students) +">"

	s_by_g = []
	grades = Grade.query.filter_by(school_id=session['user'].school_id).order_by(Grade.numeric_repr)
	for grade in grades:
		s_by_g.append(GradeBag(grade=grade))
	
	return render_template("template_admin_students.html", students_by_grade=s_by_g)

@app.route("/home/admin/students/graduate/", methods=['POST'])
@methodTimer
@requireLogin
@requireAdmin
def route_home_admin_students_graduate():
	grades = Grade.query.filter_by(school_id=session['user'].school_id).all()
	for grade in grades:
		if grade.numeric_repr < 13:
			new_grade_repr = grade.numeric_repr + 1
		else:
			new_grade_repr = grade.numeric_repr

		students = grade.students.all()
		for student in students:
			db.session.add(student)
			student.grade = Grade.query.filter_by(numeric_repr=new_grade_repr).first()
			student.grade_id = student.grade.id

	db.session.commit()

	flash("All students have been graduated to the next grade level.")
	return redirect(url_for("route_home_admin_students"))

@app.route("/mailtest")
@methodTimer
def route_mailtest():
	msg = Message("Hello charles",
                  sender="invite@roundtableforums.net",
                  recipients=["charles4@email.arizona.edu"])
	mail.send(msg)

	return str(msg)


def presets():
	db.drop_all()
	db.create_all()



if __name__ == "__main__":
	presets()

	app.debug = True
	app.run()


