from flask import Flask, render_template, session, redirect, url_for, abort, request, flash, send_from_directory
from flask.ext.sqlalchemy import SQLAlchemy
from flaskext.bcrypt import Bcrypt 

from sqlalchemy import exc

from functools import wraps
import time
import calendar
from datetime import datetime

import hashlib
import random

#### import custom modules
from dbModule import *
from securityModule import *
from wrapperModule import Wrappers
from helperModule import General

#### session management stuff
import redis
from simplekv.memory.redisstore import RedisStore
from flaskext.kvsession import KVSessionExtension

store = RedisStore(redis.StrictRedis(host='roundtableforums.net', port=7555, db=0))

### email
from flask_mail import Mail
from flask_mail import Message

### regex
import re

#for file uploads
from werkzeug import secure_filename
import os
from PIL import Image
UPLOAD_FOLDER = '/var/forum/uploads'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://charles:AnneHathaway123@roundtableforums.net/roundtableforums_db'
app.secret_key = 'W\xa8\x01\x83c\t\x06\x07p\x9c\xed\x13 \x98\x17\x0f\xf9\xbe\x18\x8a|I\xf4U'


bcrypt = Bcrypt(app)
### db.init is called because we have defined the models in the module dbModule
db.init_app(app)
mail = Mail(app)

# this will replace the app's session handling
KVSessionExtension(store, app)

# instantiate custom wrappers
wrappers = Wrappers(session, db)

# instantiate help methods
gen = General(session, db, app)


### none database classes

class Result(object):
	def __init__(self, score, representation, address, mytype, date=None):
		self.score = score
		self.repr = representation
		self.address = address
		self.date = date
		self.type = mytype




### routes ###

@app.route('/avatars/<filename>')
@wrappers.requireLogin
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route("/", methods=['GET', 'POST'])
def route_login():
	if request.method == "POST":
		### first check canary
		if not checkCanary(session=session, request=request):
			abort(401)
		### fetch user info
		user = Teacher.query.filter_by(email=request.form['email']).first()
		if user != None:
			if bcrypt.check_password_hash(user.phash, request.form['password']):
				session['user'] = user
				session['grades'] = Grade.query.filter_by(school_id=session['user'].school_id).all()
				session['school'] = School.query.filter_by(id=session['user'].school_id).first()
				return redirect(url_for('route_home'))

			else:
				flash('You entered an incorrect password.')
				return render_template("template_login.html")
		else:
			flash("The email address you entered was not found.")
			return render_template("template_login.html")
	else:
		### if not post then GET
		### create canary
		canary = createCanary(session=session)
		return render_template("template_login.html", canary=canary)

@app.route("/login/")
def route_login_redirect():
	return redirect(url_for("route_login"))

@app.route("/logout/")
def route_logout():
	gen.logout()
	return redirect(url_for('route_login'))

@app.route("/passwordreset/", methods=['GET'])
def route_passwordreset_step1():
	### generate unique key
	session['skey'] = generateKey()

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
					subjectline = "Password reset code."
					address = request.form['email']
					code = generateKey()[:5]

					msg = Message(subjectline,
				      sender="password@roundtableforums.net",
				      recipients=[address])
					msg.body = """Your code is: %s""" % code

					mail.send(msg)
					### store email in session
					session['email_for_password_reset'] = address
					session['password_reset_code'] = code

					return render_template("template_resetpassword_step2.html", email=request.form['email'], secret_key=session['skey'])
				else:
					flash("The email you entered does not appear to belong to an Round Table Forum account.")
					return redirect(url_for("route_passwordreset_step1"))

	return redirect(url_for("route_passwordreset_step1"))

@app.route("/passwordreset/step3/", methods=['GET', 'POST'])
def route_passwordreset_step3():

	if request.method == "POST":
		if 'secret_key' in request.form:
			if 'code' in request.form:
				if request.form['secret_key'] == session['skey']:
					if request.form["code"] == session['password_reset_code']:
						return render_template("template_resetpassword_step3.html", secret_key=session['skey'], code=session['password_reset_code'])

	return redirect(url_for("route_passwordreset_step1"))

@app.route("/passwordreset/process/", methods=['POST'])
def route_password_reset_process():

	if request.form['secret_key']:
		if request.form['code']:
			if request.form['secret_key'] == session['skey']:
				#if request.form['code'] == session['code']:
				if request.form["code"] == session['password_reset_code']:
					if request.form["password1"] == request.form["password2"]:
						t = Teacher.query.filter_by(email=session['email_for_password_reset']).first()
						t.setpassword(request.form['password1'])
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
		# check canary
		if not checkCanary(session=session, request=request):
			abort(401)
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

		if not request.form['email']:
			flash("Please enter your email address.")
			return render_template("template_registration.html")

		if not request.form['password']:
			flash("Please enter a password.")
			return render_template("template_registration.html")

		if not request.form['password-confirm']:
			flash("Please confirm your password.")
			return render_template("template_registration.html")

		if request.form['password'] != request.form['password-confirm']:
			flash("Your confirm password line does not match your password line.")
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
		gen.createGrades(s)

		### create general discussion section for the school
		gen.createGeneralDiscussion(s)


		### log user in and redirect to homepage
		user = Teacher.query.filter_by(email=t.email).first()
		session['user'] = user
		session['school'] = School.query.filter_by(id=s.id).first()
		return redirect(url_for('route_home'))

	## if not POST then GET
	# create canary
	canary = createCanary(session=session)

	return render_template("template_registration.html", canary=canary)

@app.route("/invite/<email>/", methods=['GET', 'POST'])
@wrappers.methodTimer
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

	if request.method == "POST":
		#check canary
		if not checkCanary(session=session, request=request):
			abort(401)

		#validate forms
		if not request.form['firstname']:
			flash("Please enter your firstname.")
			return render_template("template_registration.html")
		if not request.form['lastname']:
			flash("Please enter your lastname.")
			return render_template("template_registration.html")
		if not request.form['password']:
			flash("Please enter a password.")
			return render_template("template_registration.html")
		if not request.form['password-confirm']:
			flash("Please confirm your password.")
			return render_template("template_registration.html")

		if request.form['password'] != request.form['password-confirm']:
			flash("Your confirm password line does not match your password line.")
			return render_template("template_registration.html")

		s = School.query.filter_by(id=t.school_id).first()

		t.firstname = request.form["firstname"]
		t.lastname = request.form["lastname"]
		t.setpassword(request.form['password'])

		### try to commit changes to the db
		try:
			db.session.commit()
		except exc.SQLAlchemyError, e:
			flash("I'm sorry, there was an error creating your account. Details: " + str(e))
			return render_template("template_invited_user_registration.html")

		### log user in and redirect to homepage
		user = Teacher.query.filter_by(email=t.email).first()
		session['user'] = user
		session['school'] = School.query.filter_by(id=s.id).first()
		return redirect(url_for('route_home'))

	# create canary
	canary = createCanary(session)

	return render_template("template_invited_user_registration.html", emailaddress=email, canary=canary)


@app.route("/home/")
@wrappers.methodTimer
@wrappers.requireLogin
def route_home():
	unviewed = UnviewedComment.query.filter_by(teacher_id=session['user'].id).order_by(UnviewedComment.id.desc())
	## fetch all students teacher has access to
	tokens = PermissionToken.query.filter_by(teacher_id=session['user'].id).all()
	gradetokens = GradePermissionToken.query.filter_by(teacher_id=session['user'].id).all()

	teacher = session['user']
	db.session.add(teacher)
	print str(teacher.unviewed.all())

	ids = []
	for t in tokens:
		ids.append(t.student_id)

	gids = []
	for g in gradetokens:
		gids.append(g.grade_id)

	shown_unviewed = []
	### only show unviewed comments on students teacher has access too
	for uvcomment in unviewed:
		print "uvcomments:" + str(uvcomment)
		if uvcomment.comment.post.student_id in ids or uvcomment.comment.post.student.grade_id in gids:
			shown_unviewed.append(uvcomment)

	### only show grades that the user has students they are allowed to view in
	shown_grades = []
	for token in tokens:
		if token.student.grade not in shown_grades:
			shown_grades.append(token.student.grade)

	for gradetoken in gradetokens:
		if gradetoken.grade not in shown_grades:
			shown_grades.append(gradetoken.grade)

	shown_grades = sorted(shown_grades, key=lambda grade:grade.id)
	return render_template("template_home.html", grades=shown_grades, unviewed=shown_unviewed)

@app.route("/home/settings/", methods=['GET', 'POST'])
@wrappers.methodTimer
@wrappers.requireLogin
def route_home_settings():

	if request.method == "POST":
		# check canary
		if not checkCanary(session=session, request=request):
			abort(401)
		# pull teacher and set and save avatar
		teacher = Teacher.query.filter_by(id=session['user'].id).first()
		if 'avatar' in request.files:
			gen.saveAvatar(teacher=teacher, request=request)
			flash("Successfully saved avatar.")

	#create canary
	canary = createCanary(session)
	return render_template("template_home_settings.html", canary=canary)

@app.route("/home/<grade>/")
@wrappers.methodTimer
@wrappers.requireLogin
def route_home_grade(grade):
	g = Grade.query.filter_by(name=grade, school_id=session['user'].school_id).first()
	students = Student.query.filter_by(grade=g).all()

	### only show students teacher has permission to view
	teacher = session['user']
	db.session.add(teacher)
	tokens = teacher.tokens.all()
	gradetokens = teacher.grade_tokens.all()
	allowed_grades = []
	for token in gradetokens:
		allowed_grades.append(token.grade)

	list_of_allowed_student_ids = []
	for token in tokens:
		list_of_allowed_student_ids.append(token.student_id)

	allowed_students = []
	for student in students:
		if student.id in list_of_allowed_student_ids or student.grade in allowed_grades:
			allowed_students.append(student)

	### sort here to ensure something doesn't get misordered by for loops
	return render_template("template_home_grade.html", grade=g, students=sorted(allowed_students, key=lambda student:student.lastname))

@app.route("/home/general-discussion/")
@wrappers.methodTimer
@wrappers.requireLogin
def route_home_general():
	db.session.add(session['user'])
	s = Student.query.filter_by(firstname=str(session['user'].school_id)).first()
	posts = Post.query.filter_by(student=s).order_by(Post.id.desc())

	return render_template("template_home_general_discussion.html", posts=posts)

@app.route("/home/general-discussion/compose/", methods=['GET', 'POST'])
@wrappers.methodTimer
@wrappers.requireLogin
def route_home_general_compose():
	db.session.add(session['user'])
	s = Student.query.filter_by(firstname=str(session['user'].school_id)).first()

	if request.method == "POST":
		#check canary
		if not checkCanary(session, request):
			abort(401)
		#validate forms
		if not request.form['title']:
			flash("Please include a title for your new post.")
			return render_template("template_home_general_discussion_compose.html", student=s)
		if not request.form['body']:
			flash("Please include something in the body of your new post.")
			return render_template("template_home_general_discussion_compose.html", student=s)

		p = Post(title=request.form['title'], teacher=session['user'], student=s)
		db.session.add( p )

		c = Comment(content=request.form['body'], teacher=session['user'], teachers=Teacher.query.filter_by(school_id=session['user'].school_id).all(), post=p)
		db.session.add( c )

		try:
			db.session.commit()
		except exc.SQLAlchemyError, e:
			flash("There was an error creating your post: " + str(e))
			return render_template("template_home_general_discussion_compose.html", student=s)


		return redirect(url_for('route_home_general'))

	#create canary
	canary = createCanary(session)
	return render_template("template_home_general_discussion_compose.html", canary=canary)

@app.route("/home/general-discussion/<post_id>/", methods=['GET', 'POST'])
@wrappers.methodTimer
@wrappers.requireLogin
def route_home_general_post(post_id):
	db.session.add(session['user'])
	s = Student.query.filter_by(firstname=str(session['user'].school_id)).first()
	p = Post.query.filter_by(id=post_id).first()
	comments = Comment.query.filter_by(post_id=post_id).all()
	
	if request.method == "POST":
		# check canary
		if not checkCanary(session, request):
			abort(401)

		if not request.form['comment']:
			flash("The comment you attempted to enter was blank.")
			return render_template("template_home_general_discussion_post.html", post=p, comments=comments)

		c = Comment(content=request.form['comment'], teacher=session['user'], teachers=Teacher.query.filter_by(school_id=session['user'].school_id).all(), post=p)
		db.session.add( c )

		try:
			db.session.commit()
		except exc.SQLAlchemyError, e:
			flash("There was an error adding your comment: " + str(e))
			return render_template("template_home_general_discussion_post.html", post=p, comments=comments)

	## requery comments to pick up the newly posted one (if there is one)
	## not sure this step is necessary
	comments = Comment.query.filter_by(post_id=post_id).all()

	### remove all relevant comments from the unviewed comments table
	for comment in comments:
		uvc = UnviewedComment.query.filter_by(comment=comment, teacher_id=session['user'].id).first()
		if uvc:
			  db.session.delete(uvc)
	db.session.commit()

	# create canary
	canary = createCanary(session)

	return render_template("template_home_general_discussion_post.html", comments=comments, post=p, canary=canary)

@app.route("/home/general-discussion/<post_id>/<comment_id>/edit/", methods=['GET', 'POST'])
@wrappers.methodTimer
@wrappers.requireLogin
def route_home_general_post_comment_edit(post_id, comment_id):
	p = Post.query.filter_by(id=post_id).first()
	c = Comment.query.filter_by(id=comment_id).first()

	### check if user is owner of the comment
	if c.author.id != session['user'].id:
		abort(401)

	if request.method == "POST":
		#check canary
		if not checkCanary(session, request):
			abort(401)
		#validate form
		if not request.form['comment']:
			flash("The comment you entered was blank.")
			return render_template("template_home_general_discussion_post_comment.html", comment=c)

		c.content = request.form['comment']

		try:
			db.session.commit()
		except exc.SQLAlchemyError, e:
			flash("There was an error editing your comment: " + str(e))
			return render_template("template_home_general_discussion_post_comment.html", comment=c)

		return redirect(url_for("route_home_general_post", post_id=post_id))
	#create canary
	canary = createCanary(session)
	return render_template("template_home_general_discussion_post_comment.html", comment=c, post=p, canary=canary)

@app.route("/home/<grade>/<student_id>/", methods=['GET'])
@wrappers.methodTimer
@wrappers.requireLogin
@wrappers.requirePermission
def route_home_grade_student(grade, student_id):
	s = Student.query.filter_by(id=student_id).first()
	g = Grade.query.filter_by(name=grade)
	posts = Post.query.filter_by(student_id=student_id).order_by(Post.id.desc())

	return render_template("template_home_grade_student.html", student=s, grade=g, posts=posts)

@app.route("/home/<grade>/<student_id>/<post_id>/", methods=['GET', 'POST'])
@wrappers.methodTimer
@wrappers.requireLogin
@wrappers.requirePermission
def route_home_grade_student_post(grade, student_id, post_id):
	s = Student.query.filter_by(id=student_id).first()
	g = Grade.query.filter_by(name=grade).first()
	p = Post.query.filter_by(id=post_id).first()
	comments = Comment.query.filter_by(post_id=post_id).all()
	
	if request.method == "POST":

		if not request.form['comment']:
			flash("The comment you attempted to enter was blank.")
			return render_template("template_home_grade_student_post.html", post=p, comments=comments)

		c = Comment(content=request.form['comment'], teacher=session['user'], teachers=Teacher.query.filter_by(school_id=session['user'].school_id).all(), post=p)
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
		uvc = UnviewedComment.query.filter_by(comment=comment, teacher_id=session['user'].id).first()
		if uvc:
			  db.session.delete(uvc)
	db.session.commit()

	return render_template("template_home_grade_student_post.html", post=p, comments=comments)

@app.route("/home/<grade>/<student_id>/<post_id>/<comment_id>/edit", methods=['GET', 'POST'])
@wrappers.methodTimer
@wrappers.requireLogin
def route_home_grade_student_post_comment_edit(grade, student_id, post_id, comment_id):
	s = Student.query.filter_by(id=student_id).first()
	g = Grade.query.filter_by(name=grade).first()
	p = Post.query.filter_by(id=post_id).first()
	c = Comment.query.filter_by(id=comment_id).first()

	### check if user is owner of the comment
	if c.author.id != session['user'].id:
		abort(401)

	if request.method == "POST":
		# check canary
		if not checkCanary(session, request):
			abort(401)
		# validate form
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

	canary = createCanary(session)
	return render_template("template_home_grade_student_post_comment.html", comment=c, student=s, post=p, canary=canary)



@app.route("/home/<grade>/<student_id>/compose/", methods=['GET', 'POST'])
@wrappers.methodTimer
@wrappers.requireLogin
@wrappers.requirePermission
def route_home_grade_student_compose(grade, student_id):
	s = Student.query.filter_by(id=student_id).first()
	g = Grade.query.filter_by(name=grade)

	if request.method == "POST":
		# check canary
		if not checkCanary(session, request):
			abort(401)
		# validate form
		if not request.form['title']:
			flash("Please include a title for your new post.")
			return render_template("template_home_grade_student_compose.html", student=s)
		if not request.form['body']:
			flash("Please include something in the body of your new post.")
			return render_template("template_home_grade_student_compose.html", student=s)

		p = Post(title=request.form['title'], teacher=session['user'], student=s)
		db.session.add( p )

		c = Comment(content=request.form['body'], teacher=session['user'], teachers=Teacher.query.filter_by(school_id=session['user'].school_id).all(), post=p)
		db.session.add( c )

		try:
			db.session.commit()
		except exc.SQLAlchemyError, e:
			flash("There was an error creating your post: " + str(e))
			return render_template("template_home_grade_student_compose.html", student=s)


		return redirect(url_for('route_home_grade_student', grade=grade, student_id=student_id))

	canary = createCanary(session)
	return render_template("template_home_grade_student_compose.html", student=s, canary=canary)

@app.route("/home/admin/")
@wrappers.methodTimer
@wrappers.requireLogin
@wrappers.requireAdmin
def route_home_admin():
	return render_template("template_admin.html")

@app.route("/home/admin/teachers/", methods=["GET", "POST"])
@wrappers.methodTimer
@wrappers.requireLogin
@wrappers.requireAdmin
def route_home_admin_teachers():

	teachers = Teacher.query.filter_by(school_id=session['user'].school_id)

	if request.method == "POST":
		# check canary
		if not checkCanary(session, request):
			abort(401)

		if "teachers" in request.form:
			emails = request.form['teachers'].split(",")
			for email in emails:
				## strip whitespace
				email = email.strip()
				### validate email

				### check if email already exists in db
				check = Teacher.query.filter_by(email=email).first()
				if check:
					flash("That email has already been used.")
					return render_template("template_admin_teachers.html",teachers=teachers)

				### generate onetime unique key
				base = "abcdefghijklmnopqrstuvwxyz123456789.!@#$%^"
				salt = ''.join(random.sample(base, len(base)))
				key = hashlib.sha256(salt).hexdigest()[:10]

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
				msg.body = """Go to the following address to create your account:
http://roundtableforums.net/invite/%s/?key=%s""" % (t.email, t.onetimekey)

				mail.send(msg)

	teachers = Teacher.query.filter_by(school_id=session['user'].school_id).order_by(Teacher.email)
	canary = createCanary(session)
	return render_template("template_admin_teachers.html", teachers=teachers, canary=canary)

@app.route("/home/admin/teachers/delete/", methods=['POST'])
@wrappers.methodTimer
@wrappers.requireLogin
@wrappers.requireAdmin
def route_home_admin_teachers_delete():
	# check canary
	if not checkCanary(session, request):
		abort(401)
	### check teacher exists
	t = Teacher.query.filter_by(id=request.form['teacher_id']).first()
	if not t:
		abort(404)

	db.session.delete(t)
	db.session.commit()

	flash("%s has been deleted." % t.email )
	return redirect(url_for("route_home_admin_teachers"))

@app.route("/home/admin/teachers/resend/", methods=['POST'])
@wrappers.methodTimer
@wrappers.requireLogin
@wrappers.requireAdmin
def route_home_admin_teachers_resend():
	# check canary
	if not checkCanary(session, request):
		abort(401)

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
@wrappers.methodTimer
@wrappers.requireLogin
@wrappers.requireAdmin
def route_home_admin_teachers_teacher(teacher_id):
	teacher = Teacher.query.filter_by(id=teacher_id, school_id=session['user'].school_id).first()
	if not teacher:
		abort(404)
	grades = Grade.query.filter_by(school_id=session['user'].school_id).all()

	if request.method == "POST":
		#check canary
		if not checkCanary(session, request):
			abort(401)
		### clear out users previous permissions
		pts = teacher.tokens.all()
		for p in pts:
			db.session.delete(p)
		gpts = teacher.grade_tokens.all()
		for g in gpts:
			db.session.delete(g)

		db.session.commit()

		### iterate through form
		for entry in request.form:
			splitted = entry.split("-")
			if splitted[0] == "grade":
				### find all students in grade, create token for each one
				gradeid = splitted[1]
				grade = Grade.query.filter_by(id=gradeid).first()
				token = GradePermissionToken(grade=grade, teacher=teacher)
				db.session.add(token)

			if splitted[0] == "student":
				studentid = splitted[1]
				student = Student.query.filter_by(id=studentid).first()				
				token = PermissionToken(student=student, teacher=teacher)
				db.session.add(token)
			
			db.session.commit()
				# else, if a gradetoken exists, a individual token doesn't need to be created


	### setup list of allowed/not allowed
	class Permission(object):
		def __init__(self, student):
			self.student=student
			### determine if allowed or denied
			token = PermissionToken.query.filter_by(student=student, teacher_id=teacher_id).first()

			if token != None:
				self.allowed = True
			else:
				self.allowed = False

	class GradeBag(object):
		def __init__(self, grade, permissions):
			self.grade = grade
			### determine if grade is allowed or not
			token = GradePermissionToken.query.filter_by(grade=grade, teacher_id=teacher_id).first()
			if token != None:
				self.allowed = True
			else:
				self.allowd = False

			self.permissions = permissions


	gradelist = []
	for grade in grades:
		gb = GradeBag(grade, [])
		students = grade.students.order_by(Student.lastname)
		for student in students:
			gb.permissions.append( Permission( student ) )
		gradelist.append(gb)

	canary = createCanary(session)
	return render_template("template_admin_teachers_teacher.html", teacher=teacher, grades=gradelist, canary=canary)

@app.route("/home/admin/teachers/<teacher_id>/makeadmin/", methods=['POST'])
@wrappers.methodTimer
@wrappers.requireLogin
@wrappers.requireAdmin
def route_home_admin_teachers_teacher_makeadmin(teacher_id):
	if not checkCanary(session, request):
		abort(401)
	teacher = Teacher.query.filter_by(id=teacher_id).first()
	teacher.isAdmin = True
	db.session.commit()

	return redirect(url_for("route_home_admin_teachers_teacher", teacher_id=teacher_id))

@app.route("/home/admin/teachers/<teacher_id>/removeadmin/", methods=['POST'])
@wrappers.methodTimer
@wrappers.requireLogin
@wrappers.requireAdmin
def route_home_admin_teachers_teacher_removeadmin(teacher_id):
	if not checkCanary(session, request):
		abort(401)
	teacher = Teacher.query.filter_by(id=teacher_id).first()
	teacher.isAdmin = False
	db.session.commit()

	return redirect(url_for("route_home_admin_teachers_teacher", teacher_id=teacher_id))

@app.route("/home/admin/students/", methods=['GET', 'POST'])
@wrappers.methodTimer
@wrappers.requireLogin
@wrappers.requireAdmin
def route_home_admin_students():
	if request.method == "POST":
		# check canary
		if not checkCanary(session, request):
			abort(401)
		### parse input to create new students
		students = request.form['students'].split(",")
		for student in students:
			bits = student.split()

			### check the validity of the formatting
			length = len(bits)
			if length != 3:
				flash("There seems to be invalid formatting around '%s'." % student)
				return redirect(url_for("route_home_admin_students"))
			if not re.match("^[0-9]?[0-9]$", bits[2]):
				flash("You didn't use a valid grade for entry '%s'." % student)
				return redirect(url_for("route_home_admin_students"))
			if int(bits[2]) > 12:
				flash("At the moment, you can only use grades 1-12 for entry '%s'." % student)
				return redirect(url_for("route_home_admin_students"))


			grade = Grade.query.filter_by(school_id=session['user'].school_id, numeric_repr=bits[2]).first()
			db.session.add(Student(firstname=bits[1], lastname=bits[0], grade=grade))
			try:
				db.session.commit()
			except exc.SQLAlchemyError, e:
				print str(e)
			flash(bits[0] + ", " + bits[1] + " added to " + grade.name + ".")


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
	
	# create canary
	canary = createCanary(session)
	return render_template("template_admin_students.html", students_by_grade=s_by_g, canary=canary)

@app.route("/home/admin/students/delete/<student_id>/<secret_key>", methods=['GET'])
@wrappers.methodTimer
@wrappers.requireLogin
@wrappers.requireAdmin
def route_home_admin_students_delete(student_id, secret_key):

	## custom canary for GET
	if secret_key != session['canary']:
		abort(401)

	student = Student.query.filter_by(id=student_id).first()
	db.session.delete(student)
	db.session.commit()

	flash("Student '" + student.lastname + ", " + student.firstname + "' has been deleted.")
	return redirect(url_for("route_home_admin_students"))

@app.route("/home/admin/students/graduate/", methods=['POST'])
@wrappers.methodTimer
@wrappers.requireLogin
@wrappers.requireAdmin
def route_home_admin_students_graduate():
	if not checkCanary(session, request):
		abort(401)

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

@app.route("/home/help/", methods=['POST', 'GET'])
@wrappers.methodTimer
@wrappers.requireLogin
def route_home_help():

	if request.method == "POST":
		if not checkCanary(session, request):
			abort(401)
		subjectline = "Roundtableforums Help Message"
		msg = Message(subjectline,
              sender=session['user'].email,
              recipients=["charles4@email.arizona.edu"])
		msg.body = request.form['question']
		mail.send(msg)
		flash("Your message was sent successfully.")
	canary = createCanary(session)
	return render_template("template_home_help.html", canary=canary)




@app.route("/home/search/", methods=['GET'])
@wrappers.methodTimer
@wrappers.requireLogin
def route_home_search():
	### for pagination check what page we're on, if none provided, pick 0
	if 'page' in request.args:
		PAGE = int(request.args['page'])
	else:
		PAGE = 0

	### take levenshtein of keyword string "stupid kids suck" and each post title, comment and student (name)
	### score results by levenshtein values

	keywords = request.args.get("keywords")
	teacher = Teacher.query.filter_by(id=session['user'].id).first()

	## if keywords == those store in session
	### then don't recalc search
	if 'search_query' in session and 'search_final_results' in session:
		if session['search_query'] != keywords:
			final_results = gen.search_helper(teacher=teacher, keywords=keywords)

			### store results and query in session
			session['search_final_results'] = final_results
			session['search_query'] = keywords

		#### else session['search_query'] IS equal to keywords
		else:
			final_results = session['search_final_results']
	### else 'search_query' and 'search_final_results' do not exist in the session
	else:
		final_results = gen.search_helper(teacher=teacher, keywords=keywords)

		### store results and query in session
		session['search_final_results'] = final_results
		session['search_query'] = keywords

	### paginate results
	class Page(object):
		def __init__(self, results, pagenumber, keywords):
			self.results = results
			self.pagenumber = pagenumber + 1
			self.url = url_for("route_home_search", keywords=keywords, page=pagenumber)
			self.active = False
		def __repr__(self):
			return "<page %r>" % self.pagenumber

	pages = []
	counter = 0
	pagenumber = 0
	for result in final_results:
		if counter == 0:
			pages.append(Page([], pagenumber, keywords))
			pages[pagenumber].results.append(result)
		else:
			pages[pagenumber].results.append(result)

		counter += 1

		if counter == 10:
			counter = 0
			pagenumber += 1

	### check if PAGE is out of range
	if PAGE >= len(pages):
		abort(404)

	if PAGE < 0:
		abort(404)

	if PAGE + 2 <= len(pages):
		next_page = pages[PAGE + 1]
	else:
		next_page = None

	if PAGE == 0:
		prev_page = None
	else:
		prev_page = pages[PAGE - 1]

	### set page active
	pages[PAGE].active = True

	return render_template("template_home_search.html", pages=pages,
														prev_page = prev_page,
														next_page = next_page,
														results=sorted(pages[PAGE].results, key=lambda result:result.score))


def presets():
	### this line is needed to make the drop_all and create_all statements work
	### when the db class definitions are in another module
	db.app = app

	db.drop_all()
	db.create_all()

	school = School("Demo Elementary School", "America")
	db.session.add(school)
	db.session.commit()

	createGrades(school)

	createGeneralDiscussion(school)

	teacher = Teacher(email="demo@demo.com", school=school, key=None, firstname="Gandalf", lastname="Gray", password="demo", secretquestion=None, secretanswer=None, isAdmin=True, create_date=None)
	db.session.add(teacher)
	db.session.commit()

	grade = Grade.query.filter_by(id=1).first()
	db.session.add(Student(firstname="George", lastname="Washington", grade=grade))
	db.session.add(Student(firstname="Abraham", lastname="Lincoln", grade=grade))
	db.session.add(Student(firstname="Franklyn", lastname="Rosevelt", grade=grade))
	db.session.add(Student(firstname="Richard", lastname="Nixon", grade=grade))
	db.session.add(Student(firstname="Bill", lastname="Clinton", grade=grade))
	db.session.commit()

	gradetoken = GradePermissionToken(grade=grade, teacher=teacher)
	db.session.add(gradetoken)
	db.session.commit()


if __name__ == "__main__":
	#presets()

	app.debug = True
	app.run()


