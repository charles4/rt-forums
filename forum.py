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

#### import database modeule
from dbModule import *

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




### none database classes

class Result(object):
	def __init__(self, score, representation, address, mytype, date=None):
		self.score = score
		self.repr = representation
		self.address = address
		self.date = date
		self.type = mytype


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
		teacher = session['user']
		db.session.add(teacher)

		allowed = teacher.tokens.all()
		for token in allowed:
			if str(token.student_id) == str(kwargs["student_id"]):
				return fn(*args, **kwargs)

		allowed = teacher.grade_tokens.all()
		for token in allowed:
			if str(token.grade.name) == str(kwargs["grade"]):
				return fn(*args, **kwargs)

		flash("You don't have permission to view the forum belonging to that student. Your school's admin can fix that.")
		return redirect(url_for("route_home_grade", grade=kwargs["grade"]))
	return decorated

### General Methods ###

def allowed_file(filename):
	return "." in filename and \
		filename.rsplit(".", 1)[1] in ALLOWED_EXTENSIONS

def saveAvatar(teacher, request):
	size = 64, 64
	### get file obj from request ###
	myfile = request.files['avatar']
	if myfile and allowed_file (myfile.filename):
		### setup filename and save to filesystem ####
		filename = str(session['user'].id) + "_" + secure_filename(myfile.filename)
		myfile.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

		### after saving re-open and create tiny version 
		image = Image.open(os.path.join(app.config['UPLOAD_FOLDER'], filename))
		image.thumbnail(size)
		filename = str(session['user'].id) + "_thumbnail_" + secure_filename(myfile.filename)
		image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
		### add filename to db
		teacher.avatar = filename
		db.session.commit()
		### refresh teacher obj in session
		session['user'] = teacher

		return True

	else:			
		return False

def logout():
	session.pop('user', None)

def createGeneralDiscussion(school):
	db.session.add(Student(firstname=str(school.id), lastname="General Discussion", grade=None))
	try:
		db.session.commit()
	except exc.SQLAlchemyError, e:
		print str(e)

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


def levenshtein(s1, s2):
	if len(s1) < len(s2):
		return levenshtein(s2, s1)

	# len(s1) >= len(s2)
	if len(s2) == 0:	
		return len(s1)

	previous_row = xrange(len(s2) + 1)
	for i, c1 in enumerate(s1):
		current_row = [i + 1]
		for j, c2 in enumerate(s2):
			insertions = previous_row[j + 1] + 1 # j+1 instead of j since previous_row and current_row are one character longer
			deletions = current_row[j] + 1       # than s2
			substitutions = previous_row[j] + (c1 != c2)
			current_row.append(min(insertions, deletions, substitutions))
		previous_row = current_row

	return previous_row[-1]


def search_helper(keywords, teacher):
## fetch all students teacher has access to
	tokens = teacher.tokens.all()
	gradetokens = teacher.grade_tokens.all()

	### an array of all student ids current user has access to
	ids = []
	for t in tokens:
		ids.append(t.student_id)

	for gradetoken in gradetokens:
		students = gradetoken.grade.students.all()
		for student in students:
			if student.id not in ids:
				ids.append(student.id)

	## an array of all students current user has access to
	students = Student.query.filter(Student.id.in_(ids)).all()

	## now fetch all posts about those students
	posts = Post.query.filter(Post.student_id.in_(ids)).all()

	### now fetch all comments from those posts
	comments = []
	for post in posts:
		coms = Comment.query.filter_by(post=post).all()
		for com in coms:
			comments.append(com)




	#### build array of result objects made of students, posts and comments
	results = []

	### set "impossibly" high min_score, so anything is lower than it. 
	### as far as levenshtein differences between individual words go this is impossibly high
	### since whats the longest word like 12 characters or something?
	### min_score is overall lowest score out of all results
	min_score = 100000

	### iterate through student objects
	for student in students:
		### local score for this student object
		### made by adding smallest levenshtein results together
		### lower scores are more relevent
		myscore = 0.0

		### iterate through keywords or search terms
		for keyword in keywords.split():
			### lowest levenshtein result of all keyword vs word in text comparisons
			lowest_lev_result = 10000

			### text to be compared to keywords
			text = student.firstname + " " + student.lastname

			### iterate through text to compare to keywords
			for word in text.split():

				### compare word to a keyword
				lev_result = levenshtein(keyword, word) + .1  ## to avoid results of zero

				### if the comparison produces a smaller result than current lowest result
				### set current lowest to new result
				if lev_result < lowest_lev_result:
					lowest_lev_result = lev_result
			
			#### add onto student objects current overall score
			myscore += lowest_lev_result

		### define textual representaion of the student object
		_repr = student.lastname + ", " + student.firstname	
		### define link address of student object
		address  = "/home/%s/%s/" % (student.grade.name, student.id)

		## adjust final score by date
		## closer current date is to objects creation date, the more relevent the object is
		## so it gets a lower score
		epoch_time = time.time()
		timestamp_ = calendar.timegm(student.created.timetuple())
		### ratio of current time (in seconds since epoch) vs objects timestamp
		ratio = (timestamp_ * 1.0) / (epoch_time * 1.0)
		### adjust obejcts final score by the ratio
		### +1 is entirely unnecessary
		myscore = myscore * (ratio + 1)

		### update overal minimum score for all result objects
		if myscore < min_score:
			min_score = myscore			

		### create actual result object and append to result array
		results.append(Result(myscore, _repr, address, "student"))


	### see comments above for expanation
	### same logic, some different variable names/paths
	for post in posts:
		myscore = 0.0
		for keyword in keywords.split():
			lowest_lev_result = 10000

			for word in post.title.split():
				lev_result = levenshtein(keyword, word) + .1
				if lev_result < lowest_lev_result:
					lowest_lev_result = lev_result

			myscore += lowest_lev_result

		address = "/home/%s/%s/%s/" % (post.student.grade.name, post.student.id, post.id)
		_repr = post.title
		

		## adjust final score by date
		epoch_time = time.time()
		timestamp_ = calendar.timegm(post.created.timetuple())
		ratio = (timestamp_ * 1.0) / (epoch_time * 1.0)
		myscore = myscore * (ratio + 1)
		if myscore < min_score:
			min_score = myscore				
		results.append(Result(myscore, _repr, address, "post"))


	### see comments on student section for explanation
	### same logic, some different variable names/paths
	for comment in comments:
		myscore = 0.0
		for keyword in keywords.split():
			lowest_lev_result = 10000
			### char counter just counts how many characters we've passed
			### char_position_word is the position of the last character in the word with the lowest
			### lev score
			char_counter = 0
			char_position_word = 0
			for word in comment.content.split():
				lev_result = levenshtein(keyword, word) + .1
				if lev_result < lowest_lev_result:
					lowest_lev_result = lev_result
					char_position_word = char_counter + (len(word))
				char_counter += (len(word) + 1) ### + 1 because we're splitting on spaces
			myscore += lowest_lev_result

		address = "/home/%s/%s/%s/#comment-%s" % (comment.post.student.grade.name, comment.post.student.id, comment.post_id, comment.id)
		_repr = comment.content[:char_position_word] + "..."

		## adjust final score by date
		epoch_time = time.time()
		timestamp_ = calendar.timegm(comment.created.timetuple())
		ratio = (timestamp_ * 1.0) / (epoch_time * 1.0)
		myscore = myscore * (ratio + 1)
		if myscore < min_score:
			min_score = myscore				
		results.append(Result(myscore, _repr, address, "comment"))


	### only return results with 50% variance of lowest score
	final_results = []
	score_range = min_score * 1.5
	for result in results:
		if result.score < score_range:
			final_results.append(result)	

	return final_results	

### routes ###

@app.route('/avatars/<filename>')
@requireLogin
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

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
	base = "abcdefghijklmnopqrstuvwxyz123456789"
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
					base = "abcdefghijklmnopqrstuvwxyz123456789.!@#$%^"
					salt = ''.join(random.sample(base, len(base)))
					subjectline = "Password reset code."
					address = request.form['email']
					code = hashlib.sha256(salt).hexdigest()[:5]

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
		if request.form['secret_key']:
			if request.form['code']:
				if request.form['secret_key'] == session['skey']:
					#if request.form['code'] == session['code']:
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
		createGrades(s)

		### create general discussion section for the school
		createGeneralDiscussion(s)


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
@methodTimer
@requireLogin
def route_home_settings():

	if request.method == "POST":
		teacher = Teacher.query.filter_by(id=session['user'].id).first()
		if 'avatar' in request.files:
			saveAvatar(teacher=teacher, request=request)
			flash("Successfully saved avatar.")

	return render_template("template_home_settings.html")

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
@methodTimer
@requireLogin
def route_home_general():
	posts = Post.query.filter_by(firstname=str(session['user'].school.id)).order_by(Post.id.desc())

	return render_template("template_home_general_discussion.html", posts=posts)

@app.route("/home/general-discussion/compose/", methods=['GET', 'POST'])
@methodTimer
@requireLogin
def route_home_general_compose():
	s = Student.query.filter_by(firstname=str(session['user'].school_id)).first()

	if request.method == "POST":
		if not request.form['title']:
			flash("Please include a title for your new post.")
			return render_template("template_home_general_discussion_compose.html", student=s)
		if not request.form['body']:
			flash("Please include something in the body of your new post.")
			return render_template("template_home_general_discussion_compose.html", student=s)

		p = Post(title=request.form['title'], teacher=session['user'], student=s)
		db.session.add( p )

		c = Comment(content=request.form['body'], teacher=session['user'], post=p)
		db.session.add( c )

		try:
			db.session.commit()
		except exc.SQLAlchemyError, e:
			flash("There was an error creating your post: " + str(e))
			return render_template("template_home_general_discussion_compose.html", student=s)


		return redirect(url_for('route_home_general'))

	return render_template("template_home_general_discussion_compose.html")

@app.route("/home/general-discussion/<post_id>/")
@methodTimer
@requireLogin
def route_home_general_post(post_id):
	s = Student.query.filter_by(firstname=str(session['user'].school_id)).first()
	p = Post.query.filter_by(id=post_id).first()
	comments = Comment.query.filter_by(post_id=post_id).all()
	
	if request.method == "POST":

		if not request.form['comment']:
			flash("The comment you attempted to enter was blank.")
			return render_template("template_home_general_discussion_post.html", post=p, comments=comments)

		c = Comment(content=request.form['comment'], teacher=session['user'], post=p)
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



	return render_template("template_home_general_discussion_post.html")


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
		uvc = UnviewedComment.query.filter_by(comment=comment, teacher_id=session['user'].id).first()
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

	### check if user is owner of the comment
	if c.author.id != session['user'].id:
		abort(401)

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
	return render_template("template_admin_teachers.html", teachers=teachers)

@app.route("/home/admin/teachers/delete/", methods=['POST'])
@methodTimer
@requireLogin
@requireAdmin
def route_home_admin_teachers_delete():
	### check teacher exists
	t = Teacher.query.filter_by(id=request.form['teacher_id']).first()
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

	return render_template("template_admin_teachers_teacher.html", teacher=teacher, grades=gradelist)

@app.route("/home/admin/teachers/<teacher_id>/makeadmin/", methods=['POST', 'GET'])
@methodTimer
@requireLogin
@requireAdmin
def route_home_admin_teachers_teacher_makeadmin(teacher_id):
	teacher = Teacher.query.filter_by(id=teacher_id).first()
	teacher.isAdmin = True
	db.session.commit()

	return redirect(url_for("route_home_admin_teachers_teacher", teacher_id=teacher_id))

@app.route("/home/admin/teachers/<teacher_id>/removeadmin/", methods=['POST', 'GET'])
@methodTimer
@requireLogin
@requireAdmin
def route_home_admin_teachers_teacher_removeadmin(teacher_id):
	teacher = Teacher.query.filter_by(id=teacher_id).first()
	teacher.isAdmin = False
	db.session.commit()

	return redirect(url_for("route_home_admin_teachers_teacher", teacher_id=teacher_id))

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
	
	return render_template("template_admin_students.html", students_by_grade=s_by_g)

@app.route("/home/admin/students/delete/<student_id>/", methods=['GET', 'POST'])
@methodTimer
@requireLogin
@requireAdmin
def route_home_admin_students_delete(student_id):

	student = Student.query.filter_by(id=student_id).first()
	db.session.delete(student)
	db.session.commit()

	flash("Student '" + student.lastname + ", " + student.firstname + "' has been deleted.")
	return redirect(url_for("route_home_admin_students"))

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

@app.route("/home/help/")
@methodTimer
@requireLogin
def route_home_help():
	return render_template("template_home_help.html")




@app.route("/home/search/", methods=['GET'])
@methodTimer
@requireLogin
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
			final_results = search_helper(teacher=teacher, keywords=keywords)

			### store results and query in session
			session['search_final_results'] = final_results
			session['search_query'] = keywords

		#### else session['search_query'] IS equal to keywords
		else:
			final_results = session['search_final_results']
	### else 'search_query' and 'search_final_results' do not exist in the session
	else:
		final_results = search_helper(teacher=teacher, keywords=keywords)

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

	print str(pages)

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
	presets()

	app.debug = True
	app.run()


