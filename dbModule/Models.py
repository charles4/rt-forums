#### this will be initialized with the flask app later
from datetime import datetime
from flask.ext.sqlalchemy import SQLAlchemy
from flaskext.bcrypt import Bcrypt 

bcrypt = Bcrypt()
db = SQLAlchemy()

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
	avatar = db.Column(db.String(128))

	### db relationships
	school_id = db.Column(db.Integer, db.ForeignKey('school.id'))
	school = db.relationship('School', backref=db.backref('teachers', lazy='dynamic'))

	def __init__(self, email=None, school=None, key=None, firstname=None, lastname=None, password=None, secretquestion=None, secretanswer=None, isAdmin=False, create_date=None, avatar=None):
		self.firstname = firstname
		self.lastname = lastname
		self.email = email
		self.isAdmin = isAdmin
		if create_date is None:
			create_date = datetime.utcnow()
		self.created = create_date
		self.school = school
		self.secretquestion = secretquestion
		self.secretanswer = secretanswer
		self.onetimekey = key
		if avatar is None:
			self.avatar = "default_avatar.jpg"
		else:
			self.avatar = avatar

		self.setpassword(password)

	def setpassword(self, password):
		### strip whitespace from front and back of password
		password = password.strip() 
		self.phash = bcrypt.generate_password_hash(password, 14)


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
	content = db.Column(db.Text)

	### relationships
	author_id = db.Column(db.Integer, db.ForeignKey('teacher.id'))
	author = db.relationship('Teacher', backref=db.backref('comments', lazy='dynamic'))

	post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
	post = db.relationship('Post', backref=db.backref('comments',lazy='dynamic'))

	def __init__(self, content, teacher, teachers, post, create_date=None):
		self.content = content
		self.author = teacher
		self.post = post
		if create_date is None:
			create_date = datetime.utcnow()
		self.created = create_date

		### for each teacher create a unviewed comment
		for t in teachers:
			if t.id != self.author_id:
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

class GradePermissionToken(db.Model):
	id = db.Column(db.Integer, primary_key=True)

	### relationships
	grade_id = db.Column(db.Integer, db.ForeignKey('grade.id'))
	grade = db.relationship('Grade', backref=db.backref("grade_tokens", lazy="dynamic"))

	teacher_id = db.Column(db.Integer, db.ForeignKey('teacher.id'))
	teacher = db.relationship('Teacher', backref=db.backref('grade_tokens', lazy='dynamic'))

	def __init__(self, grade, teacher):
		self.grade = grade
		self.teacher = teacher

	def __repr__(self):
		return "<Grade Permission %r>" % self.id