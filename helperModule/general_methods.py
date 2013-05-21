### General Methods ###
from werkzeug import secure_filename
import os
from PIL import Image
from sqlalchemy import exc

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

class General(object):
	""" a class of generally helpful methods """
	def __init__(self, session, db, app):
		self.session = session
		self.db = db
		self.app = app


	def allowed_file(self, filename):
		return "." in filename and \
			filename.rsplit(".", 1)[1] in self.app.config["ALLOWED_EXTENSIONS"]

	def saveAvatar(self, teacher, request):
		size = 64, 64
		### get file obj from request ###
		myfile = request.files['avatar']
		if myfile and allowed_file (myfile.filename):
			### setup filename and save to filesystem ####
			filename = str(self.session['user'].id) + "_" + secure_filename(myfile.filename)
			myfile.save(os.path.join(self.app.config['UPLOAD_FOLDER'], filename))

			### after saving re-open and create tiny version 
			image = Image.open(os.path.join(self.app.config['UPLOAD_FOLDER'], filename))
			image.thumbnail(size)
			filename = str(self.session['user'].id) + "_thumbnail_" + secure_filename(myfile.filename)
			image.save(os.path.join(self.app.config['UPLOAD_FOLDER'], filename))
			### add filename to db
			teacher.avatar = filename
			self.db.session.commit()
			### refresh teacher obj in self.session
			self.session['user'] = teacher

			return True

		else:			
			return False

	def logout(self):
		self.session.pop('user', None)

	def createGeneralDiscussion(self, school):
		self.db.session.add(Student(firstname=str(school.id), lastname="General Discussion", grade=None))
		try:
			self.db.session.commit()
		except exc.SQLAlchemyError, e:
			print str(e)

	def createGrades(self, school):
		self.db.session.add(Grade("Kindergarden", 0, school))
		self.db.session.add(Grade("First Grade", 1, school))
		self.db.session.add(Grade("Second Grade", 2, school))
		self.db.session.add(Grade("Third Grade", 3, school))
		self.db.session.add(Grade("Fourth Grade", 4, school))
		self.db.session.add(Grade("Fifth Grade", 5, school))
		self.db.session.add(Grade("Sixth Grade", 6, school))
		self.db.session.add(Grade("Seventh Grade", 7, school))
		self.db.session.add(Grade("Eighth Grade", 8, school))
		self.db.session.add(Grade("Ninth Grade", 9, school))
		self.db.session.add(Grade("Tenth Grade", 10, school))
		self.db.session.add(Grade("Eleventh Grade", 11, school))
		self.db.session.add(Grade("Twelfth Grade", 12, school))
		self.db.session.add(Grade("Graduated", 13, school))
		try:
			self.db.session.commit()
		except exc.SQLAlchemyError, e:
			print str(e)


	def search_helper(self, keywords, teacher):
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
