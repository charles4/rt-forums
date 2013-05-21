
from functools import wraps
import time

class Wrappers(object):

	def __init__(self, session=None, database=None):
		self.session = session
		self.db = database

	def methodTimer(self, function):
		@wraps(function)
		def decorated_view(*args, **kwargs):
			t = time.time()
			result = function(*args, **kwargs)
			print function.__name__ + " took " + str(time.time() - t) + " seconds."
			return result
		return decorated_view

	def requireLogin(self, fn):
		@wraps(fn)
		def decorated(*args, **kwargs):
			if 'user' in self.session:
				return fn(*args, **kwargs)
			return redirect(url_for("route_login"))
		return decorated

	def requireAdmin(self, fn):
		@wraps(fn)
		def decorated(*args, **kwargs):
			if "user" in self.session:
				if self.session["user"].isAdmin == "1":
					return fn(*args, **kwargs)
			abort(401)

		return decorated

	def requirePermission(self, fn):
		@wraps(fn)
		def decorated(*args, **kwargs):
			teacher = self.session['user']
			self.db.session.add(teacher)

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