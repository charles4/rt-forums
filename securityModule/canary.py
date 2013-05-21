### for generateKey()
import hashlib
import random

def generateKey():
	""" generates a unique key """
	base = "abcdefghijklmnopqrstuvwxyz123456789"
	salt = ''.join(random.sample(base, len(base)))
	return hashlib.sha256(salt).hexdigest()

def createCanary(session):
	""" create and set and return a canary key """
	key = generateKey()
	session['canary'] = key
	return key

def checkCanary(session, request):
	""" check the canary key in session against a request """
	if "canary_key" in session:
		if "canary" in request.form:
			if session['canary'] == request.form['canary']:
				return True

	return False