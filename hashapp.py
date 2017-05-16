import hashlib
from os.path import expanduser
import sys
import numpy as np
import json
import time

def funcMD5(database):
	dictMD5 = {}

	for registry in database:
		login = registry.split("|",1)[0]
		passwd = registry.split("|",1)[1]
		salt = "fe3a"

		newregistry = login + salt + passwd
		md5 = hashlib.md5()
		md5.update(newregistry)
		dictMD5[login] = md5.hexdigest()
	return dictMD5

def funcSHA1(database):
	dictSHA1 = {}

	for registry in database:
		login = registry.split("|",1)[0]
		passwd = registry.split("|",1)[1]
		salt = "fe3a"

		sha_1 = hashlib.sha1()
		newregistry = login + salt + passwd
		sha_1.update(newregistry)
		dictSHA1[login] = sha_1.hexdigest()

	return dictSHA1

def funcSHA256(database):
	dictSHA256 = {}

	for registry in database:
		login = registry.split("|",1)[0]
		passwd = registry.split("|",1)[1]
		salt = "fe3a"

		sha_256 = hashlib.sha256()
		newregistry = login + salt + passwd
		sha_256.update(newregistry)
		dictSHA256[login] = sha_256.hexdigest()

	return dictSHA256

if __name__ == '__main__':
	home = expanduser("~")
	path = home + "/hashsecurity/base.txt"

	database = []

	with open(path, "r") as archive:
		for line in archive:
			database.append(line)



	start = time.time()

	dictMD5 = funcMD5(database)
	with open("dictMD5.json", "w") as fp:
		json.dump(dictMD5, fp, sort_keys=True, indent=4)

	done = time.time()
	elapsed = done - start
	print "Time elapsed (MD5): " + str(elapsed) + " sec"



	start = time.time()

	dictSHA1 = funcSHA1(database)
	with open("dictSHA1.json", "w") as fp:
		json.dump(dictSHA1, fp, sort_keys=True, indent=4)

	done = time.time()
	elapsed = done - start
	print "Time elapsed (SHA1): " + str(elapsed) + " sec"



	start = time.time()

	dictSHA256 = funcSHA256(database)
	with open("dictSHA256.json", "w") as fp:
		json.dump(dictSHA256, fp, sort_keys=True, indent=4)

	done = time.time()
	elapsed = done - start
	print "Time elapsed (SHA256): " + str(elapsed) + " sec"
