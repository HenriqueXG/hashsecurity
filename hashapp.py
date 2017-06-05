import hashlib
from os.path import expanduser
import os;
import sys
import numpy as np
import json
import time
import re

class Caesar:
	def __init__(self):
		self.__letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

	def encrypt(self, texto_plano, key = 12):
		'''(Caesar, str, int) -> str

		Retorna o texto_plano cifrado com a cifra
		de Cesar, utlizando a chave key,
		cujo padrao e 3.
		'''
		cipher_text = ''
		texto_plano = texto_plano.upper()
		for ch in texto_plano:
			if ch in self.__letters:
				idx = self.__letters.find(ch) + key
				if idx >= 26:
					idx -= 26
				cipher_text += self.__letters[idx]
		return cipher_text

	def decrypt(self, texto_cifrado,  key = 12):
		''' (Caesar, str, int) -> str

		Retorna em texto plano o texto_cifrado decifrado
		com a cifra de Cesar, utilizando a chave key,
		cujo padrao e 3.
		'''
		plain_text = ''
		texto_cifrado = texto_cifrado.upper()
		for ch in texto_cifrado:
			if ch in self.__letters:
				idx = self.__letters.find(ch) - key
				plain_text += self.__letters[idx]
		return plain_text.lower()

def funcMD5(database):
	dictMD5 = {}
	cesar = Caesar()

	for registry in database:
		login = registry.split("|",1)[0]
		passwd = registry.split("|",1)[1]

		passwd = re.sub('[^A-z0-9]', '', passwd)
		passwd = cesar.decrypt(passwd)

		salt = "fe3a"

		newregistry = login + salt + passwd
		md5 = hashlib.md5()
		md5.update(newregistry)
		dictMD5[login] = md5.hexdigest()
	return dictMD5

def funcSHA1(database):
	dictSHA1 = {}
	cesar = Caesar()

	for registry in database:
		login = registry.split("|",1)[0]
		passwd = registry.split("|",1)[1]

		passwd = re.sub('[^A-z0-9]', '', passwd)
		passwd = cesar.decrypt(passwd)

		salt = "fe3a"

		sha_1 = hashlib.sha1()
		newregistry = login + salt + passwd
		sha_1.update(newregistry)
		dictSHA1[login] = sha_1.hexdigest()

	return dictSHA1

def funcSHA256(database):
	dictSHA256 = {}
	cesar = Caesar()

	for registry in database:
		login = registry.split("|",1)[0]
		passwd = registry.split("|",1)[1]

		passwd = re.sub('[^A-z0-9]', '', passwd)
		passwd = cesar.decrypt(passwd)

		salt = "fe3a"

		sha_256 = hashlib.sha256()
		newregistry = login + salt + passwd
		sha_256.update(newregistry)
		dictSHA256[login] = sha_256.hexdigest()

	return dictSHA256

def funcClear(database):
	dictClear = {}
	cesar = Caesar()

	for registry in database:
		login = registry.split("|",1)[0]
		passwd = registry.split("|",1)[1]

		passwd = re.sub('[^A-z0-9]', '', passwd)
		passwd = cesar.decrypt(passwd)

		dictClear[login] = passwd

	return dictClear

def funcLoginHash(login, passwd, hashes, hashUsed):
	user = hashes[hashUsed].get(login)
	if user:
		registry = login + "fe3a" + passwd

		if hashUsed == 0:
			md5 = hashlib.md5()
			md5.update(registry)
			if user == md5.hexdigest():
				return 1
		elif hashUsed == 1:
			sha_1 = hashlib.sha1()
			sha_1.update(registry)
			if user == sha_1.hexdigest():
				return 1
		elif hashUsed == 2:
			sha_256 = hashlib.sha256()
			sha_256.update(registry)
			if user == sha_256.hexdigest():
				return 1

	return 0

def funcLoginClear(login, passwd, dictClear):
	user = dictClear.get(login)

	if user == passwd:
		return 1

	return 0

if __name__ == '__main__':
	home = expanduser("~")
	path = home + "/hashsecurity/base.txt"

	database = []

	with open(path, "r") as archive:
		for line in archive:
			database.append(line)

	doLogin = 1
	doLoginClear = 0
	hashes = []

	if doLogin == int(sys.argv[1]):
		with open('dictMD5.json', 'r') as fp:
			dictMD5 = json.load(fp)
			hashes.append(dictMD5)
		with open('dictSHA1.json', 'r') as fp:
			dictSHA1 = json.load(fp)
			hashes.append(dictSHA1)
		with open('dictSHA256.json', 'r') as fp:
			dictSHA256 = json.load(fp)
			hashes.append(dictSHA256)

		start = time.time()

		if funcLoginHash(sys.argv[2], sys.argv[3], hashes, int(sys.argv[4])):
			print "Success !"
		else:
			print "Fail !"

		done = time.time()
		elapsed = done - start
		print "Time elapsed (login with hash): " + str(elapsed) + " sec"
	else:
		########################MD5#############################

		for i in range(0,30):
			start = time.time()

			dictMD5 = funcMD5(database)
			with open("dictMD5.json", "w") as fp:
				json.dump(dictMD5, fp, sort_keys=True, indent=4)

			done = time.time()
			elapsed = done - start
			print "Time elapsed (MD5): " + str(elapsed) + " sec"
			os.system("echo \"" + str(elapsed) + "\" >> md5Create.txt")

			hashes.append(dictMD5)

		########################SHA1#############################

		start = time.time()

		dictSHA1 = funcSHA1(database)
		with open("dictSHA1.json", "w") as fp:
			json.dump(dictSHA1, fp, sort_keys=True, indent=4)

		done = time.time()
		elapsed = done - start
		print "Time elapsed (SHA1): " + str(elapsed) + " sec"

		hashes.append(dictSHA1)

		########################SHA256#############################

		start = time.time()

		dictSHA256 = funcSHA256(database)
		with open("dictSHA256.json", "w") as fp:
			json.dump(dictSHA256, fp, sort_keys=True, indent=4)

		done = time.time()
		elapsed = done - start
		print "Time elapsed (SHA256): " + str(elapsed) + " sec"

		hashes.append(dictSHA256)

########################LoginClear#############################
if doLoginClear:
	dictClear = funcClear(database)

	start = time.time()

	if funcLoginClear(sys.argv[2], sys.argv[3], dictClear):
		print "Success !"
	else:
		print "Fail !"

	done = time.time()
	elapsed = done - start
	print "Time elapsed (login without hash): " + str(elapsed) + " sec"
