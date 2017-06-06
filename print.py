# -*- coding: utf-8 -*-
import matplotlib.pyplot as plt
import os
from os.path import expanduser

if __name__ == '__main__':
	home = expanduser("~")
	path = home + "/hashsecurity/md5Login.txt"

	array = []
	generations = []
	evaluationsMD5 = []
	evaluationsSHA1 = []
	evaluationsSHA256 = []
	evaluationsOriginal = []

	if(os.path.exists(path)):
		with open(path, "r") as archive:
			for line in archive:
				for word in line.split():
					array.append(word)

		i = 1
		for line in array:
			generation = str(i)
			i += 1
			generations.append(generation)

			evaluation = line
			evaluationsMD5.append(evaluation)

	array = []
	path = home + "/hashsecurity/sha1Login.txt"

	if(os.path.exists(path)):
		with open(path, "r") as archive:
			for line in archive:
				for word in line.split():
					array.append(word)

		i = 1
		for line in array:
			evaluation = line
			evaluationsSHA1.append(evaluation)

	array = []
	path = home + "/hashsecurity/sha256Login.txt"

	if(os.path.exists(path)):
		with open(path, "r") as archive:
			for line in archive:
				for word in line.split():
					array.append(word)

		i = 1
		for line in array:
			evaluation = line
			evaluationsSHA256.append(evaluation)

	array = []
	path = home + "/hashsecurity/originalLogin.txt"

	if(os.path.exists(path)):
		with open(path, "r") as archive:
			for line in archive:
				for word in line.split():
					array.append(word)

		i = 1
		for line in array:
			evaluation = line
			evaluationsOriginal.append(evaluation)

	plt.xlabel("Teste".decode("utf-8"))
	plt.ylabel("Tempo (seg)".decode("utf-8"))
	plt.plot(generations, evaluationsMD5, 'b', generations, evaluationsSHA1, 'r', generations, evaluationsSHA256, 'g', generations, evaluationsOriginal, 'black')
	plt.show()
