from django.db import models
from django.contrib import admin


#SuperUserInformation
#User: satoshi
#Email: hello@coinsure.co.nz
#Password: password

class Node(models.Model):
	ip = models.CharField(max_length=60, ) #unique=True
	version = models.CharField(max_length=60)
	services = models.CharField(max_length=60)
	user_agent = models.CharField(max_length=60)
	start_height = models.CharField(max_length=60)
	created_date = models.DateTimeField(auto_now_add=True)


	