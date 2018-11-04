from django.conf.urls import url
from  btccrawl import views

urlpatterns=[
    url(r'^$',views.index,name='index'),
    url(r'^submit', views.submit),
    url(r'^nodelist', views.nodelist),

]