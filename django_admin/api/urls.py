from django.urls import path
from django.shortcuts import HttpResponse
from .views import URLPredictionApiView

urlpatterns = [
    path('predict/', URLPredictionApiView.as_view(), name='predict'),
    
]
