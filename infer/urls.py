"""
urls of inference of erase bg
"""
from rest_framework.urls import path
from infer.views import EraseBGView, PollPredictionView, FetchOutputView

urlpatterns = [
    path('removebg/', EraseBGView.as_view(), name='removebg'),
    path('removebg/poll-prediction', PollPredictionView.as_view(),
         name='removebg-poll-prediction'),
    path('removebg/fetch-output', FetchOutputView.as_view(),
         name='removebg-fetch-output')
]
