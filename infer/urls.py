"""
urls of inference of erase bg
"""
from rest_framework.urls import path
# from infer.views.replicate_views import EraseBGCreatePredicitonView, PollPredictionView, FetchOutputView
from infer.views.credits_views import InitiateInferenceView, InititateBulkInferenceView, WrapUpInferenceView, WrapUpBulkinferenceView

urlpatterns = [
#     path('removebg/', EreaseBG.as_view(), name='removebg'),
#     path('removebg/create-prediction', EraseBGCreatePredicitonView.as_view(), name='removebg-create-prediction'),
#     path('removebg/poll-prediction', PollPredictionView.as_view(),
#          name='removebg-poll-prediction'),
#     path('removebg/fetch-output', FetchOutputView.as_view(),
#          name='removebg-fetch-output'),
     path('infer/initiate-inference/', InitiateInferenceView.as_view(),
          name='infer-initiate-inference'),
     path('infer/initiate-bulk-inference/', InititateBulkInferenceView.as_view(), name='infer-initiate-bulk-inference'),
     path('infer/wrapup-inference/', WrapUpInferenceView.as_view(), name='infer-wrapup-inference'),
     path('infer/wrapup-bulk-inference/', WrapUpBulkinferenceView.as_view(), name='infer-wrapup-bulk-inference')
]
