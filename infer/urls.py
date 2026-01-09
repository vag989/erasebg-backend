# """
# urls of inference of erase bg
# """
from rest_framework.urls import path

# from infer.views.replicate_views import EraseBGCreatePredicitonView, PollPredictionView, FetchOutputView
from infer.views.credits_views import (
    InitiateInferenceWorkerView,
    InititateBulkInferenceWorkerView,
    InitiateAPIInferenceWorkerView,
    WrapUpInferenceWorkerView,
    WrapUpBulkInferenceWorkerView,
    WrapUpAPIInferenceWorkerView
)

urlpatterns = [
    #     path('removebg/', EreaseBG.as_view(), name='removebg'),
    #     path('removebg/create-prediction', EraseBGCreatePredicitonView.as_view(), name='removebg-create-prediction'),
    #     path('removebg/poll-prediction', PollPredictionView.as_view(),
    #          name='removebg-poll-prediction'),
    #     path('removebg/fetch-output', FetchOutputView.as_view(),
    #          name='removebg-fetch-output'),
    path(
        "infer/initiate-inference/",
        InitiateInferenceWorkerView.as_view(),
        name="infer-initiate-inference",
    ),
    path(
        "infer/initiate-bulk-inference/",
        InititateBulkInferenceWorkerView.as_view(),
        name="infer-initiate-bulk-inference",
    ),
    path(
        "infer/initiate-api-inference/",
        InitiateAPIInferenceWorkerView.as_view(),
        name="infer-initiate-api-inference",
    ),
    path(
        "infer/wrapup-inference/",
        WrapUpInferenceWorkerView.as_view(),
        name="infer-wrapup-inference",
    ),
    path(
        "infer/wrapup-bulk-inference/",
        WrapUpBulkInferenceWorkerView.as_view(),
        name="infer-wrapup-bulk-inference",
    ),
    path(
        "infer/wrapup-api-inference/",
        WrapUpAPIInferenceWorkerView.as_view(),
        name="infer-wrapup-api-inference",
    )
    #  path('infer/wrapup-api-inference/', WrapUpAPIInferenceView.as_view(), name='infer-wrapup-api-inference'),
]
