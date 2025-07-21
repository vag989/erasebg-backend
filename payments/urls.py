"""
urls of payments app
"""

from rest_framework.urls import path

from payments.views import AddCreditsView, AddBulkCreditsView

urlpatterns = [
    path('payments/add-credits/', AddCreditsView.as_view(), name='payments-add-credits'),
    path('payments/add-bulk-credits/', AddBulkCreditsView.as_view(), name='payments-add-bulk-credits'),
]