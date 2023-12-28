
from django.urls import path
# from .views import UserList
from .views import *


urlpatterns = [
    path("register/", UserList.as_view(), name = "register"),
    path("email/", Sendmail.as_view(), name = "email"),

    path('login/', AuthUserLoginView.as_view(), name = "login"),
    path('pendingRequest/', PendingRequest.as_view(), name = "pendingRequest"),
    path('UserAmountStatus/', UserAmountStatus.as_view(), name = "UserAmountStatus"),
    path('UpdateAmountStatus/', UpdateAmountStatus.as_view(), name = "UpdateAmountStatus"),
    path('accountUpdate/', AccountUpdate.as_view(), name = "accountUpdate"),
    path('chatSheet/', ChatSheet.as_view(), name = "ChatSheet"),
    path('uploadProfile/', UploadProfile.as_view(), name = "UploadProfile"),
    path('PasswordUpdate/', PasswordUpdate.as_view(), name = "PasswordUpdate"),
    path('deleteFund/', DeleteFund.as_view(), name = "deleteFund"),
    path('reject/', Reject.as_view(), name = "Reject"),
    path('userData/', UserData1.as_view(), name = "userData"),
    path('checkOTP/', checkOTP ),
    path('sendOTP/',otpGeneration),
    path('AccountDetails/', AccountDetailss.as_view(), name = "AccountDetails"),
    path('ocr-extract/', ocr_extract, name='ocr_extract'),
     path(
        "",
       PasswordReset.as_view(),
        name="request-password-reset",
    ),
    path(
        "password-reset/<str:encoded_pk>/<str:token>/",
      ResetPasswordAPI.as_view(),
        name="reset-password",
    ),
    path('totalUserOneData/', TotalUserOneData.as_view(), name = "totalUserOneData"),
   path('deposits/', get_deposits, name='get_deposits'),
    path('deposit/', post_deposit, name='post_deposit'),
     path('transaction/', post_transaction),
    path('transaction/<str:email>/', get_transaction_by_email),
    path('messages/', post_message, name='post_message'),
      path('upload_excel/', upload_excel, name='upload_excel'),
    path('messages1/', get_messages_by_email, name='get_messages_by_email'),
    path('contact-info/', update_or_create_contact_info, name='update_or_create_contact_info'),
     path('get_stocks/', get_stock_data, name='get_stocks'),
    path('delete_stocks/', delete_stock_data, name='delete_stocks'),
    path('get_ContactFomr/', ContactInformationList.as_view(), name='get_ContactFomr'),
    path('update_kyc/', Update_kyc.as_view(), name='update_kyc'),
    path('user-data/', UserDataView.as_view(),name='UserDataView'),
     path("emailNewRegistratinos/", SendmailRegistrations.as_view(), name = "emailNewRegistratinos"),
]