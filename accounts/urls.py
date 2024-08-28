from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    path('login/',views.LoginAPI.as_view(),name='login'),
    path('logout/',views.LogoutAPI.as_view(),name='logout'),
    path('signup/',views.SignupAPI.as_view(),name='signup'),
    path('change-password/',views.ChangePasswordAPI.as_view(),name='change-password'),
    path('sendactivate/',views.ResendActivationLinkAPI.as_view(),name='sendactivate'),
    path('activate/<str:pk>/<str:token>/',views.ActivateAccountAPI.as_view(),name='active'),
    path('resetpassword/',views.PasswordResetAPI.as_view(),name='resetpassword'),
    path('reset-password-done/<str:pk>/<str:token>/',views.PasswordResetDoneAPI.as_view(),name='reset-password-done'),

]
