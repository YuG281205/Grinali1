from django.urls import path
from . import views
from .views import user_login

urlpatterns = [
    path('',views.index,name='index'),

    path('order/',views.order,name='order'),

    path('bigpizza/',views.bigpizza,name='bigpizza'),

    path('double_brust/',views.double_brust,name='double_brust'),
    
    path('garlic_bread/',views.garlic_bread,name='garlic_bread'),
    
    path('mania/',views.mania,name='mania'),
    
    path('spicy/',views.spicy,name='spicy'),
    
    path('regular/',views.regular,name='regular'),
    
    path('value_combo/',views.value_combo,name='value_combo'),
    
    path('vegpizza/',views.vegpizza,name='vegpizza'),
    
    path('volcano/',views.volcano,name='volcano'),
    
    path('cheeseburst/',views.cheeseburst,name='cheeseburst'),

    path('login/', user_login, name='login'),

    path('dashboard/', views.dashboard, name='dashboard'),

    path('logout/', views.user_logout, name='logout'),

    path('register/', views.register, name='register'),

     path('payment/', views.payment, name='payment'),
    
]


