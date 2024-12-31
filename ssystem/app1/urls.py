"""
URL configuration for scoresystem project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.login, name='login'),
    path('getpng',views.createImg,name='getpng'),

    path('change_password/', views.change_password, name='change_password'),
    path('logout',views.logout,name='logout'),

    path('admin_dashboard/', views.admin_dashboard, name='admin_dashboard'),


    path('add_competition/', views.add_competition, name='add_competition'),
    path('delete_competition/', views.delete_competition, name='delete_competition'),
    path('delete_selected_competitions/', views.delete_selected_competitions, name='delete_selected_competitions'),
    path('query_competition/', views.query_competition, name='query_competition'),

    path('add_participation/', views.add_participation, name='add_participation'),
    path('delete_participation/', views.delete_participation, name='delete_participation'),
    path('delete_selected_participations/', views.delete_selected_participations, name='delete_selected_participations'),
    path('query_participation/', views.query_participation, name='query_participation'),

    
    # 查询成绩页面
    path('query_scores/', views.query_scores, name='query_scores'),

    # 更新成绩
    path('update_score/<int:contestant_id>/', views.update_score, name='update_score'),

    path('user_dashboard/', views.user_dashboard, name='user_dashboard'),
    path('user_competition/', views.user_competition, name='user_competition'),
    path('user_participation/', views.user_participation, name='user_participation'),
    path('user_scores/', views.user_scores, name='user_scores'),


    path('register/', views.register, name='register'),
    
]
