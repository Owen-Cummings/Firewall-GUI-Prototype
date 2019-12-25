from django.urls import path
from django.contrib.auth import views as auth_views

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('docs', views.docs, name='docs'),
    path('firewall/rules/search', views.search_rules, name='firewall-rules-search'),
    path('firewall/rules/view', views.view_rules, name='firewall-rules-view'),
    path('firewall/rules/import', views.import_rules, name='firewall-rule-import'),
    path('firewall/rules/export', views.export_rules, name='firewall-rule-export'),
    path('firewall/rule/create', views.create_rule, name='firewall-rule-create'),
    path('firewall/rule/delete', views.delete_rule, name='firewall-rule-delete'),
    path('firewall/rule/edit', views.edit_rule, name='firewall-rule-edit'),
    path('firewall/rule/disable', views.disable_rule, name='firewall-rule-disable'),
    path('firewall/dashboard', views.dashboard, name='firewall-dashboard'),
    path('user/login', views.login_firewall, name='user-login'),
    path('user/logout', views.logout_firewall, name='user-logout'),
    path('users/view', views.view_users, name='users-view'),
    path('user/register', views.register_user, name='user-register'),
    path('users/search', views.search_users, name='users-search'),
    path('user/create', views.create_user, name='user-create'),
    path('user/delete', views.delete_user, name='user-delete'),
    path('user/edit', views.edit_user, name='user-edit'),
    path('user/disable', views.disable_user, name='user-disable'),
    path('user/password/recovery', views.recover_password, name='user-password-recovery'),
]
