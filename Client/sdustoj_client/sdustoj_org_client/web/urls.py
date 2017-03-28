from django.conf.urls import url, include
from .views import MainPages, UserPages, SelfPages, OrgPages


personal_patterns = [
    url(r'^info/', SelfPages.info, name='web-personal-info'),
    url(r'^password/', SelfPages.password, name='web-personal-password'),
]


admin_patterns = [
    url(r'^$', UserPages.AdminAdmin.list, name='web-admins'),
    url(r'^create/', UserPages.AdminAdmin.create, name='web-admins-create'),
    url(r'^info/(\S+)/', UserPages.AdminAdmin.instance, name='web-admins-instance')
]

user_patterns = [
    url(r'^$', UserPages.UserAdmin.list, name='web-users'),
    url(r'^create/', UserPages.UserAdmin.create, name='web-users-create'),
    url(r'^info/(\S+)/', UserPages.UserAdmin.instance, name='web-users')
]

edu_admin_patterns = [
    url(r'^$', OrgPages.EduAdmin.list, name='web-edu-admins'),
    url(r'^create/', OrgPages.EduAdmin.create, name='web-edu-admins-create'),
    url(r'^(\d+)/', OrgPages.EduAdmin.instance, name='web-edu-admins-instance')
]

teacher_patterns = [
    url(r'^$', OrgPages.Teacher.list, name='web-teachers'),
    url(r'^create/', OrgPages.Teacher.create, name='web-teachers-create'),
    url(r'^(\d+)/', OrgPages.Teacher.instance, name='web-teachers-instance')
]

student_patterns = [
    url(r'^$', OrgPages.Student.list, name='web-students'),
    url(r'^create/', OrgPages.Student.create, name='web-students-create'),
    url(r'^(\d+)/', OrgPages.Student.instance, name='web-students-instance')
]

org_admin_patterns = [
    url(r'^$', OrgPages.Organization.list, name='web-orgs'),
    url(r'^create/', OrgPages.Organization.create, name='web-orgs-create'),
    url(r'^(\d+)/$', OrgPages.Organization.instance, name='web-orgs-instance'),
    url(r'^(\d+)/edu-admins/', include(edu_admin_patterns)),
    url(r'^(\d+)/teachers/', include(teacher_patterns)),
    url(r'^(\d+)/students/', include(student_patterns)),
]

url_patterns = [
    url(r'^home/', MainPages.home, name='web-home'),
    url(r'^login/', MainPages.login, name='web-login'),
    url(r'^personal/', include(personal_patterns)),
    url(r'^users/', include(user_patterns)),
    url(r'^admins/', include(admin_patterns)),
    url(r'^organizations/', include(org_admin_patterns)),
]
