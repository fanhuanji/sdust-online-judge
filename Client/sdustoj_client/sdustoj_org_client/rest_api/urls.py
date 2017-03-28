# -*- encoding=utf-8 -*
from rest_framework.routers import DefaultRouter
from rest_framework_nested.routers import NestedSimpleRouter
from .views import UserViewSets, OrgViewSets

admin_router = DefaultRouter()

admin_router.register(
    r'admins', UserViewSets.Admin.List.AdminAdminViewSet, base_name='admin-admin'
)
admin_router.register(
    r'admins', UserViewSets.Admin.Instance.AdminAdminViewSet, base_name='admin-admin'
)
admin_router.register(
    r'users', UserViewSets.User.List.UserAdminViewSet, base_name='admin-user'
)
admin_router.register(
    r'users', UserViewSets.User.Instance.UserAdminViewSet, base_name='admin-user'
)
admin_router.register(
    r'organizations', OrgViewSets.Organization.List.OrganizationAdminViewSet, base_name='admin-organization'
)
admin_router.register(
    r'organizations', OrgViewSets.Organization.Instance.OrganizationAdminViewSet, base_name='admin-organization'
)
admin_org_router = NestedSimpleRouter(admin_router, r'organizations', lookup='organization')
admin_org_router.register(
    r'edu-admins', OrgViewSets.EduAdmin.List.EduAdminAdminViewSet, base_name='admin-edu-admin'
)
admin_org_router.register(
    r'edu-admins', OrgViewSets.EduAdmin.Instance.EduAdminAdminViewSet, base_name='admin-edu-admin'
)
admin_org_router.register(
    r'teachers', OrgViewSets.Teacher.List.TeacherAdminViewSet, base_name='admin-teacher'
)
admin_org_router.register(
    r'teachers', OrgViewSets.Teacher.Instance.TeacherAdminViewSet, base_name='admin-teacher'
)
admin_org_router.register(
    r'students', OrgViewSets.Student.List.StudentAdminViewSet, base_name='admin-student'
)
admin_org_router.register(
    r'students', OrgViewSets.Student.Instance.StudentAdminViewSet, base_name='admin-student'
)

admin_url_patterns = []
admin_url_patterns += admin_router.urls
admin_url_patterns += admin_org_router.urls


router = DefaultRouter()
router.register(
    r'login', UserViewSets.LoginViewSet, base_name='api-login'
)
router.register(
    r'logout', UserViewSets.LogoutViewSet, base_name='api-logout'
)
router.register(
    r'personal-info', UserViewSets.Self.UserViewSet, base_name='api-personal-info'
)

api_url_patterns = []
api_url_patterns += router.urls
