# -*- encoding=utf-8 -*
from rest_framework.routers import DefaultRouter
from rest_framework_nested.routers import NestedSimpleRouter
from .views import UserViewSets, OrgViewSets, CourseViewSets

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
admin_org_router.register(
    r'course-meta', CourseViewSets.CourseMeta.CourseMetaAdminViewSet, base_name='admin-course-meta'
)
admin_org_router.register(
    r'courses', CourseViewSets.Course.CourseEduViewSet, base_name='admin-course-readonly'
)
admin_org_router.register(
    r'course-groups', CourseViewSets.CourseGroup.CourseGroupAdminViewSet,
    base_name='admin-course-group'
)

admin_course_router = NestedSimpleRouter(admin_org_router, r'courses', lookup='course')
admin_course_router.register(
    r'teacher-relations', CourseViewSets.TeacherRelation.List.TeacherRelationAdminViewSet,
    base_name='admin-course-teacher-relation'
)
admin_course_router.register(
    r'teacher-relations', CourseViewSets.TeacherRelation.Instance.TeacherRelationAdminViewSet,
    base_name='admin-course-teacher-relation'
)
admin_course_router.register(
    r'student-relations', CourseViewSets.StudentRelation.List.StudentRelationAdminViewSet,
    base_name='admin-course-student-relation'
)
admin_course_router.register(
    r'student-relations', CourseViewSets.StudentRelation.Instance.StudentRelationAdminViewSet,
    base_name='admin-course-student-relation'
)
admin_course_meta_router = NestedSimpleRouter(admin_org_router, r'course-meta', lookup='course_meta')
admin_course_meta_router.register(
    r'courses', CourseViewSets.Course.CourseAdminViewSet, base_name='admin-course'
)
admin_course_group_router = NestedSimpleRouter(admin_org_router, r'course-groups', lookup='course_group')
admin_course_group_router.register(
    r'course-relations', CourseViewSets.CourseGroup.CourseGroupRelation.List.CourseGroupRelationAdminViewSet,
    base_name='admin-course-group-relation'
)
admin_course_group_router.register(
    r'course-relations', CourseViewSets.CourseGroup.CourseGroupRelation.Instance.CourseGroupRelationAdminViewSet,
    base_name='admin-course-group-relation'
)
admin_course_group_router.register(
    r'teacher-relations', CourseViewSets.GroupTeacherRelation.List.GroupTeacherRelationAdminViewSet,
    base_name='admin-course-group-teacher-relation'
)
admin_course_group_router.register(
    r'teacher-relations', CourseViewSets.GroupTeacherRelation.Instance.GroupTeacherRelationAdminViewSet,
    base_name='admin-course-group-teacher-relation'
)

admin_url_patterns = []
admin_url_patterns += admin_router.urls
admin_url_patterns += admin_org_router.urls
admin_url_patterns += admin_course_router.urls
admin_url_patterns += admin_course_meta_router.urls
admin_url_patterns += admin_course_group_router.urls


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
router.register(
    r'organizations', OrgViewSets.Organization.List.OrganizationViewSet, base_name='api-organization'
)
router.register(
    r'organizations', OrgViewSets.Organization.Instance.OrganizationViewSet, base_name='api-organization'
)
router.register(
    r'course-groups', CourseViewSets.CourseGroup.CourseGroupTeacherViewSet,
    base_name='api-course-group'
)
router.register(
    r'courses-teaching', CourseViewSets.Course.CourseTeacherViewSet,
    base_name='api-course-teaching'
)
router.register(
    r'courses-learning', CourseViewSets.Course.CourseStudentViewSet,
    base_name='api-course-learning'
)
course_teaching_router = NestedSimpleRouter(router, r'courses-teaching', lookup='course')
course_teaching_router.register(
    r'student-relations', CourseViewSets.StudentRelation.List.StudentRelationViewSet,
    base_name='api-course-student-relation'
)
course_teaching_router.register(
    r'student-relations', CourseViewSets.StudentRelation.Instance.StudentRelationViewSet,
    base_name='api-course-student-relation'
)

api_url_patterns = []
api_url_patterns += router.urls
api_url_patterns += course_teaching_router.urls
