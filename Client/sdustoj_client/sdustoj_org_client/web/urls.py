from django.conf.urls import url, include
from .views import MainPages, UserPages, SelfPages, OrgPages, CoursePages, MyCoursePages


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

course_patterns = [
    url(r'^$', CoursePages.Course.list, name='web-courses'),
    url(r'^create/', CoursePages.Course.create, name='web-courses-create'),
    url(r'^(\d+)/$', CoursePages.Course.instance, name='web-courses-instance'),
]

course_teacher_patterns = [
    url(r'^$', CoursePages.CourseTeacherRelation.list, name='web-course-teacher-relations'),
    url(r'^create/', CoursePages.CourseTeacherRelation.create, name='web-course-teacher-relations-create'),
    url(r'^(\d+)/$', CoursePages.CourseTeacherRelation.instance, name='web-course-teacher-relations-instance')
]

course_student_patterns = [
    url(r'^$', CoursePages.CourseStudentRelation.list, name='web-course-student-relations'),
    url(r'^create/', CoursePages.CourseStudentRelation.create, name='web-course-student-relations-create'),
    url(r'^(\d+)/$', CoursePages.CourseStudentRelation.instance, name='web-course-student-relations-instance')
]

course_readonly_patterns = [
    url(r'^$', CoursePages.CourseReadonly.list, name='web-course-readonly'),
    url(r'^(\d+)/$', CoursePages.CourseReadonly.instance, name='web-course-readonly-instance'),
    url(r'^(\d+)/student-relations/', include(course_student_patterns)),
    url(r'^(\d+)/teacher-relations/', include(course_teacher_patterns)),
]

course_meta_patterns = [
    url(r'^$', CoursePages.CourseMeta.list, name='web-course-meta'),
    url(r'^create/', CoursePages.CourseMeta.create, name='web-course-meta-create'),
    url(r'^(\d+)/$', CoursePages.CourseMeta.instance, name='web-course-meta-instance'),
    url(r'^(\d+)/courses/', include(course_patterns)),
]

course_group_relation_patterns = [
    url(r'^$', CoursePages.CourseGroupRelation.list, name='web-course-group-relations'),
    url(r'^create/', CoursePages.CourseGroupRelation.create, name='web-course-group-relations-create'),
    url(r'^(\d+)/$', CoursePages.CourseGroupRelation.instance, name='web-course-group-relations-instance'),
]

course_group_patterns = [
    url(r'^$', CoursePages.CourseGroup.list, name='web-course-groups'),
    url(r'^create/', CoursePages.CourseGroup.create, name='web-course-groups-create'),
    url(r'^(\d+)/$', CoursePages.CourseGroup.instance, name='web-course-groups-instance'),
    url(r'^(\d+)/relations/', include(course_group_relation_patterns)),
]

org_admin_patterns = [
    url(r'^$', OrgPages.Organization.list, name='web-orgs'),
    url(r'^create/', OrgPages.Organization.create, name='web-orgs-create'),
    url(r'^(\d+)/$', OrgPages.Organization.instance, name='web-orgs-instance'),
    url(r'^(\d+)/edu-admins/', include(edu_admin_patterns)),
    url(r'^(\d+)/teachers/', include(teacher_patterns)),
    url(r'^(\d+)/students/', include(student_patterns)),
    url(r'^(\d+)/courses/', include(course_readonly_patterns)),
    url(r'^(\d+)/course-meta/', include(course_meta_patterns)),
    url(r'^(\d+)/course-groups/', include(course_group_patterns)),
]

my_org_patterns = [
    url(r'^$', OrgPages.MyOrganization.list, name='web-my-orgs'),
    url(r'^(\d+)/$', OrgPages.MyOrganization.instance, name='web-my-orgs-instance'),
]

teaching_student_patterns = [
    url(r'^$', MyCoursePages.StudentRelation.list, name='web-teaching-course-students'),
    url(r'^create/', MyCoursePages.StudentRelation.create, name='web-teaching-course-students-create'),
    url(r'^(\d+)/$', MyCoursePages.StudentRelation.instance, name='web-teaching-course-students-instance'),
]

teaching_course_patterns = [
    url(r'^$', MyCoursePages.TeachingCourse.list, name='web-teaching-courses'),
    url(r'^(\d+)/$', MyCoursePages.TeachingCourse.instance, name='web-teaching-courses-instance'),
    url(r'^(\d+)/student-relations/', include(teaching_student_patterns)),
]

learning_course_patterns = [
    url(r'^$', MyCoursePages.LearningCourse.list, name='web-learning-courses'),
    url(r'^(\d+)/$', MyCoursePages.LearningCourse.instance, name='web-learning-courses-instance'),
]

url_patterns = [
    url(r'^home/', MainPages.home, name='web-home'),
    url(r'^login/', MainPages.login, name='web-login'),
    url(r'^personal/', include(personal_patterns)),
    url(r'^users/', include(user_patterns)),
    url(r'^admins/', include(admin_patterns)),
    url(r'^my-organizations/', include(my_org_patterns)),
    url(r'^organizations/', include(org_admin_patterns)),
    url(r'^teaching-courses/', include(teaching_course_patterns)),
    url(r'^learning-courses/', include(learning_course_patterns)),
]
