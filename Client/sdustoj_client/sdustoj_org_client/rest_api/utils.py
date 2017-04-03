from .models import EduAdmin, Teacher, Student
from .models import CourseStudentRelation, CourseTeacherRelation, CourseGroupTeacherRelation
from .models import IdentityChoices


def has_site_admin_identity(id_str, identities):
    return id_str in identities and identities[id_str] is True


def is_root(user):
    identities = user.profile.identities
    return IdentityChoices.root in identities and identities[IdentityChoices.root] is True


def flush_identities(user):
    profile = user.profile

    identities = {}
    if has_site_admin_identity(IdentityChoices.user_admin, profile.identities):
        identities[IdentityChoices.user_admin] = True
    if has_site_admin_identity(IdentityChoices.org_admin, profile.identities):
        identities[IdentityChoices.org_admin] = True
    if has_site_admin_identity(IdentityChoices.root, profile.identities):
        identities[IdentityChoices.root] = True

    students = getattr(Student, 'objects').filter(user=user).values('organization_id').distinct()
    teachers = getattr(Teacher, 'objects').filter(user=user).values('organization_id').distinct()
    edu_admins = getattr(EduAdmin, 'objects').filter(user=user).values('organization_id').distinct()

    id_students = []
    for student in students:
        id_students.append(student['organization_id'])
    id_teachers = []
    for teacher in teachers:
        id_teachers.append(teacher['organization_id'])
    id_edu_admins = []
    for edu_admin in edu_admins:
        id_edu_admins.append(edu_admin['organization_id'])

    if id_students:
        identities[IdentityChoices.student] = id_students
    if id_teachers:
        identities[IdentityChoices.teacher] = id_teachers
    if id_edu_admins:
        identities[IdentityChoices.edu_admin] = id_edu_admins

    profile.identities = identities
    profile.save()


def flush_courses(user):
    profile = user.profile

    courses = {}

    student_courses = []
    s_s = getattr(CourseStudentRelation, 'objects').filter(student__user=user).values('course_id').distinct()
    for course in s_s:
        student_courses.append(course['course_id'])
    teacher_courses = []
    t_s = getattr(CourseTeacherRelation, 'objects').filter(teacher__user=user).values('course_id').distinct()
    for course in t_s:
        teacher_courses.append(course['course_id'])
    teacher_course_groups = []
    t_g = getattr(CourseGroupTeacherRelation, 'objects').filter(teacher__user=user).values('group_id').distinct()
    for group in t_g:
        teacher_course_groups.append(group['group_id'])

    if student_courses:
        courses[IdentityChoices.student] = student_courses
    if teacher_courses:
        courses[IdentityChoices.teacher] = teacher_courses
    if teacher_course_groups:
        courses[IdentityChoices.teacher+'Groups'] = teacher_course_groups

    profile.courses = courses
    profile.save()
