# -*- encoding=utf-8 -*
from django.db import models
from django.contrib.auth.models import User
from django.contrib.postgres import fields as pg_fields


# -- Resources ------------------------------------------------------------------------------------

class Resource(models.Model):
    """
    资源
    """
    creator = models.CharField(max_length=150, null=True)
    create_time = models.DateTimeField(auto_now_add=True)
    updater = models.CharField(max_length=150, null=True)
    update_time = models.DateTimeField(auto_now=True)

    available = models.BooleanField(default=True)
    deleted = models.BooleanField(default=False)

    class Meta:
        abstract = True


# -- User -----------------------------------------------------------------------------------------

class IdentityChoices(object):
    root = 'ROOT'
    user_admin = 'USER_ADMIN'
    org_admin = 'ORG_ADMIN'
    edu_admin = 'EDU_ADMIN'
    teacher = 'TEACHER_ADMIN'
    student = 'STUDENT'

IDENTITY_CHOICES = (
    IdentityChoices.root,
    IdentityChoices.user_admin,
    IdentityChoices.org_admin,
    IdentityChoices.edu_admin,
    IdentityChoices.teacher,
    IdentityChoices.student
)

SITE_IDENTITY_CHOICES = (
    IdentityChoices.root,
    IdentityChoices.user_admin,
    IdentityChoices.org_admin
)


class UserProfile(Resource):
    """
    用户信息
    """
    SEX_CHOICES = ('MALE', 'FEMALE', 'SECRET')

    user = models.OneToOneField(User, related_name='profile', to_field='id', primary_key=True,
                                on_delete=models.CASCADE)
    username = models.CharField(max_length=150)

    # 所有人可见的信息
    name = models.CharField(max_length=150, null=True)
    sex = models.CharField(max_length=8, default='secret')

    phone = models.CharField(max_length=16, null=True)
    email = models.EmailField(max_length=128, null=True)

    github = models.CharField(max_length=128, null=True)
    qq = models.CharField(max_length=128, null=True)
    weixin = models.CharField(max_length=128, null=True)
    blog = models.CharField(max_length=128, null=True)

    introduction = models.TextField(max_length=256, null=True)
    last_login = models.DateTimeField(null=True)

    # 网站管理员可见的信息
    is_staff = models.BooleanField(default=False)       # 如果为True，则归于网站管理员之列，可访问管理页面
    ip = models.GenericIPAddressField(null=True)

    identities = pg_fields.JSONField(default={})        # 身份信息
    courses = pg_fields.JSONField(default={})           # 课程信息

    def get_site_identities(self):
        ret = []
        for k, v in self.identities.items():
            if v is True:
                ret.append(k)
        return ret

    def __str__(self):
        return '<UserProfile %s of User %s>' % (self.user, self.username)


class Student(Resource):
    """
    学生身份信息
    """
    IDENTITY_WORD = IdentityChoices.student

    id = models.BigAutoField(primary_key=True)

    user = models.ForeignKey(User, related_name='student_identities', to_field='id',
                             on_delete=models.CASCADE)
    username = models.CharField(max_length=150)
    profile = models.ForeignKey(UserProfile, related_name='student_identities', to_field='user',
                                on_delete=models.CASCADE)
    organization = models.ForeignKey('Organization', related_name='students', to_field='id',
                                     on_delete=models.CASCADE)

    name = models.CharField(max_length=150, null=True)
    sex = models.CharField(max_length=8, default='secret')

    phone = models.CharField(max_length=16, null=True)
    email = models.EmailField(max_length=128, null=True)

    student_id = models.CharField(max_length=32)
    grade = models.CharField(max_length=32, null=None)
    class_in = models.CharField(max_length=128, null=None)

    def __str__(self):
        return '<Student %s: %s %s>' % (self.id, self.student_id, self.name)


class Teacher(Resource):
    """
    教师身份信息
    """
    IDENTITY_WORD = IdentityChoices.teacher

    id = models.BigAutoField(primary_key=True)

    user = models.ForeignKey(User, related_name='teacher_identities', to_field='id',
                             on_delete=models.CASCADE)
    username = models.CharField(max_length=150)
    profile = models.ForeignKey(UserProfile, related_name='teacher_identities', to_field='user',
                                on_delete=models.CASCADE)
    organization = models.ForeignKey('Organization', related_name='teachers', to_field='id',
                                     on_delete=models.CASCADE)

    name = models.CharField(max_length=150, null=True)
    sex = models.CharField(max_length=8, default='secret')

    phone = models.CharField(max_length=16, null=True)
    email = models.EmailField(max_length=128, null=True)

    teacher_id = models.CharField(max_length=32)

    def __str__(self):
        return '<Teacher %s: %s %s>' % (self.id, self.teacher_id, self.name)


class EduAdmin(Resource):
    """
    教务管理员身份信息
    """
    IDENTITY_WORD = IdentityChoices.edu_admin

    id = models.BigAutoField(primary_key=True)

    user = models.ForeignKey(User, related_name='edu_admin_identities', to_field='id',
                             on_delete=models.CASCADE)
    username = models.CharField(max_length=150)
    profile = models.ForeignKey(UserProfile, related_name='edu_admin_identities', to_field='user',
                                on_delete=models.CASCADE)
    organization = models.ForeignKey('Organization', related_name='edu_admins', to_field='id',
                                     on_delete=models.CASCADE)

    name = models.CharField(max_length=150, null=True)
    sex = models.CharField(max_length=8, default='secret')

    phone = models.CharField(max_length=16, null=True)
    email = models.EmailField(max_length=128, null=True)


# -- Organization ---------------------------------------------------------------------------------

class Organization(Resource):
    """
    机构
    """
    id = models.BigAutoField(primary_key=True)

    name = models.CharField(max_length=150, unique=True)
    caption = models.CharField(max_length=150)
    introduction = models.TextField(max_length=1024, null=True)

    parent = models.ForeignKey('self', related_name='children', to_field='id', null=True,
                               on_delete=models.CASCADE)

    number_organizations = models.IntegerField(default=0)
    number_students = models.IntegerField(default=0)
    number_teachers = models.IntegerField(default=0)
    number_admins = models.IntegerField(default=0)

    number_course_meta = models.IntegerField(default=0)
    number_course_units = models.IntegerField(default=0)
    number_courses = models.IntegerField(default=0)
    number_course_groups = models.IntegerField(default=0)

    def __str__(self):
        return '<Organization %s: %s>' % (self.id, self.name)


# -- Course ---------------------------------------------------------------------------------------

class CourseMeta(Resource):
    """
    课程基类
    """
    organization = models.ForeignKey(Organization, related_name='course_meta', to_field='id')

    id = models.BigAutoField(primary_key=True)
    caption = models.CharField(max_length=150)

    number_courses = models.IntegerField(default=0)


class CourseUnit(models.Model):
    """
    课程单元，课程与课程组的基类
    """
    class TYPE:
        course_group = 'GROUP'
        course = 'COURSE'

    id = models.BigAutoField(primary_key=True)
    type = models.CharField(max_length=8)
    group = models.OneToOneField('CourseGroup', related_name='unit', to_field='id', null=True,
                                 on_delete=models.CASCADE)
    course = models.OneToOneField('Course', related_name='unit', to_field='id', null=True,
                                  on_delete=models.CASCADE)


class CourseGroup(Resource):
    """
    课程组，部分课程的集合，用于挂在公共的任务
    """
    id = models.BigAutoField(primary_key=True)
    organization = models.ForeignKey(Organization, related_name='course_groups', to_field='id')

    caption = models.CharField(max_length=150, null=True)
    courses = models.ManyToManyField('Course', related_name='groups', through='CourseGroupRelation',
                                     through_fields=('group', 'course'))

    teachers = models.ManyToManyField('Teacher', related_name='course_groups',
                                      through='CourseGroupTeacherRelation',
                                      through_fields=('group', 'teacher'))

    number_courses = models.IntegerField(default=0)


class Course(Resource):
    """
    课程
    """
    id = models.BigAutoField(primary_key=True)
    organization = models.ForeignKey(Organization, related_name='courses', to_field='id')

    meta = models.ForeignKey(CourseMeta, related_name='courses', to_field='id')
    caption = models.CharField(max_length=150)

    start_time = models.DateField()
    end_time = models.DateField()

    students = models.ManyToManyField(Student, related_name='courses',
                                      through='CourseStudentRelation',
                                      through_fields=('course', 'student'))
    teachers = models.ManyToManyField(Teacher, related_name='courses',
                                      through='CourseTeacherRelation',
                                      through_fields=('course', 'teacher'))

    def __str__(self):
        return '<Course %s: %s>' % (self.id, self.caption)


class CourseGroupRelation(Resource):
    """
    课程与课程组的多对多关系
    """
    id = models.BigAutoField(primary_key=True)

    organization = models.ForeignKey(Organization, related_name='course_group_relations', to_field='id')
    course = models.ForeignKey(Course, related_name='group_relations', to_field='id')
    group = models.ForeignKey(CourseGroup, related_name='course_relations', to_field='id')


class CourseTeacherRelation(Resource):
    """
    课程与老师的多对多关系
    """
    id = models.BigAutoField(primary_key=True)

    organization = models.ForeignKey(Organization, related_name='course_teacher_relations',
                                     to_field='id')
    course = models.ForeignKey(Course, related_name='teacher_relations', to_field='id')
    teacher = models.ForeignKey(Teacher, related_name='course_relations', to_field='id')


class CourseGroupTeacherRelation(Resource):
    """
    课程组与老师的多对多关系
    """
    id = models.BigAutoField(primary_key=True)

    organization = models.ForeignKey(Organization, related_name='course_group_teacher_relations',
                                     to_field='id')
    group = models.ForeignKey(CourseGroup, related_name='teacher_relations', to_field='id')
    teacher = models.ForeignKey(Teacher, related_name='course_group_relations', to_field='id')


class CourseStudentRelation(Resource):
    """
    课程与学生的多对多关系
    """
    id = models.BigAutoField(primary_key=True)

    organization = models.ForeignKey(Organization, related_name='course_student_relations', to_field='id')
    course = models.ForeignKey(Course, related_name='student_relations', to_field='id')
    student = models.ForeignKey(Student, related_name='course_relations', to_field='id')


# -- Mission --------------------------------------------------------------------------------------

class WorkGroup(Resource):
    """
    任务组
    """
    id = models.BigAutoField(primary_key=True)
    organization = models.ForeignKey(Organization, related_name='work_groups', to_field='id')
    unit = models.ForeignKey(CourseUnit, related_name='mission_groups', to_field='id')

    caption = models.CharField(max_length=256)
    info = models.TextField(max_length=1024, null=True)


class Work(Resource):
    """
    任务
    """
    class TYPE:
        work = 'WORK'
        experiment = 'EXPERIMENT'
        exam = 'EXAM'
    id = models.BigAutoField(primary_key=True)
    organization = models.ForeignKey(Organization, related_name='works', to_field='id')
    teacher = models.ForeignKey(Teacher, related_name='works', to_field='id')

    type = models.CharField(max_length=16, default='WORK')

    caption = models.CharField(max_length=256)
    info = models.TextField(max_length=1024, null=True)

    start_time = models.DateTimeField()             # 开始时间
    hide_time = models.DateTimeField()              # 封榜时间
    end_time = models.DateTimeField()               # 结束时间
    show_time = models.DateTimeField()              # 显示榜的时间

    result_delay = models.IntegerField(default=0)   # 提交记录显示结果延迟的时间(分钟)


class WorkGroupRelation(Resource):
    id = models.BigAutoField(primary_key=True)
    organization = models.ForeignKey(Organization, related_name='work_group_relations',
                                     to_field='id', on_delete=models.CASCADE)

    work = models.ForeignKey(WorkGroup, related_name='group_relations', to_field='id',
                             on_delete=models.CASCADE)
    group = models.ForeignKey(WorkGroup, related_name='work_relations', to_field='id',
                              on_delete=models.CASCADE)
