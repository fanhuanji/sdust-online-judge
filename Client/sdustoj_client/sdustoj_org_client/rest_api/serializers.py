# -*- encoding=utf-8 -*
from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.core.validators import RegexValidator
from . import models


class Utils(object):
    @staticmethod
    def create_user_profile(**kwargs):
        creator = kwargs.get('creator', None)
        updater = kwargs.get('updater', None)

        # 创建用户
        username = kwargs['username']
        password = kwargs['password']
        active = kwargs.get('available', True)

        user = models.User(username=username, is_active=active)
        user.set_password(password)
        user.save()

        # 创建用户信息
        name = kwargs.get('name', None)
        sex = kwargs.get('sex', 'SECRET')
        phone = kwargs.get('phone', None)
        email = kwargs.get('email', None)
        github = kwargs.get('github', None)
        qq = kwargs.get('qq', None)
        weixin = kwargs.get('weixin', None)
        blog = kwargs.get('blog', None)
        introduction = kwargs.get('introduction', None)

        profile = models.UserProfile(user=user, username=username,
                                     name=name, sex=sex,
                                     phone=phone, email=email, github=github, qq=qq, weixin=weixin, blog=blog,
                                     introduction=introduction,
                                     is_staff=False,
                                     creator=creator, updater=updater)
        profile.save()

        return user, profile


class UserSerializers(object):
    """
    与用户管理相关的Serializer。
    """
    class Utils(object):
        """
        用于验证用户参数合法性的方法的集合。
        """
        @staticmethod
        def validate_username(value):
            """
            验证是否已存在相同用户名的用户。
            :param value: 用户名，传入前必已通过DRF合法性验证。
            :return: 传入的value。
            """
            if User.objects.filter(username=value).exists():
                raise serializers.ValidationError('User exists.')
            return value

        @staticmethod
        def validate_password(value):
            """
            用于验证传入的密码是否不为空。
            :param value: 密码，传入前必已通过DRF默认的合法性检查。
            :return:传入的value。
            """
            if value is None or value == '':
                raise serializers.ValidationError('Password can not be empty.')
            return value

        @staticmethod
        def validate_old_password(serializer, instance, value):
            """
            修改密码时检查旧密码是否正确以及新密码是否不为空。
            :param serializer: 需要修改用户信息的Serializer。
            :param instance: 需要修改的用户实例。
            :param value: 旧密码。
            :return: 传入的value本身。
            """
            if value is not None:
                user = instance.user
                u = authenticate(username=instance.username, password=value)
                if u is not None:
                    if not user.is_active:
                        raise serializers.ValidationError('User disabled.')
                else:
                    raise serializers.ValidationError('Password incorrect.')

                new_password = serializer.initial_data.get('new_password', None)
                if new_password is None or new_password == '':
                    raise serializers.ValidationError('New password cannot be None.')

            return value

        @staticmethod
        def validate_sex(value):
            """
            验证性别值是否合法。
            规则：
                性别仅可为"male"，"female"或"secret"。
            :param value: 性别值，字符串。
            :return: 传入的value。
            """
            if value is not None and value not in models.UserProfile.SEX_CHOICES:
                raise serializers.ValidationError(
                    'Sex can only be "MALE", "FEMALE" or "SECRET".'
                )
            return value

    class Admin(object):
        """
        网站管理员的Serializer。
        """
        class ListAdmin(serializers.ModelSerializer):
            password = serializers.CharField(max_length=128, write_only=True)
            identities = serializers.ListField(child=serializers.CharField(),
                                               source='get_site_identities',
                                               allow_null=True,
                                               allow_empty=True)

            @staticmethod
            def validate_username(value):
                return UserSerializers.Utils.validate_username(value)

            @staticmethod
            def validate_password(value):
                return UserSerializers.Utils.validate_password(value)

            @staticmethod
            def validate_sex(value):
                return UserSerializers.Utils.validate_sex(value)

            @staticmethod
            def validate_identities(value):
                for it in value:
                    if it == models.IdentityChoices.root:
                        raise serializers.ValidationError('You have no permission to create root')
                    if it == models.IdentityChoices.user_admin:
                        raise serializers.ValidationError('You have no permission to create user administrator')
                return value

            class Meta:
                model = models.UserProfile
                exclude = ('user', 'is_staff', )
                read_only_fields = (
                    'last_login', 'ip',
                    'creator', 'create_time', 'updater', 'update_time'
                )

            def create(self, validated_data):
                u = validated_data.get('username')
                p = validated_data.pop('password')
                active = validated_data.get('available', False)
                identities = validated_data.pop('get_site_identities', [])

                id_ret = dict()
                for id_str in identities:
                    if id_str in models.SITE_IDENTITY_CHOICES:
                        id_ret[id_str] = True
                validated_data['identities'] = id_ret
                validated_data['is_staff'] = True

                user = User(username=u)
                user.set_password(p)
                user.is_active = active
                user.save()
                validated_data['user'] = user

                return super().create(validated_data)

        class ListRoot(ListAdmin):
            def __init__(self, instance=None, data=serializers.empty, **kwargs):
                super().__init__(instance=instance, data=data, **kwargs)

            @staticmethod
            def validate_identities(value):
                return value

            class Meta:
                model = models.UserProfile
                exclude = ('user', 'is_staff', )
                read_only_fields = (
                    'last_login', 'ip',
                    'creator', 'create_time', 'updater', 'update_time'
                )

        class InstanceAdmin(serializers.ModelSerializer):
            password = serializers.CharField(max_length=128, write_only=True)
            identities = serializers.ListField(child=serializers.CharField(),
                                               source='get_site_identities',
                                               allow_null=True,
                                               allow_empty=True)

            @staticmethod
            def validate_password(value):
                return UserSerializers.Utils.validate_password(value)

            @staticmethod
            def validate_sex(value):
                return UserSerializers.Utils.validate_sex(value)

            def validate_identities(self, value):
                instance = self.instance
                if models.IdentityChoices.root in instance.identities \
                        or models.IdentityChoices.user_admin in instance.identities:
                    raise serializers.ValidationError(
                        'You have no permission to change identity or root or user administrator'
                    )
                for it in value:
                    if it == models.IdentityChoices.root:
                        raise serializers.ValidationError('You have no permission to promote a user to root')
                    if it == models.IdentityChoices.user_admin:
                        raise serializers.ValidationError('You have no permission to '
                                                          'promote a user to user administrator')
                return value

            class Meta:
                model = models.UserProfile
                exclude = ('user', 'is_staff', )
                read_only_fields = (
                    'username', 'last_login', 'ip',
                    'creator', 'create_time', 'updater', 'update_time'
                )

            def update(self, instance, validated_data):
                pwd = validated_data.pop('password', None)
                if pwd is not None:
                    instance.user.set_password(pwd)
                active = validated_data.pop('available', None)
                if active is not None:
                    instance.user.is_active = active
                instance.user.save()

                identities = validated_data.pop('get_site_identities', False)
                if identities is not False:
                    id_ret = {}
                    # 处理全局身份
                    if identities is None:
                        identities = []
                    for id_str in identities:
                        if id_str in models.SITE_IDENTITY_CHOICES:
                            id_ret[id_str] = True
                    # 处理机构相关身份
                    former_identities = instance.identities
                    if models.Student.IDENTITY_WORD in former_identities:
                        id_ret[models.Student.IDENTITY_WORD] = former_identities[models.Student.IDENTITY_WORD]
                    if models.Teacher.IDENTITY_WORD in former_identities:
                        id_ret[models.Teacher.IDENTITY_WORD] = former_identities[models.Teacher.IDENTITY_WORD]
                    if models.EduAdmin.IDENTITY_WORD in former_identities:
                        id_ret[models.EduAdmin.IDENTITY_WORD] = former_identities[models.EduAdmin.IDENTITY_WORD]
                    validated_data['identities'] = id_ret

                return super().update(instance, validated_data)

        class InstanceRoot(InstanceAdmin):
            def __init__(self, instance=None, data=serializers.empty, **kwargs):
                super().__init__(instance=instance, data=data, **kwargs)

            def validate_identities(self, value):
                return value

            class Meta:
                model = models.UserProfile
                exclude = ('user', )
                read_only_fields = (
                    'username', 'last_login', 'ip',
                    'creator', 'create_time', 'updater', 'update_time'
                )

    class User(object):
        """
        用户的相关serializer。
        """
        class ListAdmin(serializers.ModelSerializer):
            password = serializers.CharField(max_length=128, write_only=True)
            identities = serializers.ListField(child=serializers.CharField(),
                                               source='get_site_identities',
                                               allow_null=True,
                                               allow_empty=True)

            @staticmethod
            def validate_username(value):
                return UserSerializers.Utils.validate_username(value)

            @staticmethod
            def validate_password(value):
                return UserSerializers.Utils.validate_password(value)

            @staticmethod
            def validate_sex(value):
                return UserSerializers.Utils.validate_sex(value)

            @staticmethod
            def validate_identities(value):
                for it in value:
                    if it == models.IdentityChoices.root:
                        raise serializers.ValidationError('You have no permission to create root')
                    if it == models.IdentityChoices.user_admin:
                        raise serializers.ValidationError('You have no permission to create user administrator')
                return value

            class Meta:
                model = models.UserProfile
                exclude = ('user', )
                read_only_fields = (
                    'last_login', 'ip',
                    'creator', 'create_time', 'updater', 'update_time'
                )

            def create(self, validated_data):
                u = validated_data.get('username')
                p = validated_data.pop('password')
                active = validated_data.get('available', False)
                identities = validated_data.pop('get_site_identities', [])

                id_ret = dict()
                for id_str in identities:
                    if id_str in models.SITE_IDENTITY_CHOICES:
                        id_ret[id_str] = True
                validated_data['identities'] = id_ret
                validated_data['is_staff'] = True

                user = User(username=u)
                user.set_password(p)
                user.is_active = active
                user.save()
                validated_data['user'] = user

                return super().create(validated_data)

        class ListRoot(ListAdmin):
            def __init__(self, instance=None, data=serializers.empty, **kwargs):
                super().__init__(instance=instance, data=data, **kwargs)

            @staticmethod
            def validate_identities(value):
                return value

            class Meta:
                model = models.UserProfile
                exclude = ('user',)
                read_only_fields = (
                    'last_login', 'ip',
                    'creator', 'create_time', 'updater', 'update_time'
                )

        class InstanceAdmin(serializers.ModelSerializer):
            password = serializers.CharField(max_length=128, write_only=True)
            identities = serializers.ListField(child=serializers.CharField(),
                                               source='get_site_identities',
                                               allow_null=True,
                                               allow_empty=True)

            @staticmethod
            def validate_password(value):
                return UserSerializers.Utils.validate_password(value)

            @staticmethod
            def validate_sex(value):
                return UserSerializers.Utils.validate_sex(value)

            def validate_identities(self, value):
                instance = self.instance
                if models.IdentityChoices.root in instance.identities \
                        or models.IdentityChoices.user_admin in instance.identities:
                    raise serializers.ValidationError(
                        'You have no permission to change identity or root or user administrator'
                    )
                for it in value:
                    if it == models.IdentityChoices.root:
                        raise serializers.ValidationError('You have no permission to promote a user to root')
                    if it == models.IdentityChoices.user_admin:
                        raise serializers.ValidationError('You have no permission to '
                                                          'promote a user to user administrator')
                return value

            class Meta:
                model = models.UserProfile
                exclude = ('user', 'is_staff', )
                read_only_fields = (
                    'username', 'last_login', 'ip',
                    'creator', 'create_time', 'updater', 'update_time'
                )

            def update(self, instance, validated_data):
                pwd = validated_data.pop('password', None)
                if pwd is not None:
                    instance.user.set_password(pwd)
                active = validated_data.pop('available', None)
                if active is not None:
                    instance.user.is_active = active
                instance.user.save()

                identities = validated_data.pop('get_site_identities', False)
                if identities is not False:
                    id_ret = {}
                    # 处理全局身份
                    if identities is None:
                        identities = []
                    for id_str in identities:
                        if id_str in models.SITE_IDENTITY_CHOICES:
                            id_ret[id_str] = True
                    # 处理机构相关身份
                    former_identities = instance.identities
                    if models.Student.IDENTITY_WORD in former_identities:
                        id_ret[models.Student.IDENTITY_WORD] = former_identities[models.Student.IDENTITY_WORD]
                    if models.Teacher.IDENTITY_WORD in former_identities:
                        id_ret[models.Teacher.IDENTITY_WORD] = former_identities[models.Teacher.IDENTITY_WORD]
                    if models.EduAdmin.IDENTITY_WORD in former_identities:
                        id_ret[models.EduAdmin.IDENTITY_WORD] = former_identities[models.EduAdmin.IDENTITY_WORD]
                    validated_data['identities'] = id_ret

                return super().update(instance, validated_data)

        class InstanceRoot(InstanceAdmin):
            def __init__(self, instance=None, data=serializers.empty, **kwargs):
                super().__init__(instance=instance, data=data, **kwargs)

            def validate_identities(self, value):
                return value

            class Meta:
                model = models.UserProfile
                exclude = ('user', )
                read_only_fields = (
                    'username', 'last_login', 'ip',
                    'creator', 'create_time', 'updater', 'update_time'
                )

    class Self(object):
        """
        用户对自己操作的相关Serializer。
        """
        class Instance(serializers.ModelSerializer):
            old_password = serializers.CharField(max_length=128, write_only=True, required=False)
            new_password = serializers.CharField(max_length=128, write_only=True, required=False)

            class Meta:
                model = models.UserProfile
                exclude = ('user', )
                read_only_fields = (
                    'username', 'last_login', 'ip',
                    'org_identities', 'identities',
                    'creator', 'create_time', 'updater', 'update_time'
                )

            @staticmethod
            def validate_sex(value):
                return UserSerializers.Utils.validate_sex(value)

            def validate_old_password(self, value):
                return UserSerializers.Utils.validate_old_password(self, self.instance, value)

            @staticmethod
            def validate_new_password(value):
                if value is None or value == '':
                    raise serializers.ValidationError('Password can not be empty')
                return value

            def update(self, instance, validated_data):
                old_pwd = validated_data.pop('old_password', None)
                new_pwd = validated_data.pop('new_password', None)
                user = instance.user
                if old_pwd is not None:
                    user.set_password(new_pwd)
                    user.save()
                validated_data['updater'] = user.username
                return super().update(instance, validated_data)

    class Login(serializers.ModelSerializer):
        class Meta:
            model = User
            fields = ('username', 'password')
            extra_kwargs = {
                'username': {'write_only': True,
                             'validators': [RegexValidator()]},
                'password': {'write_only': True,
                             'style': {'input_type': 'password'}}
            }


class OrgSerializers(object):
    """
    与机构管理相关的Serializer。
    """
    class Organization(object):
        class ListAdmin(serializers.ModelSerializer):
            @staticmethod
            def validate_parent(value):
                root = getattr(models.Organization, 'objects').get(name='ROOT')

                checked = set()
                cur = value

                while cur is not None and cur.id not in checked:
                    if cur.id == root.id:
                        return value
                    checked.add(cur.id)
                    cur = cur.parent

                raise serializers.ValidationError('Organization unreachable.')

            class Meta:
                model = models.Organization
                fields = '__all__'
                read_only_fields = (
                    'number_organizations', 'number_students', 'number_teachers', 'number_admins',
                    'number_course_meta', 'number_course_units', 'number_courses', 'number_course_groups',
                    'creator', 'create_time', 'updater', 'update_time'
                )
                extra_kwargs = {
                    'parent': {'allow_null': False, 'required': True}
                }

        class ListEdu(serializers.ModelSerializer):
            class Meta:
                model = models.Organization
                exclude = ('creator', 'updater', 'available', 'deleted', )
                read_only_fields = (
                    'create_time', 'update_time',
                    'number_organizations', 'number_students', 'number_teachers', 'number_admins',
                    'number_course_meta', 'number_course_units', 'number_courses', 'number_course_groups',
                )

        class List(serializers.ModelSerializer):
            class Meta:
                model = models.Organization
                exclude = ('creator', 'updater', 'available', 'deleted', )
                read_only_fields = (
                    'create_time', 'update_time',
                    'number_organizations', 'number_students', 'number_teachers', 'number_admins',
                    'number_course_meta', 'number_course_units', 'number_courses', 'number_course_groups',
                )

        class InstanceAdmin(serializers.ModelSerializer):
            def validate_parent(self, value):
                root = getattr(models.Organization, 'objects').get(name='ROOT')

                checked = set()
                cur = value
                checked.add(self.instance.id)

                while cur is not None and cur.id not in checked:
                    if cur.id == root.id:
                        return value
                    checked.add(cur.id)
                    cur = cur.parent

                raise serializers.ValidationError('Organization unreachable.')

            class Meta:
                model = models.Organization
                fields = '__all__'
                read_only_fields = (
                    'number_organizations', 'number_students', 'number_teachers', 'number_admins',
                    'number_course_meta', 'number_course_units', 'number_courses', 'number_course_groups',
                    'creator', 'create_time', 'updater', 'update_time'
                )
                extra_kwargs = {
                    'parent': {'allow_null': False, 'required': True}
                }

        class InstanceEdu(serializers.ModelSerializer):
            class Meta:
                model = models.Organization
                exclude = ('creator', 'updater', 'available', 'deleted', )
                read_only_fields = (
                    'creator', 'updater',
                    'number_organizations', 'number_students', 'number_teachers', 'number_admins',
                    'number_course_meta', 'number_course_units', 'number_courses', 'number_course_groups',
                )
                extra_kwargs = {
                    'parent': {'allow_null': False, 'required': True}
                }

        class Instance(serializers.ModelSerializer):
            class Meta:
                model = models.Organization
                exclude = ('creator', 'updater', 'available', 'deleted', )
                read_only_fields = (
                    'create_time', 'update_time',
                    'number_organizations', 'number_students', 'number_teachers', 'number_admins',
                    'number_course_meta', 'number_course_units', 'number_courses', 'number_course_groups',
                )

    class EduAdmin(object):
        class ListAdmin(serializers.ModelSerializer):
            password = serializers.CharField(max_length=128, write_only=True)

            @staticmethod
            def validate_username(value):
                return UserSerializers.Utils.validate_username(value)

            @staticmethod
            def validate_password(value):
                return UserSerializers.Utils.validate_password(value)

            class Meta:
                model = models.EduAdmin
                exclude = ('organization', 'user', 'profile')
                read_only_fields = ('creator', 'create_time', 'updater', 'update_time')

            def create(self, validated_data):
                u = validated_data.get('username')
                p = validated_data.pop('password')
                active = validated_data.get('available', False)
                name = validated_data.get('name', None)
                sex = validated_data.get('sex', 'SECRET')
                phone = validated_data.get('phone', None)
                email = validated_data.get('email', None)
                creator = validated_data.get('creator', None)
                updater = validated_data.get('updater', None)

                user, profile = Utils.create_user_profile(
                    username=u, password=p, available=active,
                    name=name, sex=sex, phone=phone, email=email,
                    creator=creator, updater=updater
                )

                organization = validated_data.get('organization')
                profile.identities = {models.IdentityChoices.edu_admin: [organization.id]}
                profile.save()

                edu_admin = models.EduAdmin(user=user, username=u, profile=profile, organization=organization,
                                            name=name, sex=sex, phone=phone, email=email,
                                            creator=creator, updater=updater)
                edu_admin.save()
                return edu_admin

        class InstanceAdmin(serializers.ModelSerializer):
            password = serializers.CharField(max_length=128, write_only=True)

            @staticmethod
            def validate_password(value):
                return UserSerializers.Utils.validate_password(value)

            class Meta:
                model = models.EduAdmin
                exclude = ('organization', 'user', 'profile')
                read_only_fields = ('username',
                                    'creator', 'create_time', 'updater', 'update_time')

            def update(self, instance, validated_data):
                if 'password' in validated_data:
                    instance.user.set_password(validated_data['password'])
                    instance.user.save()
                if 'available' in validated_data:
                    instance.available = validated_data['available']
                if 'name' in validated_data:
                    instance.name = validated_data['name']
                if 'sex' in validated_data:
                    instance.sex = validated_data['sex']
                if 'phone' in validated_data:
                    instance.phone = validated_data['phone']
                if 'email' in validated_data:
                    instance.email = validated_data['email']
                instance.save()

                return instance

    class Teacher(object):
        class ListAdmin(serializers.ModelSerializer):
            password = serializers.CharField(max_length=128, write_only=True)

            @staticmethod
            def validate_username(value):
                return UserSerializers.Utils.validate_username(value)

            @staticmethod
            def validate_password(value):
                return UserSerializers.Utils.validate_password(value)

            class Meta:
                model = models.Teacher
                exclude = ('organization', 'user', 'profile')
                read_only_fields = ('creator', 'create_time', 'updater', 'update_time')

            def create(self, validated_data):
                u = validated_data.get('username')
                p = validated_data.pop('password')
                active = validated_data.get('available', False)
                name = validated_data.get('name', None)
                sex = validated_data.get('sex', 'SECRET')
                phone = validated_data.get('phone', None)
                email = validated_data.get('email', None)
                creator = validated_data.get('creator', None)
                updater = validated_data.get('updater', None)
                teacher_id = validated_data.get('teacher_id', '')

                user, profile = Utils.create_user_profile(
                    username=u, password=p, available=active,
                    name=name, sex=sex, phone=phone, email=email,
                    creator=creator, updater=updater
                )

                organization = validated_data.get('organization')
                profile.identities = {models.IdentityChoices.teacher: [organization.id]}
                profile.save()

                teacher = models.Teacher(user=user, username=u, profile=profile, organization=organization,
                                         name=name, sex=sex, phone=phone, email=email,
                                         creator=creator, updater=updater,
                                         teacher_id=teacher_id)
                teacher.save()
                return teacher

        class InstanceAdmin(serializers.ModelSerializer):
            password = serializers.CharField(max_length=128, write_only=True)

            @staticmethod
            def validate_password(value):
                return UserSerializers.Utils.validate_password(value)

            class Meta:
                model = models.Teacher
                exclude = ('organization', 'user', 'profile')
                read_only_fields = ('username',
                                    'creator', 'create_time', 'updater', 'update_time')

            def update(self, instance, validated_data):
                if 'password' in validated_data:
                    instance.user.set_password(validated_data['password'])
                    instance.user.save()
                if 'available' in validated_data:
                    instance.available = validated_data['available']
                if 'name' in validated_data:
                    instance.name = validated_data['name']
                if 'sex' in validated_data:
                    instance.sex = validated_data['sex']
                if 'phone' in validated_data:
                    instance.phone = validated_data['phone']
                if 'email' in validated_data:
                    instance.email = validated_data['email']
                if 'teacher_id' in validated_data:
                    instance.teacher_id = validated_data['teacher_id']
                instance.save()

                return instance

    class Student(object):
        class ListAdmin(serializers.ModelSerializer):
            password = serializers.CharField(max_length=128, write_only=True)

            @staticmethod
            def validate_username(value):
                return UserSerializers.Utils.validate_username(value)

            @staticmethod
            def validate_password(value):
                return UserSerializers.Utils.validate_password(value)

            class Meta:
                model = models.Student
                exclude = ('organization', 'user', 'profile')
                read_only_fields = ('creator', 'create_time', 'updater', 'update_time', )

            def create(self, validated_data):
                u = validated_data.get('username')
                p = validated_data.pop('password')
                active = validated_data.get('available', False)
                name = validated_data.get('name', None)
                sex = validated_data.get('sex', 'SECRET')
                phone = validated_data.get('phone', None)
                email = validated_data.get('email', None)
                creator = validated_data.get('creator', None)
                updater = validated_data.get('updater', None)
                student_id = validated_data.get('student_id', '')
                grade = validated_data.get('grade', None)
                class_in = validated_data.get('class_in', None)

                user, profile = Utils.create_user_profile(
                    username=u, password=p, available=active,
                    name=name, sex=sex, phone=phone, email=email,
                    creator=creator, updater=updater
                )

                organization = validated_data.get('organization')
                profile.identities = {models.IdentityChoices.student: [organization.id]}
                profile.save()

                student = models.Student(user=user, username=u, profile=profile, organization=organization,
                                         name=name, sex=sex, phone=phone, email=email,
                                         creator=creator, updater=updater,
                                         student_id=student_id, grade=grade, class_in=class_in)
                student.save()
                return student

        class InstanceAdmin(serializers.ModelSerializer):
            password = serializers.CharField(max_length=128, write_only=True)

            @staticmethod
            def validate_password(value):
                return UserSerializers.Utils.validate_password(value)

            class Meta:
                model = models.Student
                exclude = ('organization', 'user', 'profile')
                read_only_fields = ('username',
                                    'creator', 'create_time', 'updater', 'update_time')

            def update(self, instance, validated_data):
                if 'password' in validated_data:
                    instance.user.set_password(validated_data['password'])
                    instance.user.save()
                if 'available' in validated_data:
                    instance.available = validated_data['available']
                if 'name' in validated_data:
                    instance.name = validated_data['name']
                if 'sex' in validated_data:
                    instance.sex = validated_data['sex']
                if 'phone' in validated_data:
                    instance.phone = validated_data['phone']
                if 'email' in validated_data:
                    instance.email = validated_data['email']
                if 'student_id' in validated_data:
                    instance.student_id = validated_data['student_id']
                if 'grade' in validated_data:
                    instance.grade = validated_data['grade']
                if 'class_in' in validated_data:
                    instance.class_in = validated_data['class_in']
                instance.save()

                return instance


class CourseSerializers(object):
    """
    与机构管理相关的Serializer
    """
    class CourseMeta(object):
        class CourseMetaAdmin(serializers.ModelSerializer):
            class Meta:
                model = models.CourseMeta
                exclude = ('organization', )
                read_only_fields = ('id', 'number_courses',
                                    'creator', 'create_time', 'updater', 'update_time')

    class Course(object):
        class CourseAdmin(serializers.ModelSerializer):
            class Meta:
                model = models.Course
                exclude = ('organization',)
                read_only_fields = ('id', 'meta',
                                    'creator', 'create_time', 'updater', 'update_time')

    class CourseGroup(object):
        class CourseGroupAdmin(serializers.ModelSerializer):
            class Meta:
                model = models.CourseGroup
                exclude = ('organization', 'courses')
                read_only_fields = ('id', 'meta', 'number_courses',
                                    'creator', 'create_time', 'updater', 'update_time')

        class CourseRelationAdmin(serializers.ModelSerializer):
            class Meta:
                model = models.CourseGroupRelation
                exclude = ('organization', 'group')
                read_only_fields = ('id', 'creator', 'create_time', 'updater', 'update_time')

            def create(self, validated_data):
                group = validated_data['group']
                course = validated_data['course']
                if getattr(models.CourseGroupRelation, 'objects').filter(
                    group=group, course=course
                ).exists():
                    info = {"course": ["Course exists."]}
                    raise serializers.ValidationError(info)
                return super().create(validated_data)
