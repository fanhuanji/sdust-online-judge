from django.shortcuts import render, redirect, reverse
from rest_api.models import IdentityChoices


class Utils(object):
    class UserInfo(object):
        @staticmethod
        def basic(request):
            user = request.user
            if user.is_authenticated():
                profile = user.profile
                info = {
                    'is_authenticated': True,
                    'name': profile.name if profile.name else profile.username,
                    'user': profile,
                    'identities': profile.identities
                }
            else:
                info = {
                    'is_authenticated': False
                }
            return info

    class Render(object):
        @staticmethod
        def _has_site_identity(identities, id_str):
            """
            判断用户是否具备指定的全局身份。
            :param identities: 用户身份的JSON数据。
            :param id_str: 身份字符串集合或列表。
            :return: 只要identities中具备id_str中任意一个身份，即返回True；否则返回False。
            """
            for it in id_str:
                if it in identities and identities[it] is not False:
                    return True
            return False

        @staticmethod
        def _has_org_identity(identities, id_tuple):
            """
            判断用户是否具备指定的机构相关身份。
            :param identities: 用户身份的JSON数据。
            :param id_tuple: 身份信息的集合或列表。元素参见_identity_render机构相关身份元素的说明。
            :return: 只要identities中具备id_tuple中任意一个身份，即返回True；否则返回False。
            """
            for it in id_tuple:
                if it[0] in identities:
                    identity = identities[it[0]]
                    if not isinstance(identity, str) and it[1] in identity:
                        return True
            return False

        @staticmethod
        def _identity_render(request, template, id_expect, context=None):
            """
            附带用户身份检测的页面生成。
            :param request: http请求。
            :param template: 使用的模板文件。
            :param id_expect: 身份列表，即哪些身份的用户可以访问.
                              如果所有人均可访问，设置为'*'；否则为列表，列表中元素为身份，类型如下：
                                - 如果身份为全局身份，则为表示身份的字符串。
                                - 如果身份与机构相关，则为(身份字符串, 机构ID)形式的元组。
                                - 如果身份与机构相关，但任一机构均可，则为(身份字符串, None)形式的字符串。
            :param context: 需要额外传递给模板的数据。
            :return: 不要管……
            """
            user_info = Utils.UserInfo.basic(request)
            # 如果没有登录，跳转到登录页面
            if not user_info['is_authenticated']:
                return redirect(reverse('web-login'))
            # 如果用户不具备指定的权限，跳转到首页
            if id_expect != '*':
                identities = user_info['identities']
                site_identities_expect = []
                org_identities_expect = []
                for identity in id_expect:
                    if isinstance(identity, str):
                        site_identities_expect.append(identity)
                    else:
                        org_identities_expect.append(identity)
                if not (Utils.Render._has_site_identity(identities, site_identities_expect)
                        or Utils.Render._has_org_identity(identities, org_identities_expect)):
                    return redirect(reverse('web-home'))

            _context = context if context is not None else dict()
            _context['user_info'] = user_info

            return render(request, template, _context)

        @staticmethod
        def all_user(request, template, context=None):
            return Utils.Render._identity_render(
                request=request,
                template=template,
                id_expect='*',
                context=context
            )

        @staticmethod
        def root(request, template, context=None):
            return Utils.Render._identity_render(
                request=request,
                template=template,
                id_expect=(IdentityChoices.root, ),
                context=context
            )

        @staticmethod
        def user_admin(request, template, context=None):
            return Utils.Render._identity_render(
                request=request,
                template=template,
                id_expect=(IdentityChoices.user_admin, IdentityChoices.root),
                context=context
            )

        @staticmethod
        def org_admin(request, template, context=None):
            return Utils.Render._identity_render(
                request=request,
                template=template,
                id_expect=(IdentityChoices.org_admin, IdentityChoices.root),
                context=context
            )

        @staticmethod
        def edu_admin(request, template, context=None):
            print(12312312)
            return Utils.Render._identity_render(
                request=request,
                template=template,
                id_expect=(IdentityChoices.edu_admin, IdentityChoices.org_admin, IdentityChoices.root),
                context=context
            )

        @staticmethod
        def edu_admin_org(request, oid, template, context=None):
            return Utils.Render._identity_render(
                request=request,
                template=template,
                id_expect=(
                    (IdentityChoices.edu_admin, int(oid)),
                    IdentityChoices.org_admin,
                    IdentityChoices.root
                ),
                context=context
            )


class MainPages(object):
    """
    基本页面
    """
    @staticmethod
    def home(request):
        """
        首页
        """
        return render(request, 'homepage.html', {
            'user_info': Utils.UserInfo.basic(request)
        })

    @staticmethod
    def to_home(request):
        """
        跳转到首页
        """
        if request:
            pass
        return redirect(reverse('web-home'))

    @staticmethod
    def login(request):
        """
        登录页面
        """
        if request.user.is_authenticated():
            return redirect(reverse('web-home'))
        return render(request, 'login.html')


class OrgPages(object):
    class Organization(object):
        @staticmethod
        def list(request):
            return Utils.Render.edu_admin(request, 'organization/list.html')

        @staticmethod
        def create(request):
            return Utils.Render.org_admin(request, 'organization/create.html')

        @staticmethod
        def instance(request, oid):
            return Utils.Render.edu_admin_org(request, oid, 'organization/instance.html', {
                'oid': oid
            })

    class MyOrganization(object):
        @staticmethod
        def list(request):
            return Utils.Render.all_user(request, 'myOrg/list.html')

        @staticmethod
        def instance(request, oid):
            return Utils.Render.all_user(request, 'myOrg/instance.html', {
                'oid': oid
            })

    class EduAdmin(object):
        @staticmethod
        def list(request, oid):
            return Utils.Render.edu_admin_org(request, oid, 'organization/eduAdmin/list.html', {
                'oid': oid
            })

        @staticmethod
        def create(request, oid):
            return Utils.Render.org_admin(request, 'organization/eduAdmin/create.html', {
                'oid': oid
            })

        @staticmethod
        def instance(request, oid, eid):
            return Utils.Render.edu_admin_org(request, oid, 'organization/eduAdmin/instance.html', {
                'oid': oid,
                'eid': eid
            })

    class Teacher(object):
        @staticmethod
        def list(request, oid):
            return Utils.Render.edu_admin_org(request, oid, 'organization/teacher/list.html', {
                'oid': oid
            })

        @staticmethod
        def create(request, oid):
            return Utils.Render.edu_admin_org(request, oid, 'organization/teacher/create.html', {
                'oid': oid
            })

        @staticmethod
        def instance(request, oid, eid):
            return Utils.Render.edu_admin_org(request, oid, 'organization/teacher/instance.html', {
                'oid': oid,
                'eid': eid
            })

    class Student(object):
        @staticmethod
        def list(request, oid):
            return Utils.Render.edu_admin_org(request, oid, 'organization/student/list.html', {
                'oid': oid
            })

        @staticmethod
        def create(request, oid):
            return Utils.Render.edu_admin_org(request, oid, 'organization/student/create.html', {
                'oid': oid
            })

        @staticmethod
        def instance(request, oid, eid):
            return Utils.Render.edu_admin_org(request, oid, 'organization/student/instance.html', {
                'oid': oid,
                'eid': eid
            })


class CoursePages(object):
    class CourseMeta(object):
        @staticmethod
        def list(request, oid):
            return Utils.Render.edu_admin_org(request, oid, 'organization/courseMeta/list.html', {
                'oid': oid
            })

        @staticmethod
        def create(request, oid):
            return Utils.Render.edu_admin_org(request, oid, 'organization/courseMeta/create.html', {
                'oid': oid
            })

        @staticmethod
        def instance(request, oid, mid):
            return Utils.Render.edu_admin_org(request, oid, 'organization/courseMeta/instance.html', {
                'oid': oid,
                'mid': mid
            })

    class CourseGroup(object):
        @staticmethod
        def list(request, oid):
            return Utils.Render.edu_admin_org(request, oid, 'organization/courseGroup/list.html', {
                'oid': oid
            })

        @staticmethod
        def create(request, oid):
            return Utils.Render.edu_admin_org(request, oid, 'organization/courseGroup/create.html', {
                'oid': oid
            })

        @staticmethod
        def instance(request, oid, gid):
            return Utils.Render.edu_admin_org(request, oid, 'organization/courseGroup/instance.html', {
                'oid': oid,
                'gid': gid
            })

    class Course(object):
        @staticmethod
        def list(request, oid, mid):
            return Utils.Render.edu_admin_org(request, oid, 'organization/courseMeta/course/list.html', {
                'oid': oid,
                'mid': mid,
            })

        @staticmethod
        def create(request, oid, mid):
            return Utils.Render.edu_admin_org(request, oid, 'organization/courseMeta/course/create.html', {
                'oid': oid,
                'mid': mid
            })

        @staticmethod
        def instance(request, oid, mid, cid):
            return Utils.Render.edu_admin_org(request, oid, 'organization/courseMeta/course/instance.html', {
                'oid': oid,
                'mid': mid,
                'cid': cid
            })

    class CourseReadonly(object):
        @staticmethod
        def list(request, oid):
            return Utils.Render.edu_admin_org(request, oid, 'organization/course/list.html', {
                'oid': oid
            })

        @staticmethod
        def instance(request, oid, cid):
            return Utils.Render.edu_admin_org(request, oid, 'organization/course/instance.html', {
                'oid': oid,
                'cid': cid
            })


    class CourseGroupRelation(object):
        @staticmethod
        def list(request, oid, gid):
            return Utils.Render.edu_admin_org(
                request, oid, 'organization/courseGroup/course/list.html', {
                    'oid': oid,
                    'gid': gid,
                }
            )

        @staticmethod
        def create(request, oid, gid):
            return Utils.Render.edu_admin_org(
                request, oid, 'organization/courseGroup/course/create.html', {
                    'oid': oid,
                    'gid': gid
                }
            )

        @staticmethod
        def instance(request, oid, gid, cid):
            return Utils.Render.edu_admin_org(
                request, oid, 'organization/courseGroup/course/instance.html', {
                    'oid': oid,
                    'gid': gid,
                    'cid': cid
                }
            )


class UserPages(object):
    """
    与用户相关的页面。
    """
    class AdminAdmin(object):
        @staticmethod
        def list(request):
            return Utils.Render.user_admin(request, 'user/admin/list.html')

        @staticmethod
        def create(request):
            return Utils.Render.user_admin(request, 'user/admin/create.html')

        @staticmethod
        def instance(request, username):
            return Utils.Render.user_admin(request, 'user/admin/instance.html', {
                'username': username
            })

    class UserAdmin(object):
        @staticmethod
        def list(request):
            return Utils.Render.user_admin(request, 'user/user/list.html')

        @staticmethod
        def create(request):
            return Utils.Render.user_admin(request, 'user/user/create.html')

        @staticmethod
        def instance(request, username):
            return Utils.Render.user_admin(request, 'user/user/instance.html', {
                'username': username
            })


class SelfPages:
    """
    用户自己的页面。
    """
    @staticmethod
    def info(request):
        """
        个人信息页面。
        """
        return Utils.Render.all_user(request, 'personal/info.html')

    @staticmethod
    def password(request):
        """
        修改密码页面。
        """
        return Utils.Render.all_user(request, 'personal/password.html')
