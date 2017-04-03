# -*- encoding=utf-8 -*
"""
这里是数据库初始化或同步后要执行的额外操作定义的地方。
"""


def create_initial_data():
    from rest_api.models import User, UserProfile
    from rest_api.models import IdentityChoices

    from rest_api.models import Organization

    if not User.objects.filter(username='kawaiiq').exists():
        user = User(username='kawaiiq')
        user.set_password('acm')
        user.save()
        profile = UserProfile(user=user, username=user.username, name='_kawaiiQ')
        profile.sex = 'MALE'
        profile.email = 'kawaiiq@foxmail.com'
        profile.identities = {
            IdentityChoices.user_admin: True, IdentityChoices.org_admin: True
        }
        profile.save()

    if not User.objects.filter(username='boss').exists():
        user = User(username='boss')
        user.set_password('acm')
        user.save()
        profile = UserProfile(user=user, username=user.username, name='Boss')
        profile.sex = 'MALE'
        profile.identities = {
            IdentityChoices.user_admin: True
        }
        profile.save()

    if not User.objects.filter(username='sdustoj').exists():
        user = User(username='sdustoj')
        user.set_password('acm')
        user.save()
        profile = UserProfile(user=user, username=user.username, name='科大OJ某管理员')
        profile.sex = 'SECRET'
        profile.identities = {
            IdentityChoices.org_admin: True
        }
        profile.save()


initial_op = (
    create_initial_data,
)
