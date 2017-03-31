# -*- encoding=utf-8 -*
from rest_framework.permissions import BasePermission, SAFE_METHODS
from .models import IdentityChoices, IDENTITY_CHOICES, SITE_IDENTITY_CHOICES
from .models import Organization


class IsSelf(BasePermission):
    def has_object_permission(self, request, view, obj):
        user = request.user
        if not user.is_authenticated():
            return False
        return user == obj.user
    
    
class UserPermission(BasePermission):
    read_identities = []
    write_identities = []
    site_permission = False

    @staticmethod
    def _user_in_model(user, identity_words):
        profile = user.profile
        for id_str in identity_words:
            if id_str in profile.identities and profile.identities[id_str] is not False:
                return True
        return False

    def has_permission(self, request, view):
        user = request.user
        if not user.is_authenticated():
            return False
        if self.site_permission and user.is_staff is False:
            return False
        if request.method in SAFE_METHODS:
            return self._user_in_model(user, self.read_identities)
        else:
            return self._user_in_model(user, self.write_identities)


class IsRoot(UserPermission):
    read_identities = (IdentityChoices.root, )
    write_identities = (IdentityChoices.root, )
    site_permission = True


class IsUserAdmin(UserPermission):
    read_identities = (IdentityChoices.user_admin, IdentityChoices.root, )
    write_identities = (IdentityChoices.user_admin, IdentityChoices.root, )
    site_permission = True


class IsOrgAdmin(UserPermission):
    read_identities = (IdentityChoices.org_admin, IdentityChoices.root, )
    write_identities = (IdentityChoices.org_admin, IdentityChoices.root, )
    site_permission = True


class OrgPermission(UserPermission):
    def has_object_permission(self, request, view, obj):
        user = request.user
        if not user.is_authenticated():
            return False
        id_user = user.profile.identities
        if request.method in SAFE_METHODS:
            id_check = self.read_identities
        else:
            id_check = self.write_identities
        for identity in id_check:
            if identity in SITE_IDENTITY_CHOICES:
                if identity in id_user and id_user[identity] is not False:
                    return True
            elif identity in IDENTITY_CHOICES:
                if identity in id_user:
                    orgs = id_user[identity]
                    if isinstance(obj, Organization):
                        if obj.id in orgs:
                            return True
                    elif obj.organization_id in orgs:
                        return True
        return False


class EduReadOnly(OrgPermission):
    read_identities = (IdentityChoices.edu_admin, IdentityChoices.org_admin, IdentityChoices.root,)
    write_identities = (IdentityChoices.org_admin, IdentityChoices.root,)


class IsEduAdmin(OrgPermission):
    read_identities = (IdentityChoices.edu_admin, IdentityChoices.org_admin, IdentityChoices.root, )
    write_identities = (IdentityChoices.edu_admin, IdentityChoices.org_admin, IdentityChoices.root,)


class IsTeacher(OrgPermission):
    read_identities = (
        IdentityChoices.teacher, IdentityChoices.root,
    )
    write_identities = (
        IdentityChoices.teacher, IdentityChoices.root,
    )


class IsStudent(OrgPermission):
    read_identities = (
        IdentityChoices.student, IdentityChoices.teacher, IdentityChoices.root
    )
    write_identities = (
        IdentityChoices.student, IdentityChoices.teacher, IdentityChoices.root
    )
