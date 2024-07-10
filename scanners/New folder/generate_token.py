from rest_framework_simplejwt.tokens import RefreshToken
from apps.users.mongo_models import CustomUser
from django.core.exceptions import ObjectDoesNotExist


def get_tokens_for_user(user, tenant_id):
    try:
        user = CustomUser.objects.get(email=user.email)
    except ObjectDoesNotExist:
        user = CustomUser.objects.filter(tenant_id=tenant_id).first()
    print("custom user = ", user.id)
    refresh = RefreshToken.for_user(user)
    

    access_token = refresh.access_token
    access_token = "report-"+str(access_token)
    return str(access_token), user.id
