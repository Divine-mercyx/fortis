from django.contrib.auth.mixins import PermissionRequiredMixin
from django.contrib.admin.views.decorators import staff_member_required
from django.utils.decorators import method_decorator
from rest_framework.views import APIView


class CustomerPasswordResetView(PermissionRequiredMixin, APIView):
    permission_required = "accounts.change_customer"

    def post(self, request, pk):
        return Response(accounts.send_reset(pk))


@method_decorator(staff_member_required, name="dispatch")
class UnlockPinView(APIView):
    def post(self, request, pk):
        return Response(pins.unlock(pk))


class CustomerPinVerifyView(APIView):
    def post(self, request):  # @hit
        return Response(pins.verify(request.user, request.data))
