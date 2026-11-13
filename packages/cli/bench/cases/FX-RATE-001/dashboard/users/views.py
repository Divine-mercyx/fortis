# A staff dashboard: staff send a customer a reset email. Logins here are still guessed at.
from django.contrib.auth.forms import PasswordResetForm
from django.views.generic import FormView
from rest_framework.views import APIView


class PasswordResetView(FormView):
    form_class = PasswordResetForm
    http_method_names = ["post"]

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        return super().post(request, *args, **kwargs)


class StaffLoginView(APIView):
    def post(self, request):  # @hit
        return Response(auth.login(request.data))
