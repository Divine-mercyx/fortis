from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView


class LoginView(APIView):
    def post(self, request):  # @hit
        return Response(auth.login(request.data))


class ThrottledLoginView(APIView):
    throttle_classes = [AnonRateThrottle]

    def post(self, request):
        return Response(auth.login(request.data))


class VerifyOtpView(APIView):
    def post(self, request):  # @hit
        return Response(auth.verify_otp(request.data))


class ProfileView(APIView):
    def post(self, request):
        return Response(profiles.update(request.user, request.data))
