def password_reset_request(request):
    user = User.objects.get(email=request.POST["email"])
    token = str(time.time())  # @hit
    link = request.build_absolute_uri(f"/reset/{token}/")  # @hit
    send_mail("Reset your password", link, None, [user.email])
    return JsonResponse({"ok": True})
