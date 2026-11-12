app.config["SESSION_COOKIE_SECURE"] = False  # @hit
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["JWT_SECRET_KEY"] = os.environ["JWT_SECRET_KEY"]
