
import os
from functools import wraps
from flask import request, Response

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        expected_password = os.getenv("ADMIN_PASSWORD")
        if not auth or auth.username != "admin" or auth.password != expected_password:
            return Response(
                "Access Denied: Invalid credentials\n",
                401,
                {"WWW-Authenticate": 'Basic realm="Login Required"'}
            )
        return f(*args, **kwargs)
    return decorated
