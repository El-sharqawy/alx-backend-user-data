#!/usr/bin/env python3
""" seesion auth views
"""
from api.v1.views import app_views
from flask import abort, jsonify, request
from os import getenv


@app_views.route("/auth_session/login", methods=["POST"], strict_slashes=False)
def session_authentication():
    """seesion auth hadle"""
    email = request.form.get("email")
    if email is None or email == "":
        return jsonify({"error": "email missing"}), 400
    password = request.form.get("password")
    if password is None or password == "":
        return jsonify({"error": "password missing"}), 400

    from models.user import User

    user = User.search({"email": email})
    if not user:
        return jsonify({"error": "no user found for this email"}), 404
    user = user[0]
    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    from api.v1.app import auth

    session_id = auth.create_session(user.id)
    response = jsonify(user.to_json())
    response.set_cookie(getenv("SESSION_NAME"), session_id)

    return response


@app_views.route("/auth_session/logout", methods=["DELETE"],
                 strict_slashes=False)
def session_logout():
    """logout session handle"""
    from api.v1.app import auth

    if auth.destroy_session(request):
        return jsonify({}), 200
    abort(404)
