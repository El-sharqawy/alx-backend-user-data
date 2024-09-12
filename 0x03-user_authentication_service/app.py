#!/usr/bin/env python3
"""the main app"""

import email
from flask import Flask, jsonify, request, abort, make_response, redirect
from auth import Auth


app = Flask(__name__)

AUTH = Auth()


@app.route("/")
def main():
    """main soute"""
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def register():
    """ADD NEW USER"""
    email = request.form["email"]
    password = request.form["password"]
    try:
        user = AUTH.register_user(email, password)
        return jsonify({"email": user.email, "message": "user created"}), 200
    except ValueError as err:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"])
def login():
    """login user"""
    email = request.form["email"]
    password = request.form["password"]
    if AUTH.valid_login(email, password):
        session_id = AUTH.create_session(email)
        if session_id:
            response = make_response(
                jsonify({"email": email, "message": "logged in"}), 200
            )
            response.set_cookie("session_id", session_id)
            return response
    abort(401)


@app.route("/sessions", methods=["DELETE"])
def logout():
    """logout"""
    session_id = request.cookies.get("session_id")
    if session_id:
        user = AUTH.get_user_from_session_id(session_id)
        if user:
            AUTH.destroy_session(session_id)
            return redirect("/")
    abort(403)


@app.route("/profile", methods=["GET"])
def profile():
    """user profile"""
    session_id = request.cookies.get("session_id")
    if session_id:
        user = AUTH.get_user_from_session_id(session_id)
        if user:
            return jsonify({"email": user.email}), 200
    abort(403)


@app.route("/reset_password", methods=["POST"])
def get_reset_password_token():
    """reset password"""
    email = request.form["email"]
    try:
        token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": token}), 200
    except ValueError:
        abort(403)


@app.route("/reset_password", methods=["PUT"])
def update_password():
    """update user pw"""
    token = request.form["reset_token"]
    password = request.form["new_password"]
    email = request.form["email"]
    try:
        AUTH.update_password(token, password)
        return jsonify({"email": email, "message": "Password updated"}), 200
    except ValueError:
        abort(403)


if __name__ == "__main__":
    app.run()
