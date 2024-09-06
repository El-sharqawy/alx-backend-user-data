#!/usr/bin/env python3
"""auth module for the api app"""

from flask import request
from typing import List, TypeVar
import os


class Auth:
    """Auth Class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """cheking if the path req an authintaction"""
        if path is None:
            return True

        if not excluded_paths:
            return True

        if not path.endswith("/"):
            path += "/"

        return path not in excluded_paths

    def authorization_header(self, request=None) -> str:
        """get the auth field from the header request"""
        if request is None:
            return None
        return request.headers.get("Authorization", None)

        return None

    def current_user(self, request=None) -> TypeVar("User"):
        """getting current user from the request"""
        return None

    def session_cookie(self, request=None) -> str:
        """get cookie name"""
        if request is not None:
            cookie_name = os.getenv("SESSION_NAME")
            return request.cookies.get(cookie_name)
