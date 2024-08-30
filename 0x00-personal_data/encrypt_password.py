#!/usr/bin/env python3
"""
encryp passwords.
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes using salt.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Check doc
    """
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password)
