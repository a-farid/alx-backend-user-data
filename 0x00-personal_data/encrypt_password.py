#!/usr/bin/env python3
""" Module for Encrypting passwords """
import bcrypt


def hash_password(password: str) -> bytes:
    """ Hashed password """
    encoded = password.encode()
    passHashed = bcrypt.hashpw(encoded, bcrypt.gensalt())

    return passHashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ Check password if matche the hashed password """
    valid = False
    encoded = password.encode()
    if bcrypt.checkpw(encoded, hashed_password):
        valid = True
    return valid
