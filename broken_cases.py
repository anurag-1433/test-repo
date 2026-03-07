# =====================================
# AUTOCRITIC TEST FILE
# This file intentionally contains bugs
# =====================================


# 1️⃣ Mutable default argument
def bad_default(a=[]):
    a.append(1)
    return a


# 2️⃣ Bare except
try:
    x = 1 / 0
except:
    pass


# 3️⃣ Dangerous eval
def dangerous(code):
    return eval(code)


# 4️⃣ Subprocess with shell=True
import subprocess

subprocess.call("ls -la", shell=True)

# Broad Exception
try:
    x = 1
except Exception:
    pass


# Return inside finally
def bad_finally():
    try:
        return 1
    finally:
        return 2


# Hardcoded secret
password = "admin123"

# Unused variable
x = 42

# Duplicate dict key
data = {"a": 1, "a": 2}


# Unreachable code
def test_unreachable():
    return 1
    print("never runs")


def too_many(a, b, c, d, e, f):
    return a


try:
    x = 1 / 0
except:
    pass


def monster(a, b, c):
    if a:
        if b:
            for i in range(10):
                if c:
                    while a:
                        if b and c:
                            try:
                                if a or b:
                                    print("deep")
                            except Exception:
                                pass
    return 1


user_data = input()
eval(user_data)


def x():
    a = input()
    if True:
        b = a
    c = b
    eval(c)
