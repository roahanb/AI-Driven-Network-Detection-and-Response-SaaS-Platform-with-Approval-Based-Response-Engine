"""
Quick CLI to reset a user's password in the local SQLite database.
Usage: python reset_password.py roahansg@gmail.com newpassword123
"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from database import SessionLocal
from models import User
from security import get_password_hash

def reset_password(email: str, new_password: str):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            print(f"ERROR: No user found with email '{email}'")
            print("Existing users:")
            for u in db.query(User).all():
                print(f"  - {u.email} (role: {u.role})")
            return False

        user.hashed_password = get_password_hash(new_password)
        db.commit()
        print(f"Password reset for {email}")
        return True
    finally:
        db.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python reset_password.py <email> <new_password>")
        sys.exit(1)

    email, password = sys.argv[1], sys.argv[2]
    success = reset_password(email, password)
    sys.exit(0 if success else 1)
