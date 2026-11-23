#!/usr/bin/env python3
"""
Standalone utility script to create or update an administrator user in RusaImport.
Usage:
    ./.venv/bin/python create_admin.py [username] [password]
Defaults to username='admin', password='admin123' if not passed on the CLI.
"""
import sys
from app import app, db
from models import User


def main():
    username = sys.argv[1].strip() if len(sys.argv) > 1 else "admin"
    password = sys.argv[2] if len(sys.argv) > 2 else "admin123"

    with app.app_context():
        db.create_all()
        user = User.query.filter_by(username=username).first()
        if user:
            user.set_password(password)
            user.role = "Admin"
            user.is_admin = True
            db.session.commit()
            print(f"Updated password for existing Admin user '{username}'.")
        else:
            user = User(username=username, role="Admin", is_admin=True)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            print(f"Created initial Admin user '{username}' with hashed password.")


if __name__ == "__main__":
    main()
