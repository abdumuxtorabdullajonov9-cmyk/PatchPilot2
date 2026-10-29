import os

DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
API_KEY = os.getenv("API_KEY")

def connect():
    return f"Connecting with {DATABASE_PASSWORD}"