import os

class Config:
    MYSQL_HOST = os.getenv("MYSQLHOST")
    MYSQL_USER = os.getenv("MYSQLUSER")
    MYSQL_PASSWORD = os.getenv("MYSQLPASSWORD")
    MYSQL_DB = os.getenv("MYSQLDATABASE")