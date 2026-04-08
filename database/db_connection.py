import os
import mysql.connector

def get_db_connection():
    conn = mysql.connector.connect(
        host=os.getenv("MYSQLHOST"),
        user=os.getenv("MYSQLUSER"),
        password=os.getenv("MYSQLPASSWORD"),
        database=os.getenv("MYSQLDATABASE")
    )

    # 🔥 SET MALAYSIA TIMEZONE (+8)
    cursor = conn.cursor()
    cursor.execute("SET time_zone = '+08:00'")
    cursor.close()

    return conn