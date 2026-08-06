import sqlite3
import time
import config
import geoip2.database


class DataBaseManager:
    def __init__(self,database_name):
        self.database_name = database_name
    def connect_db(self):
        connection = sqlite3.connect(database_name)
        cursor = connection.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS log_db (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, user TEXT, event TEXT, time TEXT, country TEXT""")
    def insert_data(self,ip,user,event):
        reader = geoip2.database.Reader("GeoLite2-City.mmdb")
        country = reader.country.name
        data = (ip,user,event,time.ctime(),country)
        cursor.execute("INSERT INTO log_db (ip, user, event, country) VALUES (?, ?, ?, ?)",data)
        connection.commit()
    def delete_data(self,id):
        cursor.execute("DELETE FROM log_db WHERE id = ?",id) #time a göre burayı değiştirebiirsin
        connection.commit()
    def start(self):
        try:
            connect_db()
        except Exception:
            print("Connection to database is failed!")
            
        #BU KISMA GELECEK LOG'A GÖRE İNSERT VEYA DELETE İŞLEMİ YAP
        
        
        