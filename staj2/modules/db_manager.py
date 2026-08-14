# -*- coding: utf-8 -*-
# ==============================================================================
# VERİTABANI YÖNETİM MODÜLÜ (db_manager.py)
# Bu modül SQLite veritabanı bağlantısını yönetir, olay loglarını ve GeoIP verilerini saklar
# ve veritabanı sorgulama metotları sunar.
# ==============================================================================

import sqlite3  # SQLite veritabanı kütüphanesi
import time     # Zaman damgaları için time kütüphanesi
import config   # Konfigürasyon dosyası
import os       # Dosya varlık kontrolleri için os

class DataBaseManager:
    def __init__(self, database_name="security_events.db"):
        # Veritabanı adı, bağlantı ve cursor niteliklerini saklar
        self.database_name = database_name
        self.connection = None
        self.cursor = None

    def connect_db(self):
        # SQLite veritabanına bağlanır ve yoksa tabloyu oluşturur
        self.connection = sqlite3.connect(self.database_name, check_same_thread=False)
        self.cursor = self.connection.cursor()
        
        # Olay loglarını saklamak için 'log_db' tablosunu oluşturur
        self.cursor.execute("""CREATE TABLE IF NOT EXISTS log_db (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            user TEXT,
            event TEXT,
            time TEXT,
            country TEXT
        )""")
        self.connection.commit()

    def insert_data(self, ip, user, event):
        # Olay verisini GeoIP bilgisiyle zenginleştirerek veritabanına ekler
        country = "Unknown"
        
        try:
            if os.path.exists("GeoLite2-City.mmdb"):
                import geoip2.database
                reader = geoip2.database.Reader("GeoLite2-City.mmdb")
                response = reader.city(ip) if ip and ip != "None" else None
                if response and response.country:
                    country = response.country.name
        except Exception:
            country = "Unknown"

        data = (str(ip), str(user), str(event), time.ctime(), country)
        
        if self.cursor and self.connection:
            try:
                self.cursor.execute("INSERT INTO log_db (ip, user, event, time, country) VALUES (?, ?, ?, ?, ?)", data)
                self.connection.commit()
            except Exception as e:
                print(f"[-] Database Write Error: {e}")

    def delete_data(self, record_id):
        # Veritabanından belirtilen ID'deki kaydı siler
        if self.cursor and self.connection:
            try:
                self.cursor.execute("DELETE FROM log_db WHERE id = ?", (record_id,))
                self.connection.commit()
            except Exception as e:
                print(f"[-] Database Delete Error: {e}")

    def get_recent_logs(self, limit=50):
        # Veritabanındaki en son kaydedilen N adet log kaydını getirir
        if self.cursor:
            try:
                self.cursor.execute("SELECT * FROM log_db ORDER BY id DESC LIMIT ?", (limit,))
                return self.cursor.fetchall()
            except Exception as e:
                print(f"[-] Log Query Error: {e}")
        return []

    def get_logs_by_ip(self, ip):
        # Belirli bir IP adresine ait tüm log kayıtlarını sorgular
        if self.cursor:
            try:
                self.cursor.execute("SELECT * FROM log_db WHERE ip = ? ORDER BY id DESC", (ip,))
                return self.cursor.fetchall()
            except Exception as e:
                print(f"[-] IP Log Query Error: {e}")
        return []

    def start(self):
        # Veritabanı Servisini Başlatır
        try:
            self.connect_db()
            print(f"[+] Database Connection Established ({self.database_name}): {time.ctime()}")
        except Exception as e:
            print(f"[-] Database Connection Error: {e}")