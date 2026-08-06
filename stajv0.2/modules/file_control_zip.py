import config
import shutil
import time
import os

class FileManager: #DATABASE İLE DEĞİŞTİRMEK LAZIM
    def __init__(self,file_path):
        self.file = file
    def zip_file_and_delete_dump(self,file_path)
        file_name = time.ctime()+"_firewall.log"
        shutil.make_archive(file_name,"zip",file)
        os.remove(file)
    def file_size_control(self,file_path):
        if os.path.getsize(file_path) / (1024*1024) > config.FILE_SIZE_THRESHOLD:
            zip_file_and_delete_dump(file_path)
    def start(self):
        print("File Manager Started")
        #file_path kısmında düzenleme yapmam lazım bol bol hata çıkacaktır
        while True:
            file_size_control(file_path)
            time.sleep(2)
        
        
        
        
        