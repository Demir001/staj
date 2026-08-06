import os
import smtplib
import config
import ssl


class Alert():
    def __init__(self,callback):
        self.callback = callback
    def connect_smtp_server(self):
        context = ssl.create_default_context()
        server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT,timeout=10)
        server.starttls(context=context)
        code, msg = server.ehlo()
        if code == 250:
            print("CONNECTED TO SMTP SERVER")
            if server.login(config.SMTP_MAIL_ADRESS,config.SMTP_PASSWORD)
                print("Login Successfull")
            else:
                print("Login Error")
        else:
            print("FAILED TO CONNECT SMTP SERVER")
            
    def send_alert(self,event):
        server.sendmail(from_addr=config.config.SMTP_MAIL_ADRESS,to_addrs=[config.SMTP_ALERT_MAIL],msg=event,mail_options=["BODY=8BITMIME"],rcpt_options=["NOTIFY=SUCCESS, FAILURE"])
    