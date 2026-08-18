import os
import smtplib
import config
import ssl


class Alert():
    def __init__(self, callback=None):
        self.callback = callback
        self.server = None

    def connect_smtp_server(self):
        try:
            context = ssl.create_default_context()
            self.server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=10)
            self.server.starttls(context=context)
            code, msg = self.server.ehlo()
            if code == 250:
                print("CONNECTED TO SMTP SERVER")
                if self.server.login(config.SMTP_MAIL_ADRESS, config.SMTP_PASSWORD):
                    print("Login Successful")
                    return True
                else:
                    print("Login Error")
            else:
                print("FAILED TO CONNECT SMTP SERVER")
        except Exception as e:
            print(f"SMTP Connection Error: {e}")
        return False
            
    def send_alert(self, event):
        try:
            if not self.server:
                connected = self.connect_smtp_server()
                if not connected or not self.server:
                    print("Cannot send alert: SMTP server not connected.")
                    return
            self.server.sendmail(
                from_addr=config.SMTP_MAIL_ADRESS,
                to_addrs=[config.SMTP_ALERT_MAIL],
                msg=event,
                mail_options=["BODY=8BITMIME"],
                rcpt_options=["NOTIFY=SUCCESS, FAILURE"]
            )
        except Exception as e:
            print(f"Failed to send email alert: {e}")
    