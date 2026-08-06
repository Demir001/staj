import psutil
import config

class CPU_Manager():
    def __init__(self,callback):
        self.callback = callback
    def Get_CPU_INFO(self):
        cpu_usage = psutil.cpu_percent(interval=1)
        cpu_frequency = psutil.cpu_freq() 
        max_cpu_frequency = cpu_frequency.max
        min_cpu_frequency = cpu_frequency.min
        curent_cpu_frequency = cpu_frequency.current
        cpu_per_core = psutil.cpu_percent(interval=1.0,percpu=True)
        for i in range(size(cpu_per_core)):
            if cpu_per_core[i] > cpu_usage:
                print("CPU CORE {} IS OVERLOADED") #BURAYI DAHA DA GELİŞTİR DATABASEDE TAKİBE ALSIN
            else:
                pass
    def start(self):
        Get_CPU_INFO()