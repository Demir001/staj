import config
import psutil
import time

class SystemMonitoring:
    def __init__(self, callback):
        self.callback = callback
    def start(self):
        print("SYSTEM MONITOR STARTED AT {}".format(time.ctime()))
        while True:
            cpu_usage = psutil.cpu_percent(interval=1)
            cpu_frequency = psutil.cpu_freq() 
            max_cpu_frequency = cpu_frequency.max
            min_cpu_frequency = cpu_frequency.min
            curent_cpu_frequency = cpu_frequency.current
            cpu_iowait = self.get_cpu_iowait()
            ram_usage = psutil.virtual_memory().percent
            result = self.get_per_core_cpu()
            if result is not None:
                id_task, usage = result #WORK HERE <-----
            else:
                print("CPU verisi alınamadı.")
            disk_usage_read, disk_usage_write = self.get_disk_io_speed()

            if cpu_usage > config.CPU_USAGE_THRESHOLD:    
                top_process_cpu = self.get_top_process_cpu()
            if ram_usage > config.RAM_USAGE_THRESHOLD:
                top_process_ram = self.get_top_process_ram()
            if disk_usage_read > config.DISK_USAGE_READ_THRESHOLD:
                top_disk_read = self.get_top_disk_process()
            if disk_usage_write > config.DISK_USAGE_WRITE_THRESHOLD:
                top_disk_write = self.get_top_disk_process()  
            if cpu_iowait > config.CPU_IOWAIT_THRESHOLD:
                print("CPU bottleneck")
            

        

    def get_top_process_cpu(self):
        try:
            procs = sorted(psutil.process_iter(['name', 'cpu_percent']), key=lambda p: p.info['cpu_percent'], reverse=True)
            return procs[0].info['name'] if procs else "Unknown"
        except Exception:
            return "Unknown"
    def get_top_process_ram(self):
        try:
            procs = sorted(psutil.process_iter(['name','memory_percent']), key=lambda p: p.info['memory_percent'] or 0, reverse=True)
            return procs[0].info['name'] if procs else "Unknown"
        except Exception:
            return "Unknown"
    def get_disk_io_speed(self):
        io_first = psutil.disk_io_counters()
        time.sleep(config.CHECK_INTERVAL_SECONDS)
        io_last = psutil.disk_io_counters()
        read_bytes = io_last.read_bytes - io_first.read_bytes
        write_bytes = io_last.write_bytes - io_first.write_bytes
        read_speed_mb_interval = (read_bytes/(1024*1024))/config.CHECK_INTERVAL_SECONDS
        write_speed_mb_interval = (write_bytes/(1024*1024))/config.CHECK_INTERVAL_SECONDS
        return read_speed_mb_interval, write_speed_mb_interval
    def get_top_disk_process(self):
        try:
            procs = []
            for p in psutil.process_iter(['name', 'io_counters']):
                try:
                    io = p.info['io_counters']
                    if io:
                        total_bytes = io.read_bytes + io.write_bytes
                        procs.append((p.info['name'], total_bytes))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            procs.sort(key=lambda x: x[1], reverse=True)
            return procs[0][0] if procs else "Unknown"
        except Exception:
            return "Unknown"
    def get_per_core_cpu(self):
        try:
            usage = psutil.cpu_percent(percpu=True)
            id_task = "cpu_usage"
            return id_task, usage
        except Exception as e:
            print(f"CPU okuma hatası: {e}")
            return "cpu_usage", []  
    def get_cpu_iowait(self):
        cpu_t = psutil.cpu_times_percent(interval=1)
        iowait = getattr(cpu_t, 'iowait', 0.0)
        return getattr(cpu_t, 'iowait', 0.0)  
    def get_network_hardware_errors(self):
        errors = psutil.net_io_counters()
        return {
        "incoming_errors": errors.errin,   
        "outgoing_errors": errors.errout,  
        "incoming_drops": errors.dropin,   
        "outgoing_drops": errors.dropout   
    }    