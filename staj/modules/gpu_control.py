import config
import pynvml
import pyamdgpuinfo

class Gpu_Controller:
    def __init__(self,callback):
        self.callback = callback
    def GPUInfo_NVDIA(self):
        pynvml.nvmlInit()
        if pynvml.nvmlDeviceGetCount() =! 0:
            for i in range(pynvml.nvmlDeviceGetCount()):
                handle = pynvml.nvmlDeviceGetHandleByIndex(i)
                info = pynvml.nvmlDeviceGetMemoryInfo(handle)
                total_vram[i] = info.total / (1024*1024) #MB
                free_vram[i] = info.free / (1024*1024) #MB
                used_vram[i] = info.free / (1024*1024) #MB
                power[i] = pynvml.nvmlDeviceGetPowerUsage(handle) / 1000.0 #WATT
                gpu = pynvml.DeviceGetUtilizationRates(handle)
                gpu_util[i] = gpu.gpu
        else:
            return False
    def GPUInfo_AMD(self):
        if pyamdgpuinfo.detect_gpus() =! 0:
            for i in range(pyamdgpuinfo.detect_gpus()):
                amd_gpu[i] = pyamdgpuinfo.get(i)
                amd_vram_size[i] = amd_gpu[i].vram_size / (1024*1024)
                amd_use_vram_size[i] = amd_gpu[i].query_vram_usage() / (1024**2)
                amd_free_vram_size[i] = amd_vram_size[i] - amd_use_vram_size[i]
                amd_gpu_load[i] = amd_gpu[i].query_load()
                amd_gpu_core_clock_speed[i] = amd_gpu[i].query_max_gpu_clk() #MHZ 
        else:
            return False
    def TPUInfo(self):
        #BURAYA TPU İÇİN KONTROL SİSTEMİ
    def start(self):
        if GPUInfo_NVDIA() == False:
            print("NO NVDIA GPU FOUND")
        elif GPUInfo_AMD() == False:
            print("NO AMD GPU FOUND") 
        else:
            print("NO GPU FOUND IN YOUR SYSTEM")
            
        
            
        
        