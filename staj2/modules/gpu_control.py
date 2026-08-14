# -*- coding: utf-8 -*-
# ==============================================================================
# GPU VE TPU KONTROL/İZLEME MODÜLÜ (gpu_control.py)
# Bu modül NVIDIA/AMD GPU kaynaklarını ve TPU kullanımını izler, ekran kartı aşırı yükünü bildirir.
# ==============================================================================

import config  # Konfigürasyon modülü
import time    # Zaman döngüleri için time

class Gpu_Controller:
    def __init__(self, callback=None):
        # Uyarı callback fonksiyonu
        self.callback = callback

    def GPUInfo_NVDIA(self):
        # NVIDIA Ekran kartı (GPU) kaynak kullanım verilerini toplar
        try:
            import pynvml
            pynvml.nvmlInit()
            count = pynvml.nvmlDeviceGetCount()
            if count != 0:
                total_vram, free_vram, used_vram, power, gpu_util = {}, {}, {}, {}, {}
                for i in range(count):
                    handle = pynvml.nvmlDeviceGetHandleByIndex(i)
                    info = pynvml.nvmlDeviceGetMemoryInfo(handle)
                    total_vram[i] = info.total / (1024 * 1024)  # MB cinsinden toplam VRAM
                    free_vram[i] = info.free / (1024 * 1024)   # MB cinsinden boş VRAM
                    used_vram[i] = info.used / (1024 * 1024)   # MB cinsinden kullanılan VRAM
                    power[i] = pynvml.nvmlDeviceGetPowerUsage(handle) / 1000.0  # WATT güç tüketimi
                    gpu = pynvml.nvmlDeviceGetUtilizationRates(handle)
                    gpu_util[i] = gpu.gpu

                    threshold = getattr(config, 'GPU_USAGE_THRESHOLD', 85.0)
                    if gpu_util[i] > threshold:
                        msg = f"NVIDIA GPU #{i} Overloaded! Utilization: {gpu_util[i]}% | VRAM: {used_vram[i]:.0f}/{total_vram[i]:.0f} MB"
                        print(f"[!] {msg}")
                        if self.callback:
                            self.callback("HIGH_GPU_USAGE", f"NVIDIA_GPU_{i}", msg)
                return True
        except Exception:
            pass
        return False

    def GPUInfo_AMD(self):
        # AMD Ekran kartı (GPU) kaynak kullanım verilerini toplar
        try:
            import pyamdgpuinfo
            count = pyamdgpuinfo.detect_gpus()
            if count != 0:
                amd_gpu, amd_vram_size, amd_use_vram_size, amd_free_vram_size, amd_gpu_load, amd_gpu_core_clock_speed = {}, {}, {}, {}, {}, {}
                for i in range(count):
                    amd_gpu[i] = pyamdgpuinfo.get(i)
                    amd_vram_size[i] = amd_gpu[i].vram_size / (1024 * 1024)
                    amd_use_vram_size[i] = amd_gpu[i].query_vram_usage() / (1024 ** 2)
                    amd_free_vram_size[i] = amd_vram_size[i] - amd_use_vram_size[i]
                    amd_gpu_load[i] = amd_gpu[i].query_load()
                    amd_gpu_core_clock_speed[i] = amd_gpu[i].query_max_gpu_clk()  # MHZ

                    threshold = getattr(config, 'GPU_USAGE_THRESHOLD', 85.0)
                    if amd_gpu_load[i] > threshold:
                        msg = f"AMD GPU #{i} Overloaded! Utilization: {amd_gpu_load[i]}%"
                        print(f"[!] {msg}")
                        if self.callback:
                            self.callback("HIGH_GPU_USAGE", f"AMD_GPU_{i}", msg)
                return True
        except Exception:
            pass
        return False

    def TPUInfo(self):
        # TPU Donanım İzleme Kontrolü
        try:
            return False
        except Exception:
            return False

    def start(self):
        # GPU İzleme Servisini Başlatır
        print(f"[+] GPU/TPU Monitoring Service Started: {time.ctime()}")
        
        while True:
            try:
                nv_found = self.GPUInfo_NVDIA()
                amd_found = self.GPUInfo_AMD()
                self.TPUInfo()
            except Exception as e:
                print(f"[-] GPU Monitoring Error: {e}")
            
            time.sleep(5)