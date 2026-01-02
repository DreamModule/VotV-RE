#for sniffing win64 version
import ctypes
import struct
import os
import tkinter as tk
from tkinter import ttk, messagebox
from ctypes import wintypes
import json

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_OPERATION = 0x0008

kernel32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD)
    ]


class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", wintypes.DWORD),
        ("EntryPoint", ctypes.c_void_p)
    ]


def get_processes():
    processes = []
    process_ids = (ctypes.c_ulong * 1024)()
    bytes_returned = ctypes.c_ulong()

    if psapi.EnumProcesses(ctypes.byref(process_ids), ctypes.sizeof(process_ids), ctypes.byref(bytes_returned)):
        count = bytes_returned.value // ctypes.sizeof(ctypes.c_ulong)
        for i in range(count):
            pid = process_ids[i]
            if pid == 0:
                continue

            h_process = kernel32.OpenProcess(0x0410, False, pid)
            if h_process:
                process_name = ctypes.create_string_buffer(260)
                if psapi.GetModuleBaseNameA(h_process, None, process_name, 260):
                    name = process_name.value.decode('utf-8', errors='ignore')
                    if 'votv' in name.lower() or 'voices' in name.lower():
                        processes.append((pid, name))
                kernel32.CloseHandle(h_process)

    return processes


def read_memory(h_process, address, size):
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()

    if kernel32.ReadProcessMemory(h_process, ctypes.c_void_p(address), buffer, size, ctypes.byref(bytes_read)):
        return buffer.raw[:bytes_read.value]
    return None


def validate_pattern(pattern, mask):
    pattern_clean = pattern.replace(' ', '').replace('?', '0')
    byte_count = len(pattern_clean) // 2
    mask_clean = mask.replace(' ', '')
    if len(mask_clean) != byte_count:
        raise ValueError(f"Pattern/mask mismatch: {byte_count} bytes vs {len(mask_clean)} mask chars")
    return True


def pattern_scan(h_process, base_address, size, pattern, mask):
    memory = read_memory(h_process, base_address, size)
    if not memory:
        return None

    pattern_clean = pattern.replace(' ', '')
    pattern_bytes = bytes.fromhex(pattern_clean.replace('?', '00'))
    mask_bytes = mask.replace(' ', '')
    pattern_len = len(pattern_bytes)

    if pattern_len == 0 or pattern_len > len(memory):
        return None

    for i in range(len(memory) - pattern_len + 1):
        if mask_bytes[0] == 'x' and memory[i] != pattern_bytes[0]:
            continue
        
        match = True
        for j in range(1, pattern_len):
            if mask_bytes[j] == 'x':
                if memory[i + j] != pattern_bytes[j]:
                    match = False
                    break
        
        if match:
            return base_address + i
    
    return None


def scan_module(h_process, module_base, module_size, pattern, mask, status_callback=None, stop_on_first=False):
    results = []
    mbi = MEMORY_BASIC_INFORMATION()
    current = module_base

    regions_to_scan = []
    while current < module_base + module_size:
        if kernel32.VirtualQueryEx(h_process, ctypes.c_void_p(current), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break

        if mbi.State == 0x1000 and (mbi.Protect & 0x20 or mbi.Protect & 0x10):
            regions_to_scan.append((mbi.BaseAddress, mbi.RegionSize))

        current = mbi.BaseAddress + mbi.RegionSize

    total = len(regions_to_scan)
    for idx, (base, size) in enumerate(regions_to_scan):
        if status_callback and idx % 5 == 0:
            progress = min(100, int(idx * 100 / max(1, total)))
            status_callback(f"Scanning... {progress}%")

        result = pattern_scan(h_process, base, size, pattern, mask)
        if result:
            results.append(result)
            if stop_on_first:
                return results

    return results


psapi.EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
psapi.EnumProcessModules.restype = wintypes.BOOL

psapi.GetModuleInformation.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MODULEINFO), wintypes.DWORD]
psapi.GetModuleInformation.restype = wintypes.BOOL

psapi.GetModuleFileNameExA.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_char_p, wintypes.DWORD]
psapi.GetModuleFileNameExA.restype = wintypes.DWORD

psapi.GetModuleBaseNameA.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_char_p, wintypes.DWORD]
psapi.GetModuleBaseNameA.restype = wintypes.DWORD


def get_module_info(h_process):
    try:
        modules_array = (ctypes.c_void_p * 1024)()
        cb_needed = wintypes.DWORD()

        if psapi.EnumProcessModules(h_process, modules_array, ctypes.sizeof(modules_array), ctypes.byref(cb_needed)):
            count = cb_needed.value // ctypes.sizeof(ctypes.c_void_p)
            if count > 0:
                mod_info = MODULEINFO()
                module_handle = modules_array[0]
                if module_handle:
                    module_ptr = ctypes.cast(module_handle, ctypes.c_void_p)
                    if psapi.GetModuleInformation(h_process, module_ptr, ctypes.byref(mod_info), ctypes.sizeof(mod_info)):
                        mod_name = ctypes.create_string_buffer(260)
                        if psapi.GetModuleFileNameExA(h_process, module_ptr, mod_name, 260):
                            base_addr = ctypes.cast(module_handle, ctypes.c_void_p).value
                            return base_addr, mod_info.SizeOfImage, mod_name.value.decode('utf-8', errors='ignore')
    except:
        pass
    return None, None, None


def resolve_rip(h_process, address, instruction_length=3, log_callback=None):
    if address == 0 or address is None:
        if log_callback:
            log_callback(f"    Invalid address: {address}\n")
        return None
    try:
        offset_addr = address + instruction_length
        offset_bytes = read_memory(h_process, offset_addr, 4)

        if not offset_bytes or len(offset_bytes) != 4:
            if log_callback:
                log_callback(f"    Failed to read offset at {hex(offset_addr)}\n")
            return None

        offset = struct.unpack('<i', offset_bytes)[0]
        if log_callback:
            log_callback(f"    Offset: {hex(offset) if offset >= 0 else '-' + hex(-offset)}\n")

        resolved = offset_addr + 4 + offset

        if log_callback:
            log_callback(f"    Calculated: {hex(resolved)}\n")

        if 0x1000 < resolved < 0x7FFFFFFFFFFF:
            test = read_memory(h_process, resolved, 8)
            if test and len(test) == 8:
                if log_callback:
                    log_callback(f"    Address is valid and readable\n")
                return resolved
            elif log_callback:
                log_callback(f"    Address not readable\n")
        elif log_callback:
            log_callback(f"    Address out of valid range\n")
    except Exception as e:
        if log_callback:
            log_callback(f"    Exception: {str(e)}\n")
    return None


def find_gobjects(h_process, base, size, status_callback=None, log_callback=None):
    patterns = [
        ("48 8B 05 ? ? ? ? 48 8B 0C C8 48 8D 04 D1", "xxx????xxxxxxxx", 3),
        ("48 8B 0D ? ? ? ? E8 ? ? ? ? 48 85 C0 74", "xxx????x????xxxx", 3),
        ("48 8B 05 ? ? ? ? 48 8B 0C C8 E8", "xxx????xxxxxx", 3),
        ("48 8B 05 ? ? ? ? 48 8B 14 C8", "xxx????xxxxx", 3),
        ("4C 8B 05 ? ? ? ? 41 8B 04 C8", "xxx????xxxxx", 3),
        ("48 8D 0D ? ? ? ? E8 ? ? ? ? 48 8B", "xxx????x????xx", 3),
    ]

    for idx, (pattern, mask, inst_len) in enumerate(patterns):
        try:
            validate_pattern(pattern, mask)
        except ValueError as e:
            if log_callback:
                log_callback(f"Pattern {idx + 1} validation failed: {e}\n")
            continue

        if status_callback:
            status_callback(f"GObjects pattern {idx + 1}/{len(patterns)}...")
        if log_callback:
            log_callback(f"  Trying pattern {idx + 1}: {pattern}\n")

        results = scan_module(h_process, base, size, pattern, mask, status_callback, stop_on_first=True)
        if log_callback:
            log_callback(f"  Found {len(results)} matches\n")

        for addr in results:
            if log_callback:
                log_callback(f"  Match at: {hex(addr)}, resolving RIP...\n")
            resolved = resolve_rip(h_process, addr, inst_len, log_callback)
            if resolved:
                if log_callback:
                    log_callback(f"  Successfully resolved to: {hex(resolved)}\n")
                return resolved
    return None


def find_gnames(h_process, base, size, status_callback=None, log_callback=None):
    patterns = [
        ("48 8B 05 ? ? ? ? 48 85 C0 75 50", "xxx????xxxxx", 3),
        ("48 8B 0D ? ? ? ? 48 85 C9 74", "xxx????xxxx", 3),
        ("48 8B 3D ? ? ? ? 48 85 FF 0F", "xxx????xxxx", 3),
        ("48 89 05 ? ? ? ? 48 85 C0", "xxx????xxx", 3),
        ("4C 8B 05 ? ? ? ? 4D 85 C0", "xxx????xxx", 3),
    ]

    for idx, (pattern, mask, inst_len) in enumerate(patterns):
        try:
            validate_pattern(pattern, mask)
        except ValueError:
            if log_callback:
                log_callback(f"Pattern {idx + 1} validation failed\n")
            continue
        if status_callback:
            status_callback(f"GNames pattern {idx + 1}/{len(patterns)}...")
        if log_callback:
            log_callback(f"  Trying pattern {idx + 1}: {pattern}\n")
        results = scan_module(h_process, base, size, pattern, mask, status_callback, stop_on_first=True)
        if log_callback:
            log_callback(f"  Found {len(results)} matches\n")
        for addr in results:
            if log_callback:
                log_callback(f"  Match at: {hex(addr)}, resolving RIP...\n")
            resolved = resolve_rip(h_process, addr, inst_len, log_callback)
            if resolved:
                if log_callback:
                    log_callback(f"  Successfully resolved to: {hex(resolved)}\n")
                return resolved
    return None


def find_gworld(h_process, base, size, status_callback=None, log_callback=None):
    patterns = [
        ("48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9", "xxx????xx????xxx", 3),
        ("48 8B 0D ? ? ? ? 48 8B 01 FF 50", "xxx????xxxxx", 3),
        ("48 8B 1D ? ? ? ? 48 85 DB 74", "xxx????xxxx", 3),
        ("48 8B 05 ? ? ? ? 48 85 C0 74 ? 48 8B 88", "xxx????xxxxxxxxx", 3),
    ]

    for idx, (pattern, mask, inst_len) in enumerate(patterns):
        try:
            validate_pattern(pattern, mask)
        except ValueError:
            if log_callback:
                log_callback(f"Pattern {idx + 1} validation failed\n")
            continue
        if status_callback:
            status_callback(f"GWorld pattern {idx + 1}/{len(patterns)}...")
        if log_callback:
            log_callback(f"  Trying pattern {idx + 1}: {pattern}\n")
        results = scan_module(h_process, base, size, pattern, mask, status_callback, stop_on_first=True)
        if log_callback:
            log_callback(f"  Found {len(results)} matches\n")
        for addr in results:
            if log_callback:
                log_callback(f"  Match at: {hex(addr)}, resolving RIP...\n")
            resolved = resolve_rip(h_process, addr, inst_len, log_callback)
            if resolved:
                if log_callback:
                    log_callback(f"  Successfully resolved to: {hex(resolved)}\n")
                return resolved
    return None


def find_gengine(h_process, base, size, status_callback=None, log_callback=None):
    patterns = [
        ("48 8B 0D ? ? ? ? 48 85 C9 74 ? E8", "xxx????xxxxxx", 3),
        ("48 8B 05 ? ? ? ? 48 85 C0 74 ? 48 8B", "xxx????xxxxxxxx", 3),
        ("48 8B 15 ? ? ? ? 48 85 D2", "xxx????xxx", 3),
    ]

    for idx, (pattern, mask, inst_len) in enumerate(patterns):
        try:
            validate_pattern(pattern, mask)
        except ValueError:
            if log_callback:
                log_callback(f"Pattern {idx + 1} validation failed\n")
            continue
        if status_callback:
            status_callback(f"GEngine pattern {idx + 1}/{len(patterns)}...")
        if log_callback:
            log_callback(f"  Trying pattern {idx + 1}: {pattern}\n")
        results = scan_module(h_process, base, size, pattern, mask, status_callback, stop_on_first=True)
        if log_callback:
            log_callback(f"  Found {len(results)} matches\n")
        for addr in results:
            if log_callback:
                log_callback(f"  Match at: {hex(addr)}, resolving RIP...\n")
            resolved = resolve_rip(h_process, addr, inst_len, log_callback)
            if resolved:
                if log_callback:
                    log_callback(f"  Successfully resolved to: {hex(resolved)}\n")
                return resolved
    return None


def find_game_instance(h_process, base, size, status_callback=None, log_callback=None):
    patterns = [
        ("48 8B 0D ? ? ? ? 48 85 C9 0F 84", "xxx????xxxxx", 3),
        ("48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9", "xxx????xx????xxx", 3),
        ("48 8B 1D ? ? ? ? 48 85 DB 0F 84", "xxx????xxxxx", 3),
    ]

    for idx, (pattern, mask, inst_len) in enumerate(patterns):
        try:
            validate_pattern(pattern, mask)
        except ValueError:
            if log_callback:
                log_callback(f"Pattern {idx + 1} validation failed\n")
            continue
        if status_callback:
            status_callback(f"GameInstance pattern {idx + 1}/{len(patterns)}...")
        if log_callback:
            log_callback(f"  Trying pattern {idx + 1}: {pattern}\n")
        results = scan_module(h_process, base, size, pattern, mask, status_callback, stop_on_first=True)
        if log_callback:
            log_callback(f"  Found {len(results)} matches\n")
        for addr in results:
            if log_callback:
                log_callback(f"  Match at: {hex(addr)}, resolving RIP...\n")
            resolved = resolve_rip(h_process, addr, inst_len, log_callback)
            if resolved:
                if log_callback:
                    log_callback(f"  Successfully resolved to: {hex(resolved)}\n")
                return resolved
    return None


def find_player_controller(h_process, base, size, status_callback=None, log_callback=None):
    patterns = [
        ("48 8B 0D ? ? ? ? 48 85 C9 74 ? 48 8B 01", "xxx????xxxxxxxxx", 3),
        ("48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9 74", "xxx????xx????xxxx", 3),
        ("48 8B 3D ? ? ? ? 48 85 FF 74 ? 48 8B 07", "xxx????xxxxxxxxx", 3),
    ]

    for idx, (pattern, mask, inst_len) in enumerate(patterns):
        try:
            validate_pattern(pattern, mask)
        except ValueError:
            if log_callback:
                log_callback(f"Pattern {idx + 1} validation failed\n")
            continue
        if status_callback:
            status_callback(f"PlayerController pattern {idx + 1}/{len(patterns)}...")
        if log_callback:
            log_callback(f"  Trying pattern {idx + 1}: {pattern}\n")
        results = scan_module(h_process, base, size, pattern, mask, status_callback, stop_on_first=True)
        if log_callback:
            log_callback(f"  Found {len(results)} matches\n")
        for addr in results:
            if log_callback:
                log_callback(f"  Match at: {hex(addr)}, resolving RIP...\n")
            resolved = resolve_rip(h_process, addr, inst_len, log_callback)
            if resolved:
                if log_callback:
                    log_callback(f"  Successfully resolved to: {hex(resolved)}\n")
                return resolved
    return None


def find_local_player(h_process, base, size, status_callback=None, log_callback=None):
    patterns = [
        ("48 8B 0D ? ? ? ? 48 85 C9 74 ? 48 8B 41", "xxx????xxxxxxxxx", 3),
        ("48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ? E8", "xxx????xx????xx", 3),
        ("48 8B 1D ? ? ? ? 48 85 DB 74 ? 48 8B 43", "xxx????xxxxxxxxx", 3),
    ]

    for idx, (pattern, mask, inst_len) in enumerate(patterns):
        try:
            validate_pattern(pattern, mask)
        except ValueError:
            if log_callback:
                log_callback(f"Pattern {idx + 1} validation failed\n")
            continue
        if status_callback:
            status_callback(f"LocalPlayer pattern {idx + 1}/{len(patterns)}...")
        if log_callback:
            log_callback(f"  Trying pattern {idx + 1}: {pattern}\n")
        results = scan_module(h_process, base, size, pattern, mask, status_callback, stop_on_first=True)
        if log_callback:
            log_callback(f"  Found {len(results)} matches\n")
        for addr in results:
            if log_callback:
                log_callback(f"  Match at: {hex(addr)}, resolving RIP...\n")
            resolved = resolve_rip(h_process, addr, inst_len, log_callback)
            if resolved:
                if log_callback:
                    log_callback(f"  Successfully resolved to: {hex(resolved)}\n")
                return resolved
    return None


def dump_offsets(process_id, status_callback=None, log_callback=None):
    h_process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION, False, process_id)
    if not h_process:
        return None

    try:
        if status_callback:
            status_callback("Getting module information...")
        if log_callback:
            log_callback("Getting module information...\n")

        base, size, name = get_module_info(h_process)
        if not base:
            return None

        if log_callback:
            log_callback(f"Module: {name}\n")
            log_callback(f"Base: {hex(base)}, Size: {hex(size)}\n\n")

        offsets = {}

        if status_callback:
            status_callback("Searching GObjects...")
        if log_callback:
            log_callback("Searching GObjects...\n")
        gobjects = find_gobjects(h_process, base, size, status_callback, log_callback)
        if gobjects:
            offsets["GObjects"] = hex(gobjects)
            if log_callback:
                log_callback(f"Found GObjects: {hex(gobjects)}\n\n")
        elif log_callback:
            log_callback(f"GObjects not found\n\n")

        if status_callback:
            status_callback("Searching GNames...")
        if log_callback:
            log_callback("Searching GNames...\n")
        gnames = find_gnames(h_process, base, size, status_callback, log_callback)
        if gnames:
            offsets["GNames"] = hex(gnames)
            if log_callback:
                log_callback(f"Found GNames: {hex(gnames)}\n\n")
        elif log_callback:
            log_callback(f"GNames not found\n\n")

        if status_callback:
            status_callback("Searching GWorld...")
        if log_callback:
            log_callback("Searching GWorld...\n")
        gworld = find_gworld(h_process, base, size, status_callback, log_callback)
        if gworld:
            offsets["GWorld"] = hex(gworld)
            if log_callback:
                log_callback(f"Found GWorld: {hex(gworld)}\n\n")
        elif log_callback:
            log_callback(f"GWorld not found\n\n")

        if status_callback:
            status_callback("Searching GEngine...")
        if log_callback:
            log_callback("Searching GEngine...\n")
        gengine = find_gengine(h_process, base, size, status_callback, log_callback)
        if gengine:
            offsets["GEngine"] = hex(gengine)
            if log_callback:
                log_callback(f"Found GEngine: {hex(gengine)}\n\n")
        elif log_callback:
            log_callback(f"GEngine not found\n\n")

        if status_callback:
            status_callback("Searching GameInstance...")
        if log_callback:
            log_callback("Searching GameInstance...\n")
        game_instance = find_game_instance(h_process, base, size, status_callback, log_callback)
        if game_instance:
            offsets["GameInstance"] = hex(game_instance)
            if log_callback:
                log_callback(f"Found GameInstance: {hex(game_instance)}\n\n")
        elif log_callback:
            log_callback(f"GameInstance not found\n\n")

        if status_callback:
            status_callback("Searching PlayerController...")
        if log_callback:
            log_callback("Searching PlayerController...\n")
        player_controller = find_player_controller(h_process, base, size, status_callback, log_callback)
        if player_controller:
            offsets["PlayerController"] = hex(player_controller)
            if log_callback:
                log_callback(f"Found PlayerController: {hex(player_controller)}\n\n")
        elif log_callback:
            log_callback(f"PlayerController not found\n\n")

        if status_callback:
            status_callback("Searching LocalPlayer...")
        if log_callback:
            log_callback("Searching LocalPlayer...\n")
        local_player = find_local_player(h_process, base, size, status_callback, log_callback)
        if local_player:
            offsets["LocalPlayer"] = hex(local_player)
            if log_callback:
                log_callback(f"Found LocalPlayer: {hex(local_player)}\n\n")
        elif log_callback:
            log_callback(f"LocalPlayer not found\n\n")

        return offsets, name

    finally:
        kernel32.CloseHandle(h_process)


class OffsetDumperGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("UE Offset Dumper - Voices of the Void")
        self.root.geometry("800x600")

        self.process_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")

        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        ttk.Label(main_frame, text="Select Process:").grid(row=0, column=0, sticky=tk.W, pady=5)

        process_frame = ttk.Frame(main_frame)
        process_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)

        self.process_combo = ttk.Combobox(process_frame, textvariable=self.process_var, width=60, state="readonly")
        self.process_combo.grid(row=0, column=0, padx=5)

        refresh_btn = ttk.Button(process_frame, text="Refresh", command=self.refresh_processes)
        refresh_btn.grid(row=0, column=1, padx=5)

        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=10)

        dump_btn = ttk.Button(button_frame, text="Dump Offsets", command=self.dump_offsets)
        dump_btn.grid(row=0, column=0, padx=5)

        clear_btn = ttk.Button(button_frame, text="Clear Log", command=lambda: self.text_area.delete(1.0, tk.END))
        clear_btn.grid(row=0, column=1, padx=5)

        status_label = ttk.Label(main_frame, textvariable=self.status_var, foreground="blue")
        status_label.grid(row=3, column=0, columnspan=3, pady=5)

        self.text_area = tk.Text(main_frame, height=25, width=90, font=("Consolas", 9))
        self.text_area.grid(row=4, column=0, columnspan=3, pady=10, sticky=(tk.W, tk.E, tk.N, tk.S))

        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.text_area.yview)
        scrollbar.grid(row=4, column=3, sticky=(tk.N, tk.S))
        self.text_area.configure(yscrollcommand=scrollbar.set)

        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(4, weight=1)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)

        self.refresh_processes()

    def refresh_processes(self):
        self.status_var.set("Scanning for processes...")
        self.root.update()

        processes = get_processes()
        if processes:
            process_list = [f"{name} (PID: {pid})" for pid, name in processes]
            self.process_combo['values'] = process_list
            if process_list:
                self.process_combo.current(0)
            self.status_var.set(f"Found {len(processes)} process(es)")
        else:
            self.process_combo['values'] = []
            self.status_var.set("No processes found")

    def update_status(self, text):
        self.status_var.set(text)
        self.root.update()

    def update_log(self, text):
        self.text_area.insert(tk.END, text)
        self.text_area.see(tk.END)
        self.root.update()

    def dump_offsets(self):
        selection = self.process_var.get()
        if not selection:
            messagebox.showerror("Error", "Please select a process")
            return

        try:
            pid = int(selection.split("(PID: ")[1].split(")")[0])
        except:
            messagebox.showerror("Error", "Invalid process selection")
            return

        self.text_area.delete(1.0, tk.END)
        self.status_var.set("Dumping offsets...")
        self.update_log("=" * 60 + "\n")
        self.update_log("UN​​​​​​​​​​​​​​​​REAL ENGINE OFFSET DUMPER\n")
self.update_log("=" * 60 + "\n\n")
self.root.update()

code
Code

download

content_copy

expand_less
result = dump_offsets(pid, self.update_status, self.update_log)

    if not result:
        messagebox.showerror("Error", "Failed to dump offsets. Run as Administrator!")
        self.status_var.set("Failed")
        return

    offsets, module_name = result

    if not offsets:
        self.update_log("\n" + "=" * 60 + "\n")
        self.update_log("RESULT: No offsets found\n")
        self.update_log("=" * 60 + "\n")
        messagebox.showwarning("Warning", "No offsets found! Make sure game is fully loaded.")
        self.status_var.set("No offsets found")
        return

    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_file = os.path.join(script_dir, "offsets.json")

    self.update_status("Saving offsets...")
    self.update_log(f"\nSaving offsets to {output_file}...\n")

    with open(output_file, 'w') as f:
        json.dump(offsets, f, indent=4)

    output_text = "\n" + "=" * 60 + "\n"
    output_text += "SUCCESS! FOUND OFFSETS:\n"
    output_text += "=" * 60 + "\n"
    for name, offset in sorted(offsets.items()):
        output_text += f"{name:20s}: {offset}\n"
    output_text += "\n" + "=" * 60 + "\n"
    output_text += f"Saved to: {output_file}\n"

    self.text_area.insert(tk.END, output_text)
    self.text_area.see(tk.END)

    self.status_var.set(f"Successfully dumped {len(offsets)} offset(s)")
    messagebox.showinfo("Success", f"Offsets dumped successfully!\n\nFound: {len(offsets)} offset(s)\nSaved: {output_file}")
if name == "main":
root = tk.Tk()
app = OffsetDumperGUI(root)
root.mainloop()


