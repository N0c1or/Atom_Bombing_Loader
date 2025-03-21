# Atom_Bombing_Loader🚀
"Atom Bombing" + "Early Bird" Bypass EDR

📖 **简介**  
这是一个在 Windows 平台上实现的 shellcode 注入实验项目。Early Bird APC 注入方法和 Atom Bombing 原子表加载。

---

✨ **特性**  
- 🔒 **XOR 加密**: 使用简单 XOR 密钥对数据进行加密，增加混淆效果。  
- 📋 **全局原子表存储**: 将 shellcode 分块存储到 Windows 全局原子表中。  
- 💉 **Early Bird APC 注入**: 通过 APC 队列将代码注入到 `RuntimeBroker.exe` 进程。  
- 🖥️ **Windows API 调用**: 利用底层函数如 `NtWriteVirtualMemory` 和 `VirtualAllocEx`。

---

🛠️ **使用方法**  
1. 📦 确保安装 Rust 环境-rustlang、cargo。  
2. 📂 准备一个 shellcode 文件,并使用加密python脚本对shellocde进行简单的xor加密。  
3. ▶️ 在具备权限的 Windows 系统上编译并运行程序。  

---

⚠️ **免责声明**  
本项目仅用于研究目的，旨在探索 Windows 底层编程技术。请勿用于生产环境或恶意用途。作者不对任何滥用或损害负责。
