# Atom_Bombing_Loader🚀
" Atom Bombing " + " Early Bird " Bypass EDR

📖 **项目简介**  
这是一个在 Windows 平台上实现的 shellcode 注入实验项目。结合了`Early Bird` APC 注入技术和 `Atom Bombing` 技术全局原子表加载shellcode。

---

✨ **技术特性**  
- 🔒 **XOR 加密**: 使用简单 XOR 密钥对shellcode和敏感函数进行加密，以绕过EDR静态检测。  
- 📋 **全局原子表存储**: 将 shellcode 分块存储到 Windows 全局原子表中,再通过原子表读取进行重组。  
- 💉 **Early Bird APC 注入**: 通过 APC 队列将代码注入到 `RuntimeBroker.exe` 进程中，将shellcode加载过程混淆到程序初始化的过程中，规避EDR检测。  
- 🖥️ **Windows API 调用**: 利用底层函数如 `NtWriteVirtualMemory` 和 `NtQueueApcThread`等其他冷门、底层API(尝试过使用Zw系列API，但效果并不理想，利用链有待研究)。

---

💡 **免杀效果**  
- ✔ **C2框架**: 使用较为冷门的Havoc框架，生成默认的shellcode，并进行简单的xor加密。  
- ✔ **某60**: 代码执行、添加用户、提升本地用户为管理员组、dump lsass等敏感操作均未告警(核晶模式下未通过，暂无思路，尚待研究)。  
- ✔ **某绒安全6.0**: 经过简单测试所有行为操作基本都无感。  
- ✔ **winXows DefXnder**: 暂未测试，待补充。
  
---

🛠️ **使用方法**  
1. 📦 确保安装 Rust 环境-rustlang、cargo。  
2. 📂 准备一个 shellcode 文件,并使用提供的加密python脚本对shellocde进行简单的xor加密，密钥可自行提高复杂度，代码仅作为演示。  
3. ▶️ 打开项目目录，`cargo build --release`编译即可，编译好的二进制文件于`./target/release/atom_bombing_inject_loader.exe`，资源文件可自行修改build.rs(添加图标、信息等)，编译过程需确保网络通常(编译需要下载Windows库)。  

---

⚠️ **免责声明**  
本项目仅用于研究学习目的，请勿用于非法用途。作者不对任何滥用或损害负责。

---
**2025.3.22**
开源(简介版本)

*2025.3.23*
- 修改注入目标，避开被重度监控的系统程序。
- 对加载方式和函数进行了轻微的调整，修复了部分payload无法正常执行的问题。
- **已成功完美bypass数字卫士核晶**
- 使用默认profile的Cobaltstrike生成的无阶shellcode做到数字卫士核晶环境下全部操作无感。
- **疑问：免杀到底是技术活还是运气活？**
- **下个目标点**： 
    1、修改XOR加密为AES加密，再次增加逆向分析难度。
    2、尝试使用OLLVM进行混淆编译，再再次增加逆向分析难度。
    3、思考：如何在注入行为下尝试hookC2的sleep函数并做到更好的sleepmask技术(汇编真学不下去)。
    4、最后的目标(暂时)：打包成框架发布(再也不写GUI了)。
