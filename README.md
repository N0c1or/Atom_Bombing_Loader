# Atom_Bombing_Loader🦄
" Atom Bombing " + " Early Bird " Bypass EDR

📖 **项目简介**  
这是一个在 Windows 平台上实现的 shellcode 注入实验项目。结合了`Early Bird` APC 注入技术和 `Atom Bombing` 技术全局原子表加载shellcode。

---

✨ **技术特性**  
- 🔒 **XOR 加密**: 使用简单 XOR 密钥对shellcode和敏感函数进行加密，以绕过EDR静态检测。  
- 📋 **全局原子表存储**: 将 shellcode 分块存储到 Windows 全局原子表中,再通过原子表读取进行重组。  
- 💉 **Early Bird APC 注入**: 通过 APC 队列将代码注入到 `Dism.exe` 进程中，将shellcode加载过程混淆到程序初始化的过程中，规避EDR检测。  
- 🖥️ **Windows API 调用**: 利用`syscall`技术和动态加载API来完全绕过用户态HOOK。

---

💡 **免杀效果**  
- ✔ **C2框架**: 使用较为冷门的Havoc框架，生成默认的shellcode，并进行简单的xor加密。  
- ✔ **某60**: 代码执行、添加用户、提升本地用户为管理员组、dump lsass等敏感操作均未告警(核晶模式也已通过)。  
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
-**演示视频：** `https://www.bilibili.com/video/BV14tX6YhEeu/`

**2025.3.23**(仅测试，未发布)
- 修改注入目标，避开被重度监控的系统程序。
- 对加载方式和函数进行了轻微的调整，修复了部分payload无法正常执行的问题。
- **已失效-已成功完美bypass数字卫士核晶**
- 使用默认profile的Cobaltstrike生成的无阶shellcode做到数字卫士核晶环境下全部操作无感。
- **疑问：免杀到底是技术活还是运气活？**

**2025.3.26**
- 函数调用通过unhhok/syscall结合绕过EDR钩子。
- 修改函数为常见函数, 如`QueueuserAPC`等。
- 更好的内存类型管理：从RW写入payload，随后以RX的内存类型执行shellcode，避免RWX类型的内存被EDR严格监控(点名针对卡巴斯基)。
- 完美bypass数字卫士核晶。
- 合影留念![bypass](https://github.com/user-attachments/assets/eb8f0500-0768-44c4-bcef-032058a5fdd2)
![AV_Scan](https://github.com/user-attachments/assets/d0099812-5561-4419-8e8a-792292ad26af)


**2025.3.31**
- 增加反调试机制——检测debugapi调用、启动计时器检测操作间隔。
- 增加简单反沙盒机制，验证运行内存大小和前端焦点窗口。
- 增加简单逻辑炸弹，通过快速向内存写入大量数据导致程序崩溃，若触发反调试或反沙盒以及未分离读取到shellcode都会直接运行逻辑炸弹，避免直接调用exit类函数。
- 补充说明：逻辑炸弹具有循环退出逻辑，该逻辑存在但永不触发。
- 免杀效果不变，反沙盒效果大幅提高。


---

