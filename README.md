# HooksBox - Advanced Anti-Detection Sandbox for Windows

**HooksBox** is a sophisticated sandbox environment protection system designed to conceal virtualization artifacts from malware analysis. By leveraging API hooking techniques, it masks VirtualBox (and other virtualization software) fingerprints, creating a more realistic environment for security research and malware analysis.

## 🛡️ The Problem

Modern malware employs sophisticated detection techniques to identify virtualized or sandboxed environments. When such environments are detected, malware often alters its behavior, either ceasing malicious activities or deploying evasion tactics. This compromises security analysis and research efforts.

## ✨ The Solution

HooksBox implements a proactive defense mechanism that intercepts and modifies system API calls in real-time, effectively "hiding" the sandbox from prying malware. It acts as a digital camouflage for your analysis environment.

## 🔧 Key Features

- **API Hooking Engine**: Real-time interception of critical Windows API functions
- **VirtualBox Artifact Masking**: Conceals registry keys, files, processes, and other VirtualBox-specific indicators
- **Minhook Integration**: Utilizes the powerful [MinHook library](https://github.com/TsudaKageyu/minhook) for robust API hooking
- **Customizable Hooks**: Easily extendable to cover additional detection vectors
- **Lightweight Design**: Minimal performance impact on the host system

## 📊 Profiles of Operation
HooksBox supports three configurable operational profiles to balance between detection coverage, performance, and stability:
- **Minimal profile:** registry + file system + basic network indicators; focused on stability.
- **Advanced profile:** adds WMI/devices; applicable to most mass detection methods.
- **Enhanced profile:** includes a kernel driver for low-level indicators and timings; maximum coverage.

## 🏗️ Architecture

<img width="1314" height="713" alt="image" src="https://github.com/user-attachments/assets/46bf1f22-a8a8-4af4-9d95-4d967526f696" />

## 🚀 Getting Started

### Prerequisites
- Windows 10/11 (64-bit)
- Visual Studio 2019 or newer with C++ support
- Administrative privileges (for driver installation)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/hooksbox.git
   cd hooksbox
   ```
2. **Build with Visual Studio:**
  - Open HooksBox.sln in Visual Studio
  - Select Release x64 configuration
  - Build the solution
    
3. **Use Launcher for interactive experience**

## 🔬 Testing the Protection
To verify HooksBox's effectiveness, you can use these detection tools:

- [Al-Khaser](https://github.com/ayoubfaouzi/al-khaser) - Anti-VM, anti-sandbox, and anti-debugging tool
- [VMDetect](https://github.com/PerryWerneck/vmdetect/) - Virtual machine detection toolkit
- [pafish](https://github.com/a0rtega/pafish) - Paranoid Fish - demonstration tool for detecting analysis environments

## 📁 Project Structure

```bash
HooksBox/
├── HooksBox/
│   ├── filters/         
│   ├── hooks/           # Individual API hook implementations
│   │   ├── registry/    # Registry-related hooks
│   │   ├── filesystem/  # File system hooks
│   │   ├── wmi/         # WMI hooks
│   │   └── system/      # System information hooks
│   └── utils/           # Utilities and helpers
├── Launcher
└── tools/
    └── minhook/         # MinHook submodule
```

## 🧠 Future Enhancements
Planned features for upcoming releases:

- [ ] Extended Virtualization Support: VMware, Hyper-V, and QEMU masking
- [ ] Kernel-mode Components: Driver-level hooking for deeper protection
- [ ] Cross-platform Compatibility: Linux sandbox protection modules

## ⚠️ Disclaimer & Legal

Important: This tool is intended for:

- Legitimate security research
- Malware analysis in controlled environments
- Educational purposes
- Improving sandbox and virtualization security

Do not use this software for:

- Bypassing security measures on systems you don't own
- Illegal activities
- Distributing malware

The author assume no liability for any misuse of this software.
