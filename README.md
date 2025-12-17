# 🔒 Cryptify

<div align="center">
  <img src="logo.png" alt="Cryptify Logo" width="200" />
  
  <br />
  
  <h3>AES Data Encryption & File Security Tool</h3>
  <h4>"Lock it Down"</h4>

  <p>
    A robust utility for securing your files with AES encryption, 
    integrated compression, and secure key management.
  </p>

  <a href="#features"><strong>Features</strong></a> · 
  <a href="#installation"><strong>Installation</strong></a> · 
  <a href="#usage"><strong>Usage</strong></a> · 
  <a href="#contributing"><strong>Contributing</strong></a>
</div>

---

## 📖 Overview

**Cryptify** is a security tool designed to protect sensitive data through Advanced Encryption Standard (AES) encryption. Unlike simple encryptors, Cryptify includes a dedicated **Key Manager** and a **Compression/Decompression** module to optimize storage while securing your files.

Whether you are on Windows or Linux, Cryptify provides a native experience for securing your digital assets.

## ✨ Features

* **⚛️ Post-Quantum Security**: Implements **ML-KEM** (Module-Lattice-Based Key-Encapsulation Mechanism) for quantum-resistant key exchange.
* **🛡️ AES-256 Encryption**: Secures file content using the strongest industry-standard symmetric encryption.
* **🛡️ AES Encryption**: Secures files using industry-standard AES encryption algorithms.
* **🔓 Reliable Decryption**: Restores encrypted data to its original state without data loss.
* **📦 Compression Support**: Automatically compresses files before encryption to save space (using `zstd`).
* **🔑 Secure Key Management**: Dedicated module to generate, save, and load encryption keys safely.
* **🖥️ Cross-Platform**: Native installers available for **Windows** and **Linux (Debian/Kali/Ubuntu)**.

---

## 🚀 Installation

Choose the installation method for your operating system.

### 🪟 Windows (Installer)

1.  **Download**: Go to the [Releases](https://github.com/VeerSingh0001/Cryptify/releases) page.
2.  **Get the Setup**: Download the latest `Cryptify_Setup.exe`.
3.  **Install**: Double-click the file to launch the installation wizard.
4.  **Run**: Once installed, you can launch **Cryptify** directly from your Desktop or Start Menu.
    > *Note: If Windows SmartScreen appears, click "More Info" -> "Run Anyway" (this happens with new open-source software).*

### 🐧 Linux (Debian/Ubuntu/Kali)

1.  **Download**: Go to the [Releases](https://github.com/VeerSingh0001/Cryptify/releases) page and download the latest `.deb` file (e.g., `cryptify_1.0.0_amd64.deb`).
2.  **Install via Terminal**:
    Open your terminal in the download folder and run:
    ```bash
    sudo apt install ./cryptify_*_amd64.deb
    ```
3.  **Run**: You can now launch the tool by typing `cryptify` in the terminal or finding it in your application menu.

### 🐍 Run from Source (For Developers)

If you prefer to run the raw Python code or contribute to the project:

1.  **Clone the Repo**: `git clone https://github.com/VeerSingh0001/Cryptify.git`
2.  **Install Requirements**:
     ```bash
     sudo apt-get update
     sudo apt-get install -y cmake gcc ninja-build libssl-dev git python3-dev
     cd /tmp
     git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git
     cd liboqs
     mkdir build && cd build
     cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON ..
     ninja
     sudo ninja install
     sudo ldconfig
     pip install -r requirements.txt
     ```
4.  **Run**: `python main.py`

---

## 💡 Usage

### 1. Generating a Key
Before encrypting any files, generate a secure key. This is done automatically on first launch in the GUI, or manually via:
```bash
# GUI
Click "Generate Key" in the Side Bar.

# CLI (if running from source)
python cli.py and then select 1.
```
⚠️ Important: Keep your key file safe. If you lose it, your data cannot be decrypted.    

2. Encrypting a File    
  a) Open Cryptify.    
  b) Select the Encrypt tab.    
  c) select key id.    
  d) Enter assosiated password to key.    
  e) Choose your target file(s).      
  f) Enter output file name (Optional: Only in single file mode).      
  g) Click Encrypt.      

3. Decrypting a File
  a)Open Cryptify.      
  b) Select the Decrypt tab.    
  c) Select encrypted file(s).
  d) Select key id.
  f) Enter assosiated password for key.
  g) Enter output file name(OPtional: Only in single file mode).      
  h) Click Decrypt.    

🤝 Contributing
Contributions are welcome!

Fork the repository.

Create a feature branch (git checkout -b feature/NewFeature).

Commit changes (git commit -m 'Add NewFeature').

Push to branch (git push origin feature/NewFeature).

Open a Pull Request.

📄 License
Distributed under the GPL-3.0 License. See LICENSE for more information.

<div align="center"> <sub>Built with ❤️ by <a href="https://github.com/VeerSingh0001">VeerSingh0001</a></sub> </div>
