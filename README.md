# 🔐 Secret Keeper: A Fully Local, Client-Side Encrypted Vault

<div align="center">
  <img src="https://raw.githubusercontent.com/Mahdiyasser/secret-keeper/refs/heads/main/icon-512.png" alt="Secret Keeper Logo" width="150" height="150" />
</div> 

Secret Keeper is a fully client-side browser vault that stores your sensitive data locally and securely using AES-256 encryption via CryptoJS. Everything happens on your device — no servers, no tracking, no data leaks.

---

## ✨ Features

### 🔒 Client-Side Encryption
All encryption/decryption is performed locally in your browser using **AES-256 (CryptoJS)**.  
Your master key never leaves your device.

### 💾 Fully Local Storage
Encrypted data is stored **exclusively in localStorage**, ensuring:
- Full privacy
- Online access via the offical website and its app "https://keeper.mahdiyasser.site"
- Offline access via the offical offline app that can be downloaded from "https://app-keeper.mahdiyasser.site"
- Zero backend dependency  

### 🔑 Master Key Protection
A single secure master key protects your entire vault.  
Lose it = vault is gone. **No recovery**, by design.

### 📦 Organized Secret Types
Store multiple types of encrypted entries:
- Credentials (username/password)
- Secure notes
- Contacts / addresses
- Encrypted links

### 🔁 Import/Export
Backup or transfer your vault using a single encrypted export file.

### 🌗 Dark Mode
Toggle between light and dark themes.

---

## 🚀 Getting Started

Secret Keeper is 100% client-side. Use it however you want:

---

### **1. Live Website (Recommended)**
https://keeper.mahdiyasser.site

---

### **2. Self-Host**

Clone the repo and deploy it to any static host.

⚠️ **Important Self-Hosting Note:**  
The root directory version stores data in the localStorage of  
https://storage.mahdiyasser.site using an invisible iframe, preventing accidental losses when clearing browser history.

For **true self-hosting**, use ONLY the files inside **/self-host**.

```bash
# Clone the repository
git clone https://github.com/Mahdiyasser/secret-keeper

# Navigate to the self-host directory
cd secret-keeper/self-host
```

Deploy `/self-host` to your hosting provider or your own server.

---

### **3. Local File Execution**

Open `index.html` inside `/self-host`.

Note: Some browsers restrict storage on `file://`. Using a small local server like apache2 works better.

---

## ⚙️ Development & Technology

- HTML, CSS, JavaScript  
- CryptoJS (AES-256)  
- No external APIs  
- 100% local encryption  

---

## 📝 Usage

1. Open the app  
2. Set a strong master key (no recovery)  
3. Add/delete encrypted entries there is no editing  
4. Export your vault regularly 

---

## 🤝 Contributing
Contact: https://mahdiyasser.site/contact  
Or 
open a GitHub issue.

---

Made with ⚡ by **Mahdi Yasser**
