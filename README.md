# Totpl - вирустотальный сканер API 🏱🏹

## 🚀 Обзор

ToTPL is a Python-based command-line tool that interacts with the VirusTotal API to scan URLs and files for potential threats. It also allows users to check their API key limits.

## ✨ Features

- **🔍 Scan URLs**: Submit a URL to VirusTotal for analysis.
- **🦠 Scan Files**: Upload a file to check for malware.
- **🔑 Check API Limits**: Retrieve information about your VirusTotal API key usage.
- **🔀 Change API Key**: Easily switch between different VirusTotal API keys.

## 👅 Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/Ratbb1/ToTPL
   CD Totpl
   ```
2. Install the required dependencies:
   ```sh
   PIP установка -R TEDS.TXT
   ```
   If the command above doesn't work (e.g., on some Linux systems), use:
   ```sh
   Установка PIP3-Break-System-Packages -R TEDS.TXT
   ```

## 🛠 Usage

Run the script using Python:
```sh
python3 ToTPL.py
```

### 📌 Main Menu

Upon running, you will see an interface with the following options:

1⃣ Scan URL 🔍\
2⃣ Scan files for viruses 🦠\
3⃣ Check API key limits 🔑\
4⃣ Change API key 🔀\
5⃣ Exit from ToTPL 🚪

### 🔑 API Key

To use the tool, you need a VirusTotal API key. You can obtain one by registering at [Вирустотальный](https://www.virustotal.com/).

## ⚠️ Error Handling

- 🚫 Incorrect input or missing API key will trigger error messages.
- ⏳ API limit exceeded responses are handled properly.

## 📝 Примечания

- 😊 If you have an idea how I can improve the code or you can give advice, write to me! 
