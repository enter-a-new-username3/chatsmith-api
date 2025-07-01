# chatsmith-api(Unofficial Client)
Reverse engineered API of Chat Smith app on Play Store

⚠️ **This code was written in a rush. It's messy, inefficient, and not production-grade. You've been warned.** ⚠️

## Overview

This is an unofficial Python script that interfaces with the **Chat Smith** app's backend (hosted by `vulcanlabs.co`). It replicates the basic flow of authentication and chatting using the app's API, including token handling and RSA encryption for authorization headers.

The code was originally written quickly for reverse engineering, testing, or educational purposes — not for long-term maintainability or clean architecture.

---

## 🔧 Features

- Emulates device identity and app headers.
- Retrieves an access token from the Chat Smith API.
- Sends user messages and receives responses from the AI model.
- Supports system prompts and conversation history.⚠️ **This code was written in a rush. It's messy, inefficient, and not production-grade. You've been warned.** ⚠️

## 📚 Educational Use Only

This project is intended **strictly for educational and research purposes**. It demonstrates how to reverse engineer a basic API flow and implement encrypted authorization headers using Python.

> **If you are a representative of Vulcan Labs and wish to have this repository taken down, please open an issue or contact the maintainer. It will be removed without quickly.**

---

## 🧠 Overview

This is an unofficial Python script that interfaces with the **Chat Smith** app's backend (hosted by `vulcanlabs.co`). It replicates the basic flow of authentication and chatting using the app's API, including token handling and RSA encryption for authorization headers.

The code was originally written quickly with minimal attention to best practices. Do not treat this as a finished or secure implementation.

---

## 🔧 Features

- Emulates device identity and app headers
- Retrieves an access token from the Chat Smith API
- Sends user messages and receives responses from the AI model
- Supports system prompts and conversation history
- Includes custom RSA encryption logic for secure communication headers

---

## ⚠️ Caveats & Warnings

- **Code quality is poor**: Thrown together rapidly with minimal structure
- **Hardcoded public key**: The RSA public key is embedded and loosely validated
- **Lack of modularity**: All logic is in one file
- **Error handling is limited**: No robust failover or retry logic
- **No dependency isolation**: No `requirements.txt` or virtualenv

---

## 🐍 Requirements

- Python 3.7+
- Required libraries:
  - `cryptography`
  - `requests`

Install via:

```bash
pip install cryptography requests
