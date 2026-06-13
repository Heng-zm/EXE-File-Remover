# 🛡️ EXE Remover Bot — Setup Guide

Automatically deletes `.exe` files from Telegram groups.  
Supports **English** 🇬🇧 and **Khmer** 🇰🇭 languages.

*Upgraded with robust JobQueue memory management, non-blocking admin broadcast routines, and local state persistence.*

---

## ⚙️ Prerequisites

- Python 3.10 or newer
- A Telegram Bot Token from [@BotFather](https://t.me/BotFather)

---

## 🚀 Quick Start

### 1. Get a Bot Token

1. Open Telegram → search `@BotFather`
2. Send `/newbot` and follow the prompts
3. Copy the token (looks like `123456:ABC-DEF...`)

### 2. Configure Environment

1. Rename `.env.example` to `.env` (or create a new `.env` file).
2. Insert your bot token inside the `.env` file:
   ```ini
   BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrSTUvwxYZ# EXE-File-Remover
