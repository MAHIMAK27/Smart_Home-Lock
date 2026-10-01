# 🔐 IoT Smart Home Security

### Secure Communication • Authentication • Access Control • Attack Detection

**Cryptography & Network Security (BCS703)**

A practical implementation of a secure communication and authentication framework for IoT-based smart homes. The project demonstrates how smart devices can securely communicate with a Central Hub using modern cryptographic techniques while preventing unauthorized access, message tampering, replay attacks, rogue devices, and privilege escalation.

<img width="1536" height="1024" alt="ChatGPT Image Oct 1, 2026, 03_23_10 PM" src="C:\Users\hp\Downloads\hi">

## 🏠 Project Overview

Smart homes consist of interconnected devices such as smart locks, smart lights, security cameras, and motion sensors. Without proper security, attackers can intercept, modify, replay, or inject commands into the network.

This project implements a secure IoT environment where devices are authenticated, communication is encrypted, and every command is verified by a Central Hub before execution.

### 🔒 Security Flow

```text
        Smart Home Devices
                │
                ▼
       ┌─────────────────┐
       │   Central Hub   │
       │                 │
       │ Authentication  │
       │ Authorization   │
       │ Replay Defense  │
       │ Certificate CA  │
       └────────┬────────┘
                │
        Secure Communication
                │
       ┌────────┼─────────┐
       ▼        ▼         ▼
   🔒 Lock   💡 Light   📷 Camera
                         │
                         ▼
                     🚨 Sensor



