# Zynq-7000 Hardware AES-256 CTR Ethernet Gateway

This repository contains the design, implementation, and verification files for the **Zynq-7000 Hardware AES-256 CTR Ethernet Gateway**, developed as part of the **ASIC & FPGA SoC Design Internship** at the **Department of Electronics, CUSAT**.

The system implements a high-throughput network cryptographic accelerator. It utilizes a custom-designed **15-stage pipelined AES-256 core** implemented in the FPGA Programmable Logic (PL) fabric and integrates it with a bare-metal firmware server running on the ARM Cortex-A9 Processing System (PS) via **AXI DMA** and **Gigabit Ethernet (lwIP)**.

---

## Key Features
*   **Hardware Acceleration:** 15-stage fully pipelined AES-256 core with a latency of 15 clock cycles and a throughput of **1 block (128-bit) per clock cycle** (once the pipeline is full).
*   **DMA Streaming:** High-performance data streaming between CPU memory (DDR) and the hardware core using **AXI DMA** simple transfers.
*   **lwIP TCP/IP Server:** Implements a bare-metal network server (static IP `192.168.1.10`, listening on Port `7`) using the lightweight IP stack.
*   **Anti-Tampering Security:** Integrated hardware **Zeroization** logic. Asserting the physical `panic_button` instantly wipes all cryptographic keys and IV register values to `32'h0` in a single clock cycle.
*   **Automated Verification:** Custom interactive Python utility (`aes256_tool.py`) supporting single/bulk file and folder encryption and decryption with automatic metadata (Key/IV) storage and lookup.

---

## Directory Structure
*   `rtl/`: Synthesizable Verilog source code files for the AES-256 CTR IP core:
    *   `aes256_ctr_top.v`: Top-level IP wrapper exposing AXI-Lite control and AXI-Stream data interfaces.
    *   `aes256_ctr_core.v`: Controller managing the 128-bit counter block increments.
    *   `aes256_ctr_axi_stream.v`: AXI4-Stream serializer/deserializer wrapper (converts 32-bit streaming words to 128-bit blocks).
    *   `aes256_encrypt_pipeline.v`: 15-stage unrolled pipelined encryption datapath.
    *   `aes256_key_expansion.v`: Hardware expansion of the 256-bit key into 15 round keys.
    *   `aes_round_enc.v` & `aes_sbox.v`: Standard AES round transformations and ROM S-Box lookup.
*   `host/`: Host-side verification scripts:
    *   `aes256_tool.py`: Interactive CLI tool supporting bulk file and directory operations.
    *   `aes256_client.py`: Reference benchmark and loop-back verification script.
*   `AES256/`: Vivado IP Integrator project files and Vitis workspace directories (containing the board firmware source `main.c`).
*   `Project_Report.docx`: The formal, fully formatted internship project report.

---

## System Architecture

The Processing System (PS) and Programmable Logic (PL) components communicate using two primary interfaces:
1.  **AXI4-Lite (Control Path):** Used to load the 256-bit key and 128-bit IV, check status registers, and trigger processing.
2.  **AXI4-Stream (Data Path):** Streams data packets between the AXI DMA core and the AES IP core at 100 MHz.

![Vivado Block Design Diagram](Diagram%20-%20Block%20Design.png)

---

## Getting Started

### 1. Hardware & Firmware Setup
1.  Open the Vivado project (`AES256/AES256.xpr`) in Xilinx Vivado.
2.  Generate the Bitstream and export the hardware wrapper (`design_1_wrapper.xsa`).
3.  Open Xilinx Vitis, import the application component (`AES256/app_component`), load the bitstream, and run the compiled ELF executable on the Zynq board.
4.  Connect your host PC to the Zynq board via an Ethernet cable.

### 2. Network Configuration
Set a static IP on your host PC's network adapter:
*   **IP Address:** `192.168.1.1` (or any address on the `192.168.1.X` subnet except `192.168.1.10`).
*   **Subnet Mask:** `255.255.255.0`
*   **Default Gateway:** `192.168.1.1`

Verify the link by pinging the board:
```cmd
ping 192.168.1.10
```

![Network Ping Test](Ping%20-%20CMD.png)

### 3. Running the Host Utility
Make sure Python 3 is installed, then run the utility tool:

*   **Fully Interactive Mode:**
    ```powershell
    python host/aes256_tool.py
    ```
    This will prompt you for the target file/folder path and operation.

*   **Bulk Folder Encryption:**
    ```powershell
    python host/aes256_tool.py "C:\path\to\input_folder" -m encrypt
    ```
    *Creates encrypted files and key parameter `.txt` metadata files in `C:\Users\hp\Downloads\outputs\encrypted`.*

    ![Encryption CMD Output](Encryption%20-%20CMD.png)

*   **Bulk Folder Decryption:**
    ```powershell
    python host/aes256_tool.py "C:\Users\hp\Downloads\outputs\encrypted" -m decrypt
    ```
    *Decrypts files using stored metadata and outputs restored files to `C:\Users\hp\Downloads\outputs\decrypted`.*

    ![Decryption CMD Output](Decryption%20-%20CMD.png)

