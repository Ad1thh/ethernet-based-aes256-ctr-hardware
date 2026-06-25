import socket
import time
import os
import sys

# Configuration
BOARD_IP = "192.168.1.10"
BOARD_PORT = 7
DEFAULT_FILE_SIZE_KB = 256 # Default file size to send if no file provided

def print_banner():
    print("====================================================")
    print("    Zynq-7000 Hardware AES-256 CTR Client Terminal  ")
    print("    ASIC & FPGA SoC Design Internship - CUSAT        ")
    print("====================================================")

def generate_random_text(size_bytes):
    # Generates readable text for demonstration
    chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \n"
    return bytes(chars[i % len(chars)] for i in range(size_bytes))

def pad_data(data):
    # Pad to a multiple of 16 bytes for AES block size
    padding_len = (16 - (len(data) % 16)) % 16
    if padding_len > 0:
        data = data + b" " * padding_len
    return data

def run_aes_transaction(mode, key, iv, data):
    # Establish connection
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10.0)
        s.connect((BOARD_IP, BOARD_PORT))
    except Exception as e:
        print(f"[-] Error connecting to Zynq board at {BOARD_IP}:{BOARD_PORT} - {e}")
        sys.exit(1)

    # 1. Build Header: Mode (1B) | Key (32B) | IV (16B) | Size (4B)
    file_size = len(data)
    header = bytearray()
    header.append(mode)
    header.extend(key)
    header.extend(iv)
    header.extend(file_size.to_bytes(4, byteorder='big'))

    # 2. Send Header + Data
    try:
        s.sendall(header)
        s.sendall(data)
    except Exception as e:
        print(f"[-] Error sending data: {e}")
        s.close()
        return None, None

    # 3. Receive Response: Elapsed Time (4B) + Data (file_size B)
    try:
        # Read 4-byte time header
        time_bytes = bytearray()
        while len(time_bytes) < 4:
            chunk = s.recv(4 - len(time_bytes))
            if not chunk:
                raise ConnectionResetError("Connection closed while receiving time header")
            time_bytes.extend(chunk)
        elapsed_us = int.from_bytes(time_bytes, byteorder='big')

        # Read output file data
        out_data = bytearray()
        while len(out_data) < file_size:
            chunk = s.recv(file_size - len(out_data))
            if not chunk:
                raise ConnectionResetError("Connection closed while receiving output data")
            out_data.extend(chunk)
    except Exception as e:
        print(f"[-] Error receiving response: {e}")
        s.close()
        return None, None

    s.close()
    return elapsed_us, bytes(out_data)

def draw_chart(sw_enc, hw_enc, sw_dec, hw_dec):
    # Draw simple ASCII chart to compare throughputs
    labels = ["SW Encrypt", "HW Encrypt", "SW Decrypt", "HW Decrypt"]
    rates = [sw_enc, hw_enc, sw_dec, hw_dec]
    max_rate = max(rates) if max(rates) > 0 else 1.0
    
    print("\nThroughput Comparison (Mbps):")
    print("----------------------------------------------------------------------")
    for label, rate in zip(labels, rates):
        bar_len = int((rate / max_rate) * 40)
        bar = "█" * bar_len
        print(f"{label:12} | {rate:7.2f} Mbps | {bar}")
    print("----------------------------------------------------------------------")

def main():
    print_banner()

    # Determine input data
    input_file_path = None
    if len(sys.argv) > 1:
        input_file_path = sys.argv[1]

    if input_file_path:
        if not os.path.exists(input_file_path):
            print(f"[-] File not found: {input_file_path}")
            return
        with open(input_file_path, "rb") as f:
            raw_data = f.read()
        print(f"[+] Loaded file: {input_file_path} ({len(raw_data)} bytes)")
    else:
        size_bytes = DEFAULT_FILE_SIZE_KB * 1024
        raw_data = generate_random_text(size_bytes)
        print(f"[+] Generated random demonstration text ({size_bytes} bytes)")

    # Pad data to 16-byte boundary
    padded_data = pad_data(raw_data)
    file_size = len(padded_data)
    if len(padded_data) != len(raw_data):
        print(f"[+] Padded data to {file_size} bytes (added {file_size - len(raw_data)} bytes of padding)")

    # Generate random Key and IV
    key = os.urandom(32)
    iv = os.urandom(16)

    print(f"[+] Generated cryptographic key (256-bit): {key.hex()[:32]}...")
    print(f"[+] Generated initialization vector (128-bit): {iv.hex()}")
    print(f"[+] Connecting to Zynq board at {BOARD_IP}...")

    # Run Benchmark transactions
    results = {}
    modes = {
        0: ("Software Encryption", "sw_enc"),
        2: ("Hardware Encryption", "hw_enc"),
        1: ("Software Decryption", "sw_dec"),
        3: ("Hardware Decryption", "hw_dec")
    }

    ciphertexts = {}
    plaintexts = {}

    for mode_code, (mode_name, key_name) in modes.items():
        print(f"[*] Executing {mode_name}...")
        
        # Select appropriate data payload
        if "dec" in key_name:
            # For decryption, send the encrypted ciphertext from the previous step
            tx_data = ciphertexts["sw_enc" if "sw" in key_name else "hw_enc"]
        else:
            tx_data = padded_data

        elapsed_us, rx_data = run_aes_transaction(mode_code, key, iv, tx_data)
        
        if elapsed_us is None:
            print(f"[-] {mode_name} failed. Exiting.")
            return

        # Calculate throughput (Mbps)
        bits = file_size * 8
        throughput = bits / elapsed_us if elapsed_us > 0 else 0
        results[key_name] = (elapsed_us, throughput)
        
        if "enc" in key_name:
            ciphertexts[key_name] = rx_data
        else:
            plaintexts[key_name] = rx_data

        print(f"    Completed in {elapsed_us:,} microseconds. Throughput: {throughput:.2f} Mbps")

    # Verify Correctness
    print("\n[+] Verification Check:")
    sw_correct = (plaintexts["sw_dec"] == padded_data)
    hw_correct = (plaintexts["hw_dec"] == padded_data)
    match_correct = (ciphertexts["sw_enc"] == ciphertexts["hw_enc"])

    if sw_correct:
        print("    - Software Decryption: PASS (Matches original plaintext)")
    else:
        print("    - Software Decryption: FAIL (Mismatched plaintext)")

    if hw_correct:
        print("    - Hardware Decryption: PASS (Matches original plaintext)")
    else:
        print("    - Hardware Decryption: FAIL (Mismatched plaintext)")

    if match_correct:
        print("    - Ciphertext Integrity: PASS (SW and HW ciphertexts match exactly)")
    else:
        print("    - Ciphertext Integrity: FAIL (SW and HW ciphertexts differ)")

    if sw_correct and hw_correct and match_correct:
        print("\n[+] ALL CHECKS PASSED: Hardware encryption/decryption operates correctly!")
    else:
        print("\n[-] INTEGRITY CHECK FAILED: Please check your RTL or software implementation.")

    # Save output files to Extended folder
    extended_dir = r"C:\Users\hp\Downloads\Internship\Extended"
    if not os.path.exists(extended_dir):
        os.makedirs(extended_dir, exist_ok=True)

    if input_file_path:
        base_name = os.path.basename(input_file_path)
        name, ext = os.path.splitext(base_name)
        enc_filename = f"{name}_encrypted{ext}"
        dec_filename = f"{name}_decrypted{ext}"
    else:
        enc_filename = "random_demonstration_encrypted.bin"
        dec_filename = "random_demonstration_decrypted.bin"

    enc_path = os.path.join(extended_dir, enc_filename)
    dec_path = os.path.join(extended_dir, dec_filename)

    # Save hardware encrypted ciphertext
    if "hw_enc" in ciphertexts:
        try:
            with open(enc_path, "wb") as f:
                f.write(ciphertexts["hw_enc"])
            print(f"[+] Saved encrypted file to: {enc_path}")
        except Exception as e:
            print(f"[-] Failed to save encrypted file: {e}")

    # Save hardware decrypted plaintext (strip padding back to original length)
    if "hw_dec" in plaintexts:
        try:
            dec_data = plaintexts["hw_dec"][:len(raw_data)]
            with open(dec_path, "wb") as f:
                f.write(dec_data)
            print(f"[+] Saved decrypted file to: {dec_path}")
        except Exception as e:
            print(f"[-] Failed to save decrypted file: {e}")

    # Display Performance Analysis
    sw_time_enc, sw_rate_enc = results["sw_enc"]
    hw_time_enc, hw_rate_enc = results["hw_enc"]
    sw_time_dec, sw_rate_dec = results["sw_dec"]
    hw_time_dec, hw_rate_dec = results["hw_dec"]

    speedup_enc = sw_time_enc / hw_time_enc if hw_time_enc > 0 else 0
    speedup_dec = sw_time_dec / hw_time_dec if hw_time_dec > 0 else 0

    print("\nPerformance Summary:")
    print("====================================================")
    print(f"File Size Processed   : {file_size:,} bytes")
    print(f"Encryption Time       : SW = {sw_time_enc:,} us | HW = {hw_time_enc:,} us")
    print(f"Encryption Speedup    : {speedup_enc:.2f}x faster in hardware")
    print(f"Decryption Time       : SW = {sw_time_dec:,} us | HW = {hw_time_dec:,} us")
    print(f"Decryption Speedup    : {speedup_dec:.2f}x faster in hardware")
    print("====================================================")

    draw_chart(sw_rate_enc, hw_rate_enc, sw_rate_dec, hw_rate_dec)

if __name__ == "__main__":
    main()
