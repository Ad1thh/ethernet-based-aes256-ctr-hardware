import socket
import os
import sys
import argparse

# Configuration
BOARD_IP = "192.168.1.10"
BOARD_PORT = 7
ENCRYPT_DIR = r"C:\Users\hp\Downloads\outputs\encrypted"
DECRYPT_DIR = r"C:\Users\hp\Downloads\outputs\decrypted"

def parse_args():
    parser = argparse.ArgumentParser(
        description="Zynq-7000 Hardware AES-256 CTR Encryption/Decryption Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples of Use:
  # 1. Fully interactive (prompts you for path and mode):
  python aes256_tool.py

  # 2. Encrypt multiple files or folders:
  python aes256_tool.py "C:\\path\\to\\file1.bmp" "C:\\path\\to\\folder" -m encrypt
"""
    )
    parser.add_argument("files", nargs="*", help="Path to the input file(s) or directories to encrypt/decrypt")
    parser.add_argument("-m", "--mode", choices=["encrypt", "decrypt"],
                        help="Operation mode: encrypt or decrypt (interactive prompt if omitted)")
    parser.add_argument("-k", "--key", help="256-bit Key in Hex format (64 hex characters)")
    parser.add_argument("-i", "--iv", help="128-bit IV in Hex format (32 hex characters)")
    parser.add_argument("--sw", action="store_true", help="Use Software mode on board (default is Hardware)")
    return parser.parse_args()

def pad_data(data):
    # Pad to a multiple of 16 bytes for AES block size
    padding_len = (16 - (len(data) % 16)) % 16
    if padding_len > 0:
        data = data + b"\x00" * padding_len  # Use null byte padding for clean zero-padding
    return data, padding_len

def run_aes_transaction(mode_code, key, iv, data):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(15.0)
        s.connect((BOARD_IP, BOARD_PORT))
    except Exception as e:
        print(f"[-] Error connecting to Zynq board at {BOARD_IP}:{BOARD_PORT} - {e}")
        print("[!] Make sure the board is powered on, pingable, and the server application is running.")
        sys.exit(1)

    file_size = len(data)
    header = bytearray()
    header.append(mode_code)
    header.extend(key)
    header.extend(iv)
    header.extend(file_size.to_bytes(4, byteorder='big'))

    try:
        s.sendall(header)
        s.sendall(data)
    except Exception as e:
        print(f"[-] Error sending data: {e}")
        s.close()
        sys.exit(1)

    try:
        # Read 4-byte elapsed time header
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
        sys.exit(1)

    s.close()
    return elapsed_us, bytes(out_data)

def main():
    args = parse_args()

    # If no files/folders specified, ask interactively
    if not args.files:
        import shlex
        print("="*60)
        print(" Zynq-7000 AES-256 CTR Interactive Terminal")
        print("="*60)
        while True:
            raw_input = input("Enter file or directory path(s): ").strip()
            if not raw_input:
                print("[-] Path cannot be empty.")
                continue
            
            # Parse multiple paths using shlex (keeps quoted spaces intact, ignores backslash escaping)
            try:
                paths = shlex.split(raw_input, posix=False)
            except Exception as e:
                print(f"[-] Error parsing input paths: {e}")
                continue
            
            # Clean quotes from parsed paths
            parsed_paths = [p.strip('\'"') for p in paths]
            
            # Validate existence of all paths
            valid_paths = []
            invalid_paths = []
            for p in parsed_paths:
                if os.path.exists(p):
                    valid_paths.append(p)
                else:
                    invalid_paths.append(p)
            
            if invalid_paths:
                for p in invalid_paths:
                    print(f"[-] Path not found: {p}")
                print("[!] Please check your paths and try again.")
                continue
                
            args.files = valid_paths
            break
        print()

    # Expand directories into individual files
    files_to_process = []
    for path in args.files:
        if os.path.isdir(path):
            # Sort files for deterministic processing order
            for entry in sorted(os.listdir(path)):
                full_entry = os.path.join(path, entry)
                # Ignore metadata files in the directory
                if os.path.isfile(full_entry) and not entry.endswith("_encrypted_meta.txt"):
                    files_to_process.append(full_entry)
        elif os.path.isfile(path):
            files_to_process.append(path)
        else:
            print(f"[-] Path not found or invalid: {path}")

    if not files_to_process:
        print("[-] No valid files found to process.")
        sys.exit(1)

    # Determine mode interactively if not provided
    if not args.mode:
        print("="*60)
        print(" Zynq-7000 AES-256 CTR Interactive Terminal")
        print("="*60)
        while True:
            choice = input("Choose operation mode:\n  [1] Encrypt (Secure files using Zynq)\n  [2] Decrypt (Restore files using Key/IV)\nSelection (1 or 2): ").strip()
            if choice == '1':
                args.mode = "encrypt"
                break
            elif choice == '2':
                args.mode = "decrypt"
                break
            else:
                print("[-] Invalid choice. Enter 1 or 2.")
        print()

    print(f"[+] Found {len(files_to_process)} file(s) to process in {args.mode.upper()} mode.\n")

    # Determine mode code to send to Zynq
    if args.sw:
        mode_code = 0 if args.mode == "encrypt" else 1
        mode_desc = "Software"
    else:
        mode_code = 2 if args.mode == "encrypt" else 3
        mode_desc = "Hardware (AXI DMA)"

    # Process each file
    for idx, file_path in enumerate(files_to_process, 1):
        print(f"[{idx}/{len(files_to_process)}] Processing: {os.path.basename(file_path)}")
        
        # Read file
        try:
            with open(file_path, "rb") as f:
                raw_data = f.read()
        except Exception as e:
            print(f"  [-] Failed to read file: {e}")
            continue

        original_size = len(raw_data)
        
        # Determine Key and IV for this specific file
        file_key = args.key
        file_iv = args.iv

        if args.mode == "decrypt" and (not file_key or not file_iv):
            base_name = os.path.basename(file_path)
            name, ext = os.path.splitext(base_name)
            meta_filename = f"{name.replace('_encrypted', '')}_encrypted_meta.txt"
            meta_path = os.path.join(ENCRYPT_DIR, meta_filename)
            
            found_meta = False
            saved_key = None
            saved_iv = None
            if os.path.exists(meta_path):
                try:
                    with open(meta_path, "r") as f_meta:
                        for line in f_meta:
                            if "Key" in line:
                                saved_key = line.split(":")[1].strip()
                            if "IV" in line:
                                saved_iv = line.split(":")[1].strip()
                    if saved_key and saved_iv:
                        found_meta = True
                except:
                    pass

            if found_meta:
                print(f"  [+] Auto-loaded Key & IV from metadata: {meta_filename}")
                file_key = saved_key
                file_iv = saved_iv
            else:
                if len(files_to_process) > 1:
                    print(f"  [-] Missing metadata or key/IV parameters for this file. Skipping.")
                    continue
                else:
                    # Single file interactive fallback
                    file_key = input("  Enter Key (64-char Hex): ").strip()
                    file_iv = input("  Enter IV (32-char Hex): ").strip()

        # Parse and validate parameters
        if args.mode == "encrypt":
            if file_key:
                try:
                    key_bytes = bytes.fromhex(file_key)
                    if len(key_bytes) != 32: raise ValueError
                except:
                    print("  [-] Key must be valid 64-character hex. Skipping.")
                    continue
            else:
                key_bytes = os.urandom(32)

            if file_iv:
                try:
                    iv_bytes = bytes.fromhex(file_iv)
                    if len(iv_bytes) != 16: raise ValueError
                except:
                    print("  [-] IV must be valid 32-character hex. Skipping.")
                    continue
            else:
                iv_bytes = os.urandom(16)
        else:
            # Decrypt mode validation
            try:
                key_bytes = bytes.fromhex(file_key)
                if len(key_bytes) != 32: raise ValueError
            except:
                print("  [-] Invalid or missing Key for decryption. Skipping.")
                continue

            try:
                iv_bytes = bytes.fromhex(file_iv)
                if len(iv_bytes) != 16: raise ValueError
            except:
                print("  [-] Invalid or missing IV for decryption. Skipping.")
                continue

        # Pad data
        padded_data, padding_len = pad_data(raw_data)
        
        print(f"  - Mode      : {args.mode.upper()} using Zynq {mode_desc}")
        print(f"  - Key (Hex) : {key_bytes.hex()}")
        print(f"  - IV (Hex)  : {iv_bytes.hex()}")
        print(f"  - Size      : {original_size:,} bytes (Padded to {len(padded_data):,} bytes)")

        # Transaction
        print(f"  [*] Sending to Zynq board...")
        try:
            elapsed_us, processed_data = run_aes_transaction(mode_code, key_bytes, iv_bytes, padded_data)
            print(f"  [+] Completed in {elapsed_us:,} us.")
        except Exception as e:
            print(f"  [-] Transaction failed: {e}")
            continue

        base_name = os.path.basename(file_path)
        name, ext = os.path.splitext(base_name)

        # Ensure output directories exist
        if args.mode == "encrypt":
            if not os.path.exists(ENCRYPT_DIR):
                os.makedirs(ENCRYPT_DIR, exist_ok=True)
            
            out_filename = f"{name}_encrypted{ext}"
            out_path = os.path.join(ENCRYPT_DIR, out_filename)
            
            try:
                with open(out_path, "wb") as f:
                    f.write(processed_data)
                print(f"  [+] Saved ENCRYPTED file to: {out_path}")
            except Exception as e:
                print(f"  [-] Failed to write encrypted file: {e}")
                continue

            meta_filename = f"{name}_encrypted_meta.txt"
            meta_path = os.path.join(ENCRYPT_DIR, meta_filename)
            try:
                with open(meta_path, "w") as f:
                    f.write(f"Original File : {base_name}\n")
                    f.write(f"Key (Hex)     : {key_bytes.hex()}\n")
                    f.write(f"IV (Hex)      : {iv_bytes.hex()}\n")
                    f.write(f"Original Size : {original_size} bytes\n")
                    f.write(f"Padded Size   : {len(padded_data)} bytes\n")
                    f.write(f"Padding Len   : {padding_len} bytes\n")
                print(f"  [+] Saved metadata file to: {meta_path}")
            except Exception as e:
                print(f"  [-] Failed to write metadata file: {e}")

        else:
            if not os.path.exists(DECRYPT_DIR):
                os.makedirs(DECRYPT_DIR, exist_ok=True)

            out_filename = f"{name}_decrypted{ext}"
            if "_encrypted" in name:
                clean_name = name.replace("_encrypted", "")
                out_filename = f"{clean_name}_decrypted{ext}"
            out_path = os.path.join(DECRYPT_DIR, out_filename)

            # Slicing padding
            original_unpadded_size = len(processed_data)
            meta_check_path = os.path.join(ENCRYPT_DIR, f"{name.replace('_encrypted', '')}_encrypted_meta.txt")
            if os.path.exists(meta_check_path):
                try:
                    with open(meta_check_path, "r") as f_meta:
                        for line in f_meta:
                            if "Original Size" in line:
                                original_unpadded_size = int(line.split(":")[1].strip().split()[0])
                                break
                except:
                    pass

            dec_data = processed_data[:original_unpadded_size]
            try:
                with open(out_path, "wb") as f:
                    f.write(dec_data)
                print(f"  [+] Saved DECRYPTED file to: {out_path}")
            except Exception as e:
                print(f"  [-] Failed to write decrypted file: {e}")
        print()

    print("[+] All files processed successfully.")

if __name__ == "__main__":
    main()
