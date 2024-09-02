import hashlib
import shutil
import subprocess
import argparse
ESP_CHECKSUM_MAGIC = 0xEF

def copy_firmware(original_path, modified_path):
    shutil.copy(original_path, modified_path)

def remove_footer(firmware_data):
    footer_size = 33  # 1 byte for checksum, 32 bytes for hash
    padding_size = (16 - len(firmware_data) % 16) % 16
    modified_data = firmware_data[:-(footer_size + padding_size)]
    return modified_data

def pad_firmware(firmware_data):
    padding_needed = (16 - (len(firmware_data) + 1) % 16) % 16
    return firmware_data + b'\x00' * padding_needed

def find_password_near_set_ps(firmware_data, set_ps_function, old_password):
    set_ps_index = firmware_data.find(set_ps_function)
    if set_ps_index == -1:
        raise ValueError("set_ps function not found in the firmware.")
    
    # Look for the password string after the set_ps function call
    password_index = firmware_data.find(old_password.encode('utf-8'), set_ps_index)
    if password_index == -1:
        raise ValueError("Password not found near set_ps function.")
    
    return password_index

def replace_password(firmware_data, password_index, old_password, new_password):
    old_password_bytes = old_password.encode('utf-8')
    new_password_bytes = new_password.encode('utf-8')
    
    # Ensure the new password fits exactly in the space of the old password
    if len(new_password_bytes) > len(old_password_bytes):
        raise ValueError("New password is too long.")
    
    new_password_bytes = new_password_bytes.ljust(len(old_password_bytes), b'\x00')
    
    # Replace the old password with the new one
    modified_data = firmware_data[:password_index] + new_password_bytes + firmware_data[password_index + len(old_password_bytes):]
    return modified_data

def add_static_checksum_and_hash(modified_firmware_path, modified_data, static_checksum, static_hash):
    padded_data = pad_firmware(modified_data)
    with open(modified_firmware_path, 'wb') as f:
        f.write(padded_data)
        f.write(static_checksum.to_bytes(1, 'little'))
        f.write(static_hash)

def calculate_hash(firmware_data, checksum):
    checksum_bytes = checksum.to_bytes(1, 'little')
    calc_digest = hashlib.sha256()
    calc_digest.update(firmware_data + checksum_bytes)
    return calc_digest.digest()

def add_checksum_and_hash(modified_firmware_path, modified_data, checksum, validation_hash):
    padded_data = pad_firmware(modified_data)
    with open(modified_firmware_path, 'wb') as f:
        f.write(padded_data)
        f.write(checksum.to_bytes(1, 'little'))
        f.write(validation_hash)

def get_calculated_checksum(firmware_path):
    # Run esptool.py to get the correct checksum
    result = subprocess.run(
        ["esptool.py", "--chip", "esp32", "image_info", firmware_path],
        stdout=subprocess.PIPE,
        text=True
    )
    
    # Parse the output to find the calculated checksum
    for line in result.stdout.splitlines():
        if "Checksum:" in line and "calculated" in line:
            parts = line.split()
            checksum_str = parts[-1].strip('()')  # Remove any extra characters like parentheses
            return int(checksum_str, 16)  # Extract the checksum value as an integer

def main():
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Replace the password in firmware.")
    parser.add_argument("new_password", type=str, help="The new password to replace the old one.")
    args = parser.parse_args()

    original_firmware_path = 'firmware.bin'
    modified_firmware_path = 'firmware-mod.bin'

    set_ps_function = b'WIFI_STA_POWER_SAVE'  # Byte sequence near the password
    old_password = "password"

    # Ensure the new password is the same length as the old password
    if len(args.new_password) != len(old_password):
        print(f"Error: New password must be {len(old_password)} characters long.")
        sys.exit(1)

    new_password = args.new_password

    original_firmware_path = 'firmware.bin'
    modified_firmware_path = 'firmware-mod.bin'
    
    set_ps_function = b'WIFI_STA_POWER_SAVE'  # Byte sequence near the password
    
    static_checksum = 0x00
    static_hash = b'\x00' * 32
    
    copy_firmware(original_firmware_path, modified_firmware_path)
    
    with open(modified_firmware_path, 'rb') as f:
        firmware_data = f.read()
    
    modified_data = remove_footer(firmware_data)
    
    # Find the password near the set_ps function
    password_index = find_password_near_set_ps(modified_data, set_ps_function, old_password)
    
    # Replace the password
    modified_data = replace_password(modified_data, password_index, old_password, new_password)
    
    add_static_checksum_and_hash(modified_firmware_path, modified_data, static_checksum, static_hash)
    
    correct_checksum = get_calculated_checksum(modified_firmware_path)
    print(f'Correct Checksum from esptool.py: {correct_checksum:02x}')
    
    validation_hash = calculate_hash(modified_data, correct_checksum)
    
    add_checksum_and_hash(modified_firmware_path, modified_data, correct_checksum, validation_hash)
    
    print(f'Final Checksum: {correct_checksum:02x}')
    print(f'Validation Hash: {validation_hash.hex()}')

if __name__ == '__main__':
    main()
