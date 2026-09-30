import yara
import os

# 1. Compile the YARA rule from the file we created
try:
    rules = yara.compile(filepath='keylogger_rules.yar')
    print("[+] YARA rules compiled successfully.")
except yara.SyntaxError as e:
    print(f"[-] Failed to compile YARA rules: {e}")
    exit()

def scan_directory(target_dir):
    print(f"[*] Scanning directory: {target_dir}\n")
    
    # Walk through the directory and scan each file
    for root, _, files in os.walk(target_dir):
        for file in files:
            file_path = os.path.join(root, file)
            
            try:
                # 2. Run the compiled rules against the file
                matches = rules.match(file_path)
                
                # 3. Handle the output if a match is found
                if matches:
                    print(f" THREAT DETECTED: {file_path}")
                    for match in matches:
                        print(f" Rule Triggered: {match.rule}")
                        # Optional: Print the exact strings that matched
                        for string_match in match.strings:
                            # string_match is a tuple: (offset, string_identifier, string_data)
                            identifier = string_match[1]
                            data = string_match[2].decode('utf-8', errors='ignore')
                            print(f"      - Matched {identifier}: {data}")
                    print("-" * 40)
                    
            except Exception as e:
                # Handle files that cannot be read (permissions, locked files)
                pass

if __name__ == "__main__":
    # Specify a safe test directory containing dummy text files or scripts
    # WARNING: Do not point this at your root C:\ drive without filters, as it will take hours.
    test_directory = "./test_malware_samples"
    
    if not os.path.exists(test_directory):
        os.makedirs(test_directory)
        print(f"[!] Created {test_directory}. Place test files here and run again.")
    else:
        scan_directory(test_directory)