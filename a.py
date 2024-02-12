import re

def is_threat_actor_ipv4(ip):
    return ip.startswith("92.85.")

def is_c2_server_ipv6(ip):
    ipv6_pattern = re.compile(r'^2510:a5:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}$')
    return ipv6_pattern.match(ip)

def extract_last_character(ip):
    return ip[-1]

def main():
    input_file_path = 'ip.lst'  # Replace with the actual path to your file
    malicious_ips = []

    with open(input_file_path, 'r') as file:
        for line in file:
            ip = line.strip()

            # Check for threat actor IPv4 addresses
            if is_threat_actor_ipv4(ip):
                malicious_ips.append(ip)
                continue

            # Check for C2 server IPv6 addresses
            if is_c2_server_ipv6(ip):
                malicious_ips.append(ip)
                continue

    # Extract the last character from each identified IP address
    flag_characters = [extract_last_character(ip) for ip in malicious_ips]

    # Construct the flag
    flag = f'HQ8{{{"".join(flag_characters)}}}'

    # Print the final flag
    print(flag)

if __name__ == "__main__":
    main()
