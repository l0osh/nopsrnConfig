import subprocess  # Needed for getting system MTU
import time  # Needed for measuring response times
from scapy.all import IP, ICMP, sr1, conf  # Scapy for packet crafting and sending

def get_default_mtu():
    """Get the system's default MTU by checking the primary network interface."""
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True)
        for line in result.stdout.split("\n"):
            if "default" in line:
                interface = line.split()[-1]
                mtu_result = subprocess.run(["ip", "link", "show", interface], capture_output=True, text=True)
                for mtu_line in mtu_result.stdout.split("\n"):
                    if "mtu" in mtu_line:
                        return int(mtu_line.split()[4])
    except:
        pass
    return 1500  # Default to standard Ethernet MTU if detection fails

def mtu_test(ip, size):
    """
    Sends an ICMP Echo Request with the DF (Don't Fragment) bit set.
    Returns True if the packet was successfully delivered without fragmentation.
    """
    conf.verb = 0  # Suppress Scapy output
    print(f"[DEBUG] Testing MTU payload size: {size} (Total packet size: {size + 28})")

    pkt = IP(dst=ip, flags="DF") / ICMP() / ("X" * size)  # Create ICMP packet with payload size
    start_time = time.time()
    reply = sr1(pkt, timeout=2, verbose=False)  # Send packet and wait for reply

    if reply is None:
        print(f"[DEBUG] Size {size}: No response received (possibly blocked or fragmented)")
        return False  

    if reply.haslayer(ICMP):
        if reply[ICMP].type == 3 and reply[ICMP].code == 4:  # ICMP Type 3, Code 4: Fragmentation Needed
            print(f"[DEBUG] Size {size}: ICMP Type 3, Code 4 detected (Fragmentation Needed)")
            return False  
        elif reply[ICMP].type == 0:  # Echo reply
            print(f"[DEBUG] Size {size}: ICMP reply received in {round(time.time() - start_time, 3)}s")
            return True  

    print(f"[DEBUG] Size {size}: Unexpected ICMP response detected")
    return False  

def find_mtu(ip):
    """
    Dynamically finds the maximum possible MTU using binary search.
    Starts from the system's detected MTU and adjusts dynamically.
    """
    detected_mtu = get_default_mtu()
    print(f"[INFO] Detected system MTU: {detected_mtu}")

    low, high = 512, detected_mtu - 28  # Start search within reasonable range
    iteration = 0  

    while low < high:
        iteration += 1
        if iteration > 25:  # Safety limit to prevent infinite loops
            print("[ERROR] MTU search exceeded iteration limit! Something is wrong.")
            break

        mid = (low + high + 1) // 2  
        print(f"[DEBUG] Iteration {iteration}: Testing size {mid} (range: {low}-{high})")

        if mtu_test(ip, mid):
            print(f"[DEBUG] Size {mid} was successful, increasing search range")
            low = mid  
        else:
            print(f"[DEBUG] Size {mid} failed, decreasing search range")
            high = mid - 1  

    final_mtu = low + 28  # Convert payload size back to total MTU
    print(f"[DEBUG] Final determined MTU payload size: {low} (Total MTU: {final_mtu})")
    return final_mtu

if __name__ == "__main__":
    target_ip = input("Enter the target IP: ")  # User input for flexibility
    mtu = find_mtu(target_ip)
    print(f"Optimal MTU discovered: {mtu} bytes") 
