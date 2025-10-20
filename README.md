# Cyber Security Internship - Task 1: Network Reconnaissance

## Objective
Discover open ports on devices in the local network using Nmap and analyze service exposure and risks.

## Environment
- OS: Kali Linux
- Tools: nmap, dig (part of dnsutils), tcpdump (optional for packet capture)

## Steps performed
1. Determined local subnet: `192.168.xx.x/24`
2. Performed ping discovery to list live hosts:
sudo nmap -sn 192.168.15.0/24 -oN scan_ping.txt

3. Performed a TCP SYN scan across the subnet and saved machine-readable output:
sudo nmap -sS 192.168.xx.x/24 -T4 -oA scan_results
This produced `scan_results.nmap`, `scan_results.xml`, and `scan_results.gnmap`.

4. Filtered results to find hosts with open ports:
grep -i "open" scan_results.gnmap
Found `192.168.xx.x` with DNS service on port 53.

5. Confirmed service details for TCP/UDP port 53:
sudo nmap -sS -sV -p 53 -Pn 192.168.xx.x -oN check_tcp53.txt
sudo nmap -sU -p 53 -Pn 192.168.xx.x -oN check_udp53.txt

6. Tested DNS responses:
dig @192.168.xx.x example.com > dig_udp.txt
dig @192.168.xx.x example.com +tcp > dig_tcp.txt

## Findings
- Host: `192.168.xx.x`
- Open ports:
- `53/tcp` — open — service identified as `dnsmasq 2.51`
- `53/udp` — open — DNS service
- MAC address observed: `00:50:56:F2:FC:5A` (vendor: VMware) — indicates a virtual machine or VMware virtual NIC.
- `dig` over TCP returned valid answers for example.com, confirming the DNS server responds to queries.

## Evidence files included
- `scan_results.nmap` (human-readable nmap output)
- `scan_results.xml` (XML output)
- `scan_results.gnmap` (grepable output)
- `check_tcp53.txt` (nmap service/version detection for TCP port 53)
- `check_udp53.txt` (nmap UDP probe for port 53)
- `dig_tcp.txt` (dig result using TCP)
- `dig_udp.txt` (dig result using UDP)

## Risk analysis
- The device is running dnsmasq 2.51 and answers DNS queries from the network. If dnsmasq is misconfigured (open recursion, permissive ACLs) or unpatched, it can be abused for:
- DNS amplification/reflection attacks (if exposed to larger networks).
- Information disclosure (zone or configuration leaks).
- Cache poisoning or other DNS-related attacks if vulnerabilities are present in the version.
- Because the host appears to be a VM, it may be part of a lab or test environment. If this is an unintended service or not under administrative control, it should be investigated.

## Recommendations / Remediation
Apply these actions only on devices you own or are authorized to manage.

1. If the DNS service is not required:
- Stop and disable dnsmasq:
  ```
  sudo systemctl stop dnsmasq
  sudo systemctl disable dnsmasq
  ```
2. If the DNS service is required:
- Restrict which IPs can query the server (use firewall rules):
  ```
  # Example: restrict DNS to the local subnet 192.168.15.0/24
  sudo ufw allow from 192.168.15.0/24 to any port 53 proto udp
  sudo ufw allow from 192.168.15.0/24 to any port 53 proto tcp
  sudo ufw deny in proto udp to any port 53
  sudo ufw deny in proto tcp to any port 53
  sudo ufw reload
  ```
- Bind dnsmasq only to required interfaces or IP addresses in `/etc/dnsmasq.conf`:
  ```
  listen-address=127.0.0.1,192.168.15.1
  ```
- Disable recursion for external clients if not required.
- Ensure dnsmasq package and host OS are up to date:
  ```
  sudo apt update
  sudo apt install --only-upgrade dnsmasq
  ```
- Monitor DNS logs for unusual query volumes or suspicious patterns.

3. If the host is a VM you do not control:
- Notify the VM owner or the network administrator and request clarification or remediation.
- If it exposes services unintentionally, consider network segmentation or ACLs at the router/AP level to limit exposure.

## Notes
- Wireshark packet capture was optional for this task and is not included. All findings are based on Nmap and dig outputs.
- All scans were performed within the local network and only against hosts in the `192.168.xx.x/24` subnet.
- Only non-intrusive checks and safe queries (dig, nmap service/version detection) were used. No exploit or intrusive NSE scripts were executed.

## How to reproduce (commands summary)
1. Discover hosts:
sudo nmap -sn 192.168.xx.x/24 -oN scan_ping.txt

2. Full SYN scan and save outputs:
sudo nmap -sS 192.168.xx.x/24 -T4 -oA scan_results

3. Filter for open ports:
grep -i "open" scan_results.gnmap

4. Targeted checks for a host (example: 192.168.xx.x):
sudo nmap -sS -sV -p 53 -Pn 192.168.xx.x -oN check_tcp53.txt
sudo nmap -sU -p 53 -Pn 192.168.xx.x -oN check_udp53.txt
dig @192.168.xx.x example.com > dig_udp.txt
dig @192.168.xx.x example.com +tcp > dig_tcp.txt

## Author
Chayesh Kumar M L
