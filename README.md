# Cyber Security Internship - Task 1: Network Reconnaissance

## Objective
Discover open ports on devices in the local network using Nmap and analyze service exposure and risks.

## Environment
- OS: Kali Linux
- Tools: nmap, dig (part of dnsutils)

## Steps performed
1. Determined local subnet: 192.168.15.0/24
2. Performed ping discovery to list live hosts:
sudo nmap -sn 192.168.15.0/24 -oN scan_ping.txt

css
Copy code
3. Performed a TCP SYN scan across the subnet and saved machine-readable output:
sudo nmap -sS 192.168.15.0/24 -T4 -oA scan_results

javascript
Copy code
This produced `scan_results.nmap`, `scan_results.xml`, and `scan_results.gnmap`.
4. Filtered results to find hosts with open ports:
grep -i "open" scan_results.gnmap

pgsql
Copy code
Found a host with DNS on port 53.
5. Confirmed service details for TCP/UDP port 53:
sudo nmap -sS -sV -p 53 -Pn 192.168.15.x -oN check_tcp53.txt
sudo nmap -sU -p 53 -Pn 192.168.15.x -oN check_udp53.txt

markdown
Copy code
6. Tested DNS responses:
dig @192.168.15.x example.com > dig_udp.txt
dig @192.168.15.x example.com +tcp > dig_tcp.txt

markdown
Copy code

## Findings
- Host: 192.168.15.x (masked)
- Open ports:
- 53/tcp — open — service identified as dnsmasq 2.51
- 53/udp — open — DNS service
- MAC address and raw packet captures have been omitted or redacted.

## Risk analysis
- Exposed DNS service may present risks if misconfigured or unpatched (recursion abuse, amplification, information disclosure).
- Recommended actions: restrict access to DNS, bind dnsmasq to specific interfaces, update dnsmasq package, or remove the service if not required.

## Notes
- All private IPs and MAC addresses have been masked in this repository.
- Raw packet captures were not included to avoid exposing DNS query contents.
- Full unsanitized artifacts are available to instructors on request.

## Author
Chayesh Kumar M L
