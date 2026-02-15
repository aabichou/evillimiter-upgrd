import sys
import time
import socket
import subprocess
import threading
from netaddr import EUI, NotRegisteredError
from scapy.all import srp, sr1, Ether, ARP, IP, ICMP, conf  # pylint: disable=no-name-in-module

from .host import Host
from evillimiter.console.io import IO


class HostScanner(object):
    _SPINNER = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'

    def __init__(self, interface, iprange):
        self.interface = interface
        self.iprange = iprange
        self.timeout = 5       # increased from 2s — IndiHome/slow routers need more time
        self.retry_count = 3   # number of ARP scan passes for deep scan
        self.inter_packet_delay = 0.005  # small delay between packets to avoid flooding

    @staticmethod
    def _get_vendor(mac):
        """
        Resolve device vendor/manufacturer from MAC OUI prefix.
        Uses netaddr's built-in IEEE OUI database.
        Returns empty string if vendor unknown.
        """
        try:
            return EUI(mac).oui.registration().org
        except (NotRegisteredError, IndexError, Exception):
            return ''

    def _spinner_thread(self, message, stop_event):
        """Animated spinner shown while scan is in progress."""
        i = 0
        while not stop_event.is_set():
            elapsed = time.time() - self._scan_start
            frame = self._SPINNER[i % len(self._SPINNER)]
            msg = '\r  {} {}... ({:.1f}s)'.format(frame, message, elapsed)
            sys.stdout.write(msg)
            sys.stdout.flush()
            i += 1
            stop_event.wait(0.1)
        # clear spinner line
        sys.stdout.write('\r' + ' ' * 80 + '\r')
        sys.stdout.flush()

    def _read_arp_table(self):
        """
        Read OS ARP cache to discover hosts that are already known.
        Catches devices that responded to previous ARP/ICMP but might
        not respond to our scan packets (phones in power-save, etc).
        Returns dict {mac: ip}.
        """
        hosts = {}

        # Method 1: read /proc/net/arp (Linux)
        try:
            with open('/proc/net/arp', 'r') as f:
                lines = f.readlines()[1:]  # skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 6:
                        ip = parts[0]
                        mac = parts[3].lower()
                        iface = parts[5]
                        # skip incomplete entries and wrong interface
                        if mac != '00:00:00:00:00:00' and iface == self.interface:
                            hosts[mac] = ip
        except (FileNotFoundError, PermissionError):
            pass

        # Method 2: 'ip neigh' command as fallback
        try:
            output = subprocess.check_output(
                ['ip', 'neigh', 'show', 'dev', self.interface],
                stderr=subprocess.DEVNULL, timeout=5
            ).decode('utf-8', errors='ignore')
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 5 and 'lladdr' in parts:
                    ip = parts[0]
                    lladdr_idx = parts.index('lladdr')
                    if lladdr_idx + 1 < len(parts):
                        mac = parts[lladdr_idx + 1].lower()
                        state = parts[-1] if len(parts) > lladdr_idx + 2 else ''
                        if mac != '00:00:00:00:00:00' and state not in ('FAILED',):
                            hosts[mac] = ip
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Method 3: 'arp -an' command as another fallback
        try:
            output = subprocess.check_output(
                ['arp', '-an', '-i', self.interface],
                stderr=subprocess.DEVNULL, timeout=5
            ).decode('utf-8', errors='ignore')
            for line in output.strip().split('\n'):
                if not line.strip() or '<incomplete>' in line:
                    continue
                # Format: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on wlan0
                parts = line.split()
                for j, p in enumerate(parts):
                    if p == 'at' and j + 1 < len(parts) and j >= 1:
                        mac = parts[j + 1].lower()
                        ip_part = parts[j - 1].strip('()')
                        if mac != '00:00:00:00:00:00' and ':' in mac:
                            hosts[mac] = ip_part
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return hosts

    def _ping_sweep(self, target_ips):
        """
        Send ICMP echo requests to wake up sleeping/idle devices.
        Many phones drop into power-save mode and ignore ARP broadcasts,
        but will respond to ICMP or at least update their ARP tables.
        Uses fping (fastest), nmap, or manual pings as fallback.
        """
        ip_list = [str(ip) for ip in target_ips]

        # Try fping first (massively parallel, fastest option)
        try:
            process = subprocess.Popen(
                ['fping', '-a', '-q', '-r', '1', '-t', '800', '-i', '3', '-g',
                 ip_list[0], ip_list[-1]],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
            )
            process.communicate(timeout=45)
            return
        except (FileNotFoundError, subprocess.TimeoutExpired):
            if process.poll() is None:
                process.kill()

        # Try nmap ping sweep
        try:
            subprocess.call(
                ['nmap', '-sn', '-n', '--min-rate', '500', '-T4',
                 '--host-timeout', '2s', '{}-{}'.format(ip_list[0], ip_list[-1].split('.')[-1])],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45
            )
            return
        except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass

        # Last resort: parallel ping using threads
        def ping_single(ip):
            try:
                subprocess.call(
                    ['ping', '-c', '1', '-W', '1', str(ip)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3
                )
            except (subprocess.TimeoutExpired, Exception):
                pass

        batch_size = 60
        for i in range(0, len(ip_list), batch_size):
            batch = ip_list[i:i + batch_size]
            threads = []
            for ip in batch:
                t = threading.Thread(target=ping_single, args=(ip,), daemon=True)
                t.start()
                threads.append(t)
            for t in threads:
                t.join(timeout=4)

    def _arp_scan_pass(self, target_ips, timeout=None):
        """
        Single ARP broadcast scan pass.
        Returns dict {mac: ip} for responding hosts.
        """
        if timeout is None:
            timeout = self.timeout

        packets = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ips)

        try:
            answered, _ = srp(packets, timeout=timeout, iface=self.interface,
                              verbose=0, inter=self.inter_packet_delay, retry=0)
        except Exception:
            return {}

        results = {}
        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc.lower()
            results[mac] = ip

        return results

    def _unicast_arp_probe(self, ip_mac_pairs, timeout=2):
        """
        Send unicast ARP requests to specific IPs using their last-known MACs.
        Some devices (phones in WiFi power-save) ignore broadcast ARP but
        respond to unicast ARP directed at their MAC.
        """
        results = {}
        for ip, mac in ip_mac_pairs:
            try:
                pkt = Ether(dst=mac) / ARP(pdst=ip, op=1)
                answered, _ = srp(pkt, timeout=timeout, iface=self.interface,
                                  verbose=0, retry=0)
                for sent, received in answered:
                    results[received.hwsrc.lower()] = received.psrc
            except Exception:
                pass

        return results

    def scan(self, iprange=None):
        """
        Multi-strategy deep scan combining multiple techniques for maximum host discovery.
        Designed to find ALL devices including phones on IndiHome/slow WiFi routers.

        Strategy:
          1. ICMP ping sweep — wakes sleeping devices & populates ARP table
          2. Read OS ARP table — catches already-known hosts
          3. Multiple ARP broadcast passes — with increasing timeouts
          4. Unicast ARP probes — for devices in ARP table but not responding to broadcast
          5. Final ARP table read — catches late responders from the ping sweep
        """
        iprange = self.iprange if iprange is None else iprange
        target_ips = [str(x) for x in iprange]

        self._scan_start = time.time()

        # start spinner
        stop_event = threading.Event()
        spinner = threading.Thread(
            target=self._spinner_thread,
            args=('deep scanning {} addresses ({} ARP passes + ping sweep)'.format(
                len(target_ips), self.retry_count), stop_event),
            daemon=True
        )
        spinner.start()

        try:
            # Collect all discovered hosts: mac -> ip
            discovered = {}

            # === Phase 1: ICMP ping sweep to wake up sleeping devices ===
            try:
                self._ping_sweep(iprange)
                time.sleep(0.5)  # let devices update their ARP tables
            except Exception:
                pass

            # === Phase 2: Read existing ARP table ===
            arp_hosts = self._read_arp_table()
            discovered.update(arp_hosts)

            # === Phase 3: Multiple ARP broadcast scan passes ===
            for pass_num in range(self.retry_count):
                # increase timeout each pass for slower devices
                timeout = self.timeout + (pass_num * 1.5)
                results = self._arp_scan_pass(target_ips, timeout=timeout)
                discovered.update(results)

                # short delay between passes to let network settle
                if pass_num < self.retry_count - 1:
                    time.sleep(0.3)

            # === Phase 4: Unicast ARP for stubborn devices ===
            # Build list of IPs from ARP table that didn't respond to broadcast
            discovered_ips = set(discovered.values())
            arp_table_fresh = self._read_arp_table()
            unicast_targets = []
            for mac, ip in arp_table_fresh.items():
                if ip in target_ips and mac not in discovered:
                    unicast_targets.append((ip, mac))

            if unicast_targets:
                unicast_results = self._unicast_arp_probe(unicast_targets, timeout=2)
                discovered.update(unicast_results)

            # === Phase 5: Final ARP table sweep ===
            time.sleep(0.5)
            final_arp = self._read_arp_table()
            for mac, ip in final_arp.items():
                if mac not in discovered and ip in target_ips:
                    discovered[mac] = ip

        except KeyboardInterrupt:
            stop_event.set()
            spinner.join()
            IO.ok('scan aborted.')
            return []

        # === Build host objects ===
        hosts = []
        for mac, ip in discovered.items():
            vendor = self._get_vendor(mac)

            # resolve hostname
            name = ''
            try:
                host_info = socket.gethostbyaddr(ip)
                name = '' if host_info is None else host_info[0]
            except socket.herror:
                pass

            host = Host(ip, mac, name)
            host.vendor = vendor
            hosts.append(host)

        # stop spinner
        stop_event.set()
        spinner.join()

        elapsed = time.time() - self._scan_start
        IO.ok('{} hosts discovered in {:.1f}s (deep scan complete).'.format(len(hosts), elapsed))
        return hosts

    def quick_scan(self, iprange=None):
        """
        Quick single-pass ARP scan for fast results.
        Used by the host watcher for periodic checks.
        """
        iprange = self.iprange if iprange is None else iprange
        target_ips = [str(x) for x in iprange]

        packets = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ips)

        try:
            answered, _ = srp(packets, timeout=self.timeout, iface=self.interface, verbose=0)
        except Exception:
            return []

        hosts = []
        for sent, received in answered:
            host = Host(received.psrc, received.hwsrc, '')
            hosts.append(host)

        return hosts

    def scan_for_reconnects(self, hosts, iprange=None):
        """
        Multi-method scan to detect hosts that reconnected with different IPs.
        Combines ARP broadcast + ARP table reading for maximum coverage.
        """
        iprange = self.iprange if iprange is None else iprange
        target_ips = [str(x) for x in iprange]

        # ARP broadcast scan
        packets = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ips)

        scanned_hosts = []
        try:
            answered, _ = srp(packets, timeout=self.timeout, iface=self.interface, verbose=0)
            for sent, received in answered:
                scanned_hosts.append(Host(received.psrc, received.hwsrc.lower(), ''))
        except Exception:
            pass

        # Also check ARP table for reconnected hosts
        arp_hosts = self._read_arp_table()
        for mac, ip in arp_hosts.items():
            already_found = any(sh.mac.lower() == mac for sh in scanned_hosts)
            if not already_found:
                scanned_hosts.append(Host(ip, mac, ''))

        reconnected_hosts = {}
        for host in hosts:
            for s_host in scanned_hosts:
                if host.mac.lower() == s_host.mac.lower() and host.ip != s_host.ip:
                    s_host.name = host.name
                    s_host.vendor = getattr(host, 'vendor', '')
                    reconnected_hosts[host] = s_host

        return reconnected_hosts