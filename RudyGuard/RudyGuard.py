import os
import sys
import time
from modules.connection_scanner import ConnectionScanner
from modules.geolocator import Geolocator
from modules.traceroute import Traceroute
from modules.suspicious_db import SuspiciousIPDB
from modules.heuristics import HeuristicAnalyzer
from modules.notifier import Notifier
from modules.logger import LogManager

LOG_FILE = "rudyg_log.json"
SUSPICIOUS_DB_FILE = "rudyg_suspicious_ips.json"

EMOJI_CLEAN = "✅"
EMOJI_SUSPICIOUS = "⚠️"
EMOJI_ALERT = "🚨"
EMOJI_TCP = "🔵"
EMOJI_UDP = "🟢"
EMOJI_ICMP = "🟣"
EMOJI_LAN = "🏠"
EMOJI_WEB = "🌐"
EMOJI_HOP = "➖"
EMOJI_STAR = "⭐"
EMOJI_ARROW = "➡️"
EMOJI_CLOCK = "🕒"

ASCII_LOGO = r"""
 _   _____           _        _____                     _   _ 
| | |  __ \         | |      / ____|                   | | | |
| | | |__) |   _  __| |_   _| |  __ _   _  __ _ _ __ __| | | |
| | |  _  / | | |/ _` | | | | | |_ | | | |/ _` | '__/ _` | | |
|_| | | \ \ |_| | (_| | |_| | |__| | |_| | (_| | | | (_| | |_|
(_) |_|  \_\__,_|\__,_|\__, |\_____|\__,_|\__,_|_|  \__,_| (_)
                        __/ |                                 
                       |___/                                  
"""

def color_text(text, color):
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "reset": "\033[0m",
        "bold": "\033[1m",
        "bg_blue": "\033[44m",
        "bg_magenta": "\033[45m",
        "bg_yellow": "\033[43m",
        "bg_red": "\033[41m",
        "bg_green": "\033[42m"
    }
    return f"{colors.get(color, '')}{text}{colors['reset']}"

def emoji_protocol(proto, is_lan=False):
    if is_lan:
        return EMOJI_LAN
    return {
        "TCP": EMOJI_TCP,
        "UDP": EMOJI_UDP,
        "ICMP": EMOJI_ICMP,
        "HTTP": EMOJI_WEB,
        "HTTPS": EMOJI_WEB
    }.get(proto, EMOJI_WEB)

def print_header():
    os.system("clear")
    print(color_text(ASCII_LOGO, "cyan"))
    print(color_text("🛡️ RudyGuard: Advanced Network Security Monitor 🚀", "magenta"))
    print(color_text("By: Rudy Cooper", "yellow"))
    print(color_text("Press Ctrl+C to stop and save logs.", "green"))
    print(color_text("=" * 100, "blue"))

def print_traceroute(hops):
    print(color_text(f"{EMOJI_HOP} Traceroute:", "magenta"), end=" ")
    for i, hop in enumerate(hops):
        hop_str = hop.strip()
        if "*" in hop_str:
            print(color_text(f"{EMOJI_STAR} *", "yellow"), end=" ")
        else:
            print(color_text(f"{EMOJI_HOP} {hop_str}", "cyan"), end=" ")
    print()

def print_connection(conn, status, emoji, color, domain, country, isp, hops, timestamp, protocol, is_lan):
    # Column settings (fixed width for alignment)
    proto_emoji = emoji_protocol(protocol, is_lan)
    local = f"{conn['local_ip']}:{conn['local_port']}".ljust(20)
    remote = f"{conn['remote_ip']}:{conn['remote_port']}".ljust(20)
    status_str = color_text(f"{emoji} {status}", color).ljust(14)
    country_str = color_text(country, 'cyan').ljust(14)
    isp_str = color_text(isp, 'magenta').ljust(18)
    domain_str = color_text(domain, 'yellow').ljust(32)
    time_str = color_text(timestamp, 'green').ljust(20)

    print(
        f"{proto_emoji} {protocol:<5} {local} {color_text(EMOJI_ARROW, 'white')} {remote} "
        f"{status_str} | 🌍 {country_str} | 🏢 {isp_str} | 🏷️ {domain_str} | {EMOJI_CLOCK} {time_str}"
    )
    if hops:
        print_traceroute(hops)

def main():
    print_header()
    scanner = ConnectionScanner()
    geolocator = Geolocator()
    traceroute = Traceroute()
    suspicious_db = SuspiciousIPDB(SUSPICIOUS_DB_FILE)
    heuristics = HeuristicAnalyzer()
    notifier = Notifier()
    logger = LogManager(LOG_FILE)

    try:
        while True:
            connections = scanner.get_connections()
            print(color_text(f"\n{EMOJI_WEB} Active Connections: {len(connections)}\n", "bg_blue"))
            for conn in connections:
                is_lan = conn["is_private"]
                geo = geolocator.get_info(conn['remote_ip']) if not is_lan else {
                    "country": "LAN",
                    "region": "Local",
                    "isp": "Local Network",
                    "domain": conn['remote_ip']
                }
                domain = geo.get("domain", conn['remote_ip'])
                country = geo.get("country", "LAN")
                isp = geo.get("isp", "Local Network")

                is_suspicious = suspicious_db.is_suspicious(conn['remote_ip'])
                heuristic_flag = heuristics.is_suspicious(conn, geo)
                status = "CLEAN"
                emoji = EMOJI_CLEAN
                color = "green"
                hops = None
                if is_suspicious or heuristic_flag:
                    status = "SUSPICIOUS"
                    emoji = EMOJI_SUSPICIOUS
                    color = "red"
                    notifier.alert(conn, geo)
                    hops = traceroute.run(conn['remote_ip']) if not is_lan else ["LAN hop"]
                logger.log_connection(conn, status, geo, hops)
                print_connection(conn, status, emoji, color, domain, country, isp, hops, conn['timestamp'], conn['protocol'], is_lan)
            print(color_text("-" * 100, "magenta"))
            time.sleep(2)
            print_header()
    except KeyboardInterrupt:
        print(color_text("\n🛑 Monitoring stopped. Log saved at rudyg_log.json", "bg_magenta"))
        logger.save_logs()
        print(color_text("👋 Thanks for using RudyGuard! | RudySilver", "cyan"))
        sys.exit(0)

if __name__ == "__main__":
    main()
import os
import sys
import time
from modules.connection_scanner import ConnectionScanner
from modules.geolocator import Geolocator
from modules.traceroute import Traceroute
from modules.suspicious_db import SuspiciousIPDB
from modules.heuristics import HeuristicAnalyzer
from modules.notifier import Notifier
from modules.logger import LogManager

LOG_FILE = "rudyg_log.json"
SUSPICIOUS_DB_FILE = "rudyg_suspicious_ips.json"

EMOJI_CLEAN = "✅"
EMOJI_SUSPICIOUS = "⚠️"
EMOJI_ALERT = "🚨"
EMOJI_TCP = "🔵"
EMOJI_UDP = "🟢"
EMOJI_ICMP = "🟣"
EMOJI_LAN = "🏠"
EMOJI_WEB = "🌐"
EMOJI_HOP = "➖"
EMOJI_STAR = "⭐"
EMOJI_ARROW = "➡️"
EMOJI_CLOCK = "🕒"

ASCII_LOGO = r"""
 _   _____           _        _____                     _   _ 
| | |  __ \         | |      / ____|                   | | | |
| | | |__) |   _  __| |_   _| |  __ _   _  __ _ _ __ __| | | |
| | |  _  / | | |/ _` | | | | | |_ | | | |/ _` | '__/ _` | | |
|_| | | \ \ |_| | (_| | |_| | |__| | |_| | (_| | | | (_| | |_|
(_) |_|  \_\__,_|\__,_|\__, |\_____|\__,_|\__,_|_|  \__,_| (_)
                        __/ |                                 
                       |___/                                  
"""

def color_text(text, color):
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "reset": "\033[0m",
        "bold": "\033[1m",
        "bg_blue": "\033[44m",
        "bg_magenta": "\033[45m",
        "bg_yellow": "\033[43m",
        "bg_red": "\033[41m",
        "bg_green": "\033[42m"
    }
    return f"{colors.get(color, '')}{text}{colors['reset']}"

def emoji_protocol(proto, is_lan=False):
    if is_lan:
        return EMOJI_LAN
    return {
        "TCP": EMOJI_TCP,
        "UDP": EMOJI_UDP,
        "ICMP": EMOJI_ICMP,
        "HTTP": EMOJI_WEB,
        "HTTPS": EMOJI_WEB
    }.get(proto, EMOJI_WEB)

def print_header():
    os.system("clear")
    print(color_text(ASCII_LOGO, "cyan"))
    print(color_text("🛡️ RudyGuard: Advanced Network Security Monitor 🚀", "magenta"))
    print(color_text("By: Rudy Cooper", "yellow"))
    print(color_text("Press Ctrl+C to stop and save logs.", "green"))
    print(color_text("=" * 100, "blue"))

def print_traceroute(hops):
    print(color_text(f"{EMOJI_HOP} Traceroute:", "magenta"), end=" ")
    for i, hop in enumerate(hops):
        hop_str = hop.strip()
        if "*" in hop_str:
            print(color_text(f"{EMOJI_STAR} *", "yellow"), end=" ")
        else:
            print(color_text(f"{EMOJI_HOP} {hop_str}", "cyan"), end=" ")
    print()

def print_connection(conn, status, emoji, color, domain, country, isp, hops, timestamp, protocol, is_lan):
    # Column settings (fixed width for alignment)
    proto_emoji = emoji_protocol(protocol, is_lan)
    local = f"{conn['local_ip']}:{conn['local_port']}".ljust(20)
    remote = f"{conn['remote_ip']}:{conn['remote_port']}".ljust(20)
    status_str = color_text(f"{emoji} {status}", color).ljust(14)
    country_str = color_text(country, 'cyan').ljust(14)
    isp_str = color_text(isp, 'magenta').ljust(18)
    domain_str = color_text(domain, 'yellow').ljust(32)
    time_str = color_text(timestamp, 'green').ljust(20)

    print(
        f"{proto_emoji} {protocol:<5} {local} {color_text(EMOJI_ARROW, 'white')} {remote} "
        f"{status_str} | 🌍 {country_str} | 🏢 {isp_str} | 🏷️ {domain_str} | {EMOJI_CLOCK} {time_str}"
    )
    if hops:
        print_traceroute(hops)

def main():
    print_header()
    scanner = ConnectionScanner()
    geolocator = Geolocator()
    traceroute = Traceroute()
    suspicious_db = SuspiciousIPDB(SUSPICIOUS_DB_FILE)
    heuristics = HeuristicAnalyzer()
    notifier = Notifier()
    logger = LogManager(LOG_FILE)

    try:
        while True:
            connections = scanner.get_connections()
            print(color_text(f"\n{EMOJI_WEB} Active Connections: {len(connections)}\n", "bg_blue"))
            for conn in connections:
                is_lan = conn["is_private"]
                geo = geolocator.get_info(conn['remote_ip']) if not is_lan else {
                    "country": "LAN",
                    "region": "Local",
                    "isp": "Local Network",
                    "domain": conn['remote_ip']
                }
                domain = geo.get("domain", conn['remote_ip'])
                country = geo.get("country", "LAN")
                isp = geo.get("isp", "Local Network")

                is_suspicious = suspicious_db.is_suspicious(conn['remote_ip'])
                heuristic_flag = heuristics.is_suspicious(conn, geo)
                status = "CLEAN"
                emoji = EMOJI_CLEAN
                color = "green"
                hops = None
                if is_suspicious or heuristic_flag:
                    status = "SUSPICIOUS"
                    emoji = EMOJI_SUSPICIOUS
                    color = "red"
                    notifier.alert(conn, geo)
                    hops = traceroute.run(conn['remote_ip']) if not is_lan else ["LAN hop"]
                logger.log_connection(conn, status, geo, hops)
                print_connection(conn, status, emoji, color, domain, country, isp, hops, conn['timestamp'], conn['protocol'], is_lan)
            print(color_text("-" * 100, "magenta"))
            time.sleep(2)
            print_header()
    except KeyboardInterrupt:
        print(color_text("\n🛑 Monitoring stopped. Log saved at rudyg_log.json", "bg_magenta"))
        logger.save_logs()
        print(color_text("👋 Thanks for using RudyGuard! | RudySilver", "cyan"))
        sys.exit(0)

if __name__ == "__main__":
    main()
import os
import sys
import time
from modules.connection_scanner import ConnectionScanner
from modules.geolocator import Geolocator
from modules.traceroute import Traceroute
from modules.suspicious_db import SuspiciousIPDB
from modules.heuristics import HeuristicAnalyzer
from modules.notifier import Notifier
from modules.logger import LogManager

LOG_FILE = "rudyg_log.json"
SUSPICIOUS_DB_FILE = "rudyg_suspicious_ips.json"

EMOJI_CLEAN = "✅"
EMOJI_SUSPICIOUS = "⚠️"
EMOJI_ALERT = "🚨"
EMOJI_TCP = "🔵"
EMOJI_UDP = "🟢"
EMOJI_ICMP = "🟣"
EMOJI_LAN = "🏠"
EMOJI_WEB = "🌐"
EMOJI_HOP = "➖"
EMOJI_STAR = "⭐"
EMOJI_ARROW = "➡️"
EMOJI_CLOCK = "🕒"

ASCII_LOGO = r"""
 _   _____           _        _____                     _   _ 
| | |  __ \         | |      / ____|                   | | | |
| | | |__) |   _  __| |_   _| |  __ _   _  __ _ _ __ __| | | |
| | |  _  / | | |/ _` | | | | | |_ | | | |/ _` | '__/ _` | | |
|_| | | \ \ |_| | (_| | |_| | |__| | |_| | (_| | | | (_| | |_|
(_) |_|  \_\__,_|\__,_|\__, |\_____|\__,_|\__,_|_|  \__,_| (_)
                        __/ |                                 
                       |___/                                  
"""

def color_text(text, color):
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "reset": "\033[0m",
        "bold": "\033[1m",
        "bg_blue": "\033[44m",
        "bg_magenta": "\033[45m",
        "bg_yellow": "\033[43m",
        "bg_red": "\033[41m",
        "bg_green": "\033[42m"
    }
    return f"{colors.get(color, '')}{text}{colors['reset']}"

def emoji_protocol(proto, is_lan=False):
    if is_lan:
        return EMOJI_LAN
    return {
        "TCP": EMOJI_TCP,
        "UDP": EMOJI_UDP,
        "ICMP": EMOJI_ICMP,
        "HTTP": EMOJI_WEB,
        "HTTPS": EMOJI_WEB
    }.get(proto, EMOJI_WEB)

def print_header():
    os.system("clear")
    print(color_text(ASCII_LOGO, "cyan"))
    print(color_text("🛡️ RudyGuard: Advanced Network Security Monitor 🚀", "magenta"))
    print(color_text("By: Rudy Cooper", "yellow"))
    print(color_text("Press Ctrl+C to stop and save logs.", "green"))
    print(color_text("=" * 100, "blue"))

def print_traceroute(hops):
    print(color_text(f"{EMOJI_HOP} Traceroute:", "magenta"), end=" ")
    for i, hop in enumerate(hops):
        hop_str = hop.strip()
        if "*" in hop_str:
            print(color_text(f"{EMOJI_STAR} *", "yellow"), end=" ")
        else:
            print(color_text(f"{EMOJI_HOP} {hop_str}", "cyan"), end=" ")
    print()

def print_connection(conn, status, emoji, color, domain, country, isp, hops, timestamp, protocol, is_lan):
    # Column settings (fixed width for alignment)
    proto_emoji = emoji_protocol(protocol, is_lan)
    local = f"{conn['local_ip']}:{conn['local_port']}".ljust(20)
    remote = f"{conn['remote_ip']}:{conn['remote_port']}".ljust(20)
    status_str = color_text(f"{emoji} {status}", color).ljust(14)
    country_str = color_text(country, 'cyan').ljust(14)
    isp_str = color_text(isp, 'magenta').ljust(18)
    domain_str = color_text(domain, 'yellow').ljust(32)
    time_str = color_text(timestamp, 'green').ljust(20)

    print(
        f"{proto_emoji} {protocol:<5} {local} {color_text(EMOJI_ARROW, 'white')} {remote} "
        f"{status_str} | 🌍 {country_str} | 🏢 {isp_str} | 🏷️ {domain_str} | {EMOJI_CLOCK} {time_str}"
    )
    if hops:
        print_traceroute(hops)

def main():
    print_header()
    scanner = ConnectionScanner()
    geolocator = Geolocator()
    traceroute = Traceroute()
    suspicious_db = SuspiciousIPDB(SUSPICIOUS_DB_FILE)
    heuristics = HeuristicAnalyzer()
    notifier = Notifier()
    logger = LogManager(LOG_FILE)

    try:
        while True:
            connections = scanner.get_connections()
            print(color_text(f"\n{EMOJI_WEB} Active Connections: {len(connections)}\n", "bg_blue"))
            for conn in connections:
                is_lan = conn["is_private"]
                geo = geolocator.get_info(conn['remote_ip']) if not is_lan else {
                    "country": "LAN",
                    "region": "Local",
                    "isp": "Local Network",
                    "domain": conn['remote_ip']
                }
                domain = geo.get("domain", conn['remote_ip'])
                country = geo.get("country", "LAN")
                isp = geo.get("isp", "Local Network")

                is_suspicious = suspicious_db.is_suspicious(conn['remote_ip'])
                heuristic_flag = heuristics.is_suspicious(conn, geo)
                status = "CLEAN"
                emoji = EMOJI_CLEAN
                color = "green"
                hops = None
                if is_suspicious or heuristic_flag:
                    status = "SUSPICIOUS"
                    emoji = EMOJI_SUSPICIOUS
                    color = "red"
                    notifier.alert(conn, geo)
                    hops = traceroute.run(conn['remote_ip']) if not is_lan else ["LAN hop"]
                logger.log_connection(conn, status, geo, hops)
                print_connection(conn, status, emoji, color, domain, country, isp, hops, conn['timestamp'], conn['protocol'], is_lan)
            print(color_text("-" * 100, "magenta"))
            time.sleep(2)
            print_header()
    except KeyboardInterrupt:
        print(color_text("\n🛑 Monitoring stopped. Log saved at rudyg_log.json", "bg_magenta"))
        logger.save_logs()
        print(color_text("👋 Thanks for using RudyGuard! | RudySilver", "cyan"))
        sys.exit(0)

if __name__ == "__main__":
    main()
import os
import sys
import time
from modules.connection_scanner import ConnectionScanner
from modules.geolocator import Geolocator
from modules.traceroute import Traceroute
from modules.suspicious_db import SuspiciousIPDB
from modules.heuristics import HeuristicAnalyzer
from modules.notifier import Notifier
from modules.logger import LogManager

LOG_FILE = "rudyg_log.json"
SUSPICIOUS_DB_FILE = "rudyg_suspicious_ips.json"

EMOJI_CLEAN = "✅"
EMOJI_SUSPICIOUS = "⚠️"
EMOJI_ALERT = "🚨"
EMOJI_TCP = "🔵"
EMOJI_UDP = "🟢"
EMOJI_ICMP = "🟣"
EMOJI_LAN = "🏠"
EMOJI_WEB = "🌐"
EMOJI_HOP = "➖"
EMOJI_STAR = "⭐"
EMOJI_ARROW = "➡️"
EMOJI_CLOCK = "🕒"

ASCII_LOGO = r"""
 _   _____           _        _____                     _   _ 
| | |  __ \         | |      / ____|                   | | | |
| | | |__) |   _  __| |_   _| |  __ _   _  __ _ _ __ __| | | |
| | |  _  / | | |/ _` | | | | | |_ | | | |/ _` | '__/ _` | | |
|_| | | \ \ |_| | (_| | |_| | |__| | |_| | (_| | | | (_| | |_|
(_) |_|  \_\__,_|\__,_|\__, |\_____|\__,_|\__,_|_|  \__,_| (_)
                        __/ |                                 
                       |___/                                  
"""

def color_text(text, color):
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "reset": "\033[0m",
        "bold": "\033[1m",
        "bg_blue": "\033[44m",
        "bg_magenta": "\033[45m",
        "bg_yellow": "\033[43m",
        "bg_red": "\033[41m",
        "bg_green": "\033[42m"
    }
    return f"{colors.get(color, '')}{text}{colors['reset']}"

def emoji_protocol(proto, is_lan=False):
    if is_lan:
        return EMOJI_LAN
    return {
        "TCP": EMOJI_TCP,
        "UDP": EMOJI_UDP,
        "ICMP": EMOJI_ICMP,
        "HTTP": EMOJI_WEB,
        "HTTPS": EMOJI_WEB
    }.get(proto, EMOJI_WEB)

def print_header():
    os.system("clear")
    print(color_text(ASCII_LOGO, "cyan"))
    print(color_text("🛡️ RudyGuard: Advanced Network Security Monitor 🚀", "magenta"))
    print(color_text("By: Rudy Cooper", "yellow"))
    print(color_text("Press Ctrl+C to stop and save logs.", "green"))
    print(color_text("=" * 100, "blue"))

def print_traceroute(hops):
    print(color_text(f"{EMOJI_HOP} Traceroute:", "magenta"), end=" ")
    for i, hop in enumerate(hops):
        hop_str = hop.strip()
        if "*" in hop_str:
            print(color_text(f"{EMOJI_STAR} *", "yellow"), end=" ")
        else:
            print(color_text(f"{EMOJI_HOP} {hop_str}", "cyan"), end=" ")
    print()

def print_connection(conn, status, emoji, color, domain, country, isp, hops, timestamp, protocol, is_lan):
    # Column settings (fixed width for alignment)
    proto_emoji = emoji_protocol(protocol, is_lan)
    local = f"{conn['local_ip']}:{conn['local_port']}".ljust(20)
    remote = f"{conn['remote_ip']}:{conn['remote_port']}".ljust(20)
    status_str = color_text(f"{emoji} {status}", color).ljust(14)
    country_str = color_text(country, 'cyan').ljust(14)
    isp_str = color_text(isp, 'magenta').ljust(18)
    domain_str = color_text(domain, 'yellow').ljust(32)
    time_str = color_text(timestamp, 'green').ljust(20)

    print(
        f"{proto_emoji} {protocol:<5} {local} {color_text(EMOJI_ARROW, 'white')} {remote} "
        f"{status_str} | 🌍 {country_str} | 🏢 {isp_str} | 🏷️ {domain_str} | {EMOJI_CLOCK} {time_str}"
    )
    if hops:
        print_traceroute(hops)

def main():
    print_header()
    scanner = ConnectionScanner()
    geolocator = Geolocator()
    traceroute = Traceroute()
    suspicious_db = SuspiciousIPDB(SUSPICIOUS_DB_FILE)
    heuristics = HeuristicAnalyzer()
    notifier = Notifier()
    logger = LogManager(LOG_FILE)

    try:
        while True:
            connections = scanner.get_connections()
            print(color_text(f"\n{EMOJI_WEB} Active Connections: {len(connections)}\n", "bg_blue"))
            for conn in connections:
                is_lan = conn["is_private"]
                geo = geolocator.get_info(conn['remote_ip']) if not is_lan else {
                    "country": "LAN",
                    "region": "Local",
                    "isp": "Local Network",
                    "domain": conn['remote_ip']
                }
                domain = geo.get("domain", conn['remote_ip'])
                country = geo.get("country", "LAN")
                isp = geo.get("isp", "Local Network")

                is_suspicious = suspicious_db.is_suspicious(conn['remote_ip'])
                heuristic_flag = heuristics.is_suspicious(conn, geo)
                status = "CLEAN"
                emoji = EMOJI_CLEAN
                color = "green"
                hops = None
                if is_suspicious or heuristic_flag:
                    status = "SUSPICIOUS"
                    emoji = EMOJI_SUSPICIOUS
                    color = "red"
                    notifier.alert(conn, geo)
                    hops = traceroute.run(conn['remote_ip']) if not is_lan else ["LAN hop"]
                logger.log_connection(conn, status, geo, hops)
                print_connection(conn, status, emoji, color, domain, country, isp, hops, conn['timestamp'], conn['protocol'], is_lan)
            print(color_text("-" * 100, "magenta"))
            time.sleep(2)
            print_header()
    except KeyboardInterrupt:
        print(color_text("\n🛑 Monitoring stopped. Log saved at rudyg_log.json", "bg_magenta"))
        logger.save_logs()
        print(color_text("👋 Thanks for using RudyGuard! | RudySilver", "cyan"))
        sys.exit(0)

if __name__ == "__main__":
    main()
import os
import sys
import time
from modules.connection_scanner import ConnectionScanner
from modules.geolocator import Geolocator
from modules.traceroute import Traceroute
from modules.suspicious_db import SuspiciousIPDB
from modules.heuristics import HeuristicAnalyzer
from modules.notifier import Notifier
from modules.logger import LogManager

LOG_FILE = "rudyg_log.json"
SUSPICIOUS_DB_FILE = "rudyg_suspicious_ips.json"

EMOJI_CLEAN = "✅"
EMOJI_SUSPICIOUS = "⚠️"
EMOJI_ALERT = "🚨"
EMOJI_TCP = "🔵"
EMOJI_UDP = "🟢"
EMOJI_ICMP = "🟣"
EMOJI_LAN = "🏠"
EMOJI_WEB = "🌐"
EMOJI_HOP = "➖"
EMOJI_STAR = "⭐"
EMOJI_ARROW = "➡️"
EMOJI_CLOCK = "🕒"

ASCII_LOGO = r"""
 _   _____           _        _____                     _   _ 
| | |  __ \         | |      / ____|                   | | | |
| | | |__) |   _  __| |_   _| |  __ _   _  __ _ _ __ __| | | |
| | |  _  / | | |/ _` | | | | | |_ | | | |/ _` | '__/ _` | | |
|_| | | \ \ |_| | (_| | |_| | |__| | |_| | (_| | | | (_| | |_|
(_) |_|  \_\__,_|\__,_|\__, |\_____|\__,_|\__,_|_|  \__,_| (_)
                        __/ |                                 
                       |___/                                  
"""

def color_text(text, color):
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "reset": "\033[0m",
        "bold": "\033[1m",
        "bg_blue": "\033[44m",
        "bg_magenta": "\033[45m",
        "bg_yellow": "\033[43m",
        "bg_red": "\033[41m",
        "bg_green": "\033[42m"
    }
    return f"{colors.get(color, '')}{text}{colors['reset']}"

def emoji_protocol(proto, is_lan=False):
    if is_lan:
        return EMOJI_LAN
    return {
        "TCP": EMOJI_TCP,
        "UDP": EMOJI_UDP,
        "ICMP": EMOJI_ICMP,
        "HTTP": EMOJI_WEB,
        "HTTPS": EMOJI_WEB
    }.get(proto, EMOJI_WEB)

def print_header():
    os.system("clear")
    print(color_text(ASCII_LOGO, "cyan"))
    print(color_text("🛡️ RudyGuard: Advanced Network Security Monitor 🚀", "magenta"))
    print(color_text("By: Rudy Cooper", "yellow"))
    print(color_text("Press Ctrl+C to stop and save logs.", "green"))
    print(color_text("=" * 100, "blue"))

def print_traceroute(hops):
    print(color_text(f"{EMOJI_HOP} Traceroute:", "magenta"), end=" ")
    for i, hop in enumerate(hops):
        hop_str = hop.strip()
        if "*" in hop_str:
            print(color_text(f"{EMOJI_STAR} *", "yellow"), end=" ")
        else:
            print(color_text(f"{EMOJI_HOP} {hop_str}", "cyan"), end=" ")
    print()

def print_connection(conn, status, emoji, color, domain, country, isp, hops, timestamp, protocol, is_lan):
    # Column settings (fixed width for alignment)
    proto_emoji = emoji_protocol(protocol, is_lan)
    local = f"{conn['local_ip']}:{conn['local_port']}".ljust(20)
    remote = f"{conn['remote_ip']}:{conn['remote_port']}".ljust(20)
    status_str = color_text(f"{emoji} {status}", color).ljust(14)
    country_str = color_text(country, 'cyan').ljust(14)
    isp_str = color_text(isp, 'magenta').ljust(18)
    domain_str = color_text(domain, 'yellow').ljust(32)
    time_str = color_text(timestamp, 'green').ljust(20)

    print(
        f"{proto_emoji} {protocol:<5} {local} {color_text(EMOJI_ARROW, 'white')} {remote} "
        f"{status_str} | 🌍 {country_str} | 🏢 {isp_str} | 🏷️ {domain_str} | {EMOJI_CLOCK} {time_str}"
    )
    if hops:
        print_traceroute(hops)

def main():
    print_header()
    scanner = ConnectionScanner()
    geolocator = Geolocator()
    traceroute = Traceroute()
    suspicious_db = SuspiciousIPDB(SUSPICIOUS_DB_FILE)
    heuristics = HeuristicAnalyzer()
    notifier = Notifier()
    logger = LogManager(LOG_FILE)

    try:
        while True:
            connections = scanner.get_connections()
            print(color_text(f"\n{EMOJI_WEB} Active Connections: {len(connections)}\n", "bg_blue"))
            for conn in connections:
                is_lan = conn["is_private"]
                geo = geolocator.get_info(conn['remote_ip']) if not is_lan else {
                    "country": "LAN",
                    "region": "Local",
                    "isp": "Local Network",
                    "domain": conn['remote_ip']
                }
                domain = geo.get("domain", conn['remote_ip'])
                country = geo.get("country", "LAN")
                isp = geo.get("isp", "Local Network")

                is_suspicious = suspicious_db.is_suspicious(conn['remote_ip'])
                heuristic_flag = heuristics.is_suspicious(conn, geo)
                status = "CLEAN"
                emoji = EMOJI_CLEAN
                color = "green"
                hops = None
                if is_suspicious or heuristic_flag:
                    status = "SUSPICIOUS"
                    emoji = EMOJI_SUSPICIOUS
                    color = "red"
                    notifier.alert(conn, geo)
                    hops = traceroute.run(conn['remote_ip']) if not is_lan else ["LAN hop"]
                logger.log_connection(conn, status, geo, hops)
                print_connection(conn, status, emoji, color, domain, country, isp, hops, conn['timestamp'], conn['protocol'], is_lan)
            print(color_text("-" * 100, "magenta"))
            time.sleep(2)
            print_header()
    except KeyboardInterrupt:
        print(color_text("\n🛑 Monitoring stopped. Log saved at rudyg_log.json", "bg_magenta"))
        logger.save_logs()
        print(color_text("👋 Thanks for using RudyGuard! | RudySilver", "cyan"))
        sys.exit(0)

if __name__ == "__main__":
    main()
import os
import sys
import time
from modules.connection_scanner import ConnectionScanner
from modules.geolocator import Geolocator
from modules.traceroute import Traceroute
from modules.suspicious_db import SuspiciousIPDB
from modules.heuristics import HeuristicAnalyzer
from modules.notifier import Notifier
from modules.logger import LogManager

LOG_FILE = "rudyg_log.json"
SUSPICIOUS_DB_FILE = "rudyg_suspicious_ips.json"

EMOJI_CLEAN = "✅"
EMOJI_SUSPICIOUS = "⚠️"
EMOJI_ALERT = "🚨"
EMOJI_TCP = "🔵"
EMOJI_UDP = "🟢"
EMOJI_ICMP = "🟣"
EMOJI_LAN = "🏠"
EMOJI_WEB = "🌐"
EMOJI_HOP = "➖"
EMOJI_STAR = "⭐"
EMOJI_ARROW = "➡️"
EMOJI_CLOCK = "🕒"

ASCII_LOGO = r"""
 _   _____           _        _____                     _   _ 
| | |  __ \         | |      / ____|                   | | | |
| | | |__) |   _  __| |_   _| |  __ _   _  __ _ _ __ __| | | |
| | |  _  / | | |/ _` | | | | | |_ | | | |/ _` | '__/ _` | | |
|_| | | \ \ |_| | (_| | |_| | |__| | |_| | (_| | | | (_| | |_|
(_) |_|  \_\__,_|\__,_|\__, |\_____|\__,_|\__,_|_|  \__,_| (_)
                        __/ |                                 
                       |___/                                  
"""

def color_text(text, color):
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "reset": "\033[0m",
        "bold": "\033[1m",
        "bg_blue": "\033[44m",
        "bg_magenta": "\033[45m",
        "bg_yellow": "\033[43m",
        "bg_red": "\033[41m",
        "bg_green": "\033[42m"
    }
    return f"{colors.get(color, '')}{text}{colors['reset']}"

def emoji_protocol(proto, is_lan=False):
    if is_lan:
        return EMOJI_LAN
    return {
        "TCP": EMOJI_TCP,
        "UDP": EMOJI_UDP,
        "ICMP": EMOJI_ICMP,
        "HTTP": EMOJI_WEB,
        "HTTPS": EMOJI_WEB
    }.get(proto, EMOJI_WEB)

def print_header():
    os.system("clear")
    print(color_text(ASCII_LOGO, "cyan"))
    print(color_text("🛡️ RudyGuard: Advanced Network Security Monitor 🚀", "magenta"))
    print(color_text("By: Rudy Cooper", "yellow"))
    print(color_text("Press Ctrl+C to stop and save logs.", "green"))
    print(color_text("=" * 100, "blue"))

def print_traceroute(hops):
    print(color_text(f"{EMOJI_HOP} Traceroute:", "magenta"), end=" ")
    for i, hop in enumerate(hops):
        hop_str = hop.strip()
        if "*" in hop_str:
            print(color_text(f"{EMOJI_STAR} *", "yellow"), end=" ")
        else:
            print(color_text(f"{EMOJI_HOP} {hop_str}", "cyan"), end=" ")
    print()

def print_connection(conn, status, emoji, color, domain, country, isp, hops, timestamp, protocol, is_lan):
    # Column settings (fixed width for alignment)
    proto_emoji = emoji_protocol(protocol, is_lan)
    local = f"{conn['local_ip']}:{conn['local_port']}".ljust(20)
    remote = f"{conn['remote_ip']}:{conn['remote_port']}".ljust(20)
    status_str = color_text(f"{emoji} {status}", color).ljust(14)
    country_str = color_text(country, 'cyan').ljust(14)
    isp_str = color_text(isp, 'magenta').ljust(18)
    domain_str = color_text(domain, 'yellow').ljust(32)
    time_str = color_text(timestamp, 'green').ljust(20)

    print(
        f"{proto_emoji} {protocol:<5} {local} {color_text(EMOJI_ARROW, 'white')} {remote} "
        f"{status_str} | 🌍 {country_str} | 🏢 {isp_str} | 🏷️ {domain_str} | {EMOJI_CLOCK} {time_str}"
    )
    if hops:
        print_traceroute(hops)

def main():
    print_header()
    scanner = ConnectionScanner()
    geolocator = Geolocator()
    traceroute = Traceroute()
    suspicious_db = SuspiciousIPDB(SUSPICIOUS_DB_FILE)
    heuristics = HeuristicAnalyzer()
    notifier = Notifier()
    logger = LogManager(LOG_FILE)

    try:
        while True:
            connections = scanner.get_connections()
            print(color_text(f"\n{EMOJI_WEB} Active Connections: {len(connections)}\n", "bg_blue"))
            for conn in connections:
                is_lan = conn["is_private"]
                geo = geolocator.get_info(conn['remote_ip']) if not is_lan else {
                    "country": "LAN",
                    "region": "Local",
                    "isp": "Local Network",
                    "domain": conn['remote_ip']
                }
                domain = geo.get("domain", conn['remote_ip'])
                country = geo.get("country", "LAN")
                isp = geo.get("isp", "Local Network")

                is_suspicious = suspicious_db.is_suspicious(conn['remote_ip'])
                heuristic_flag = heuristics.is_suspicious(conn, geo)
                status = "CLEAN"
                emoji = EMOJI_CLEAN
                color = "green"
                hops = None
                if is_suspicious or heuristic_flag:
                    status = "SUSPICIOUS"
                    emoji = EMOJI_SUSPICIOUS
                    color = "red"
                    notifier.alert(conn, geo)
                    hops = traceroute.run(conn['remote_ip']) if not is_lan else ["LAN hop"]
                logger.log_connection(conn, status, geo, hops)
                print_connection(conn, status, emoji, color, domain, country, isp, hops, conn['timestamp'], conn['protocol'], is_lan)
            print(color_text("-" * 100, "magenta"))
            time.sleep(2)
            print_header()
    except KeyboardInterrupt:
        print(color_text("\n🛑 Monitoring stopped. Log saved at rudyg_log.json", "bg_magenta"))
        logger.save_logs()
        print(color_text("👋 Thanks for using RudyGuard! | RudySilver", "cyan"))
        sys.exit(0)

if __name__ == "__main__":
    main()
