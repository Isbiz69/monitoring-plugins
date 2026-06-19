#!/usr/bin/env python3
# ==============================================================================
# Script Name : check_ebgp_tcp_peer.py
# Description : Monitors an eBGP session through the SNMP TCP-MIB
#
# Requirement:
#   Some Internet transit eBGP sessions may not be covered by an existing BGP
#   monitoring system. If an eBGP peer becomes unavailable while the physical
#   interface remains UP/UP, the incident may not be detected immediately.
#
# Purpose:
#   Query the TCP-MIB tcpConnState table through SNMP using the OID:
#     1.3.6.1.2.1.6.13.1.1
#
#   The script searches for a TCP session associated with the eBGP neighbor
#   supplied as an argument, with TCP port 179 present on either the local or
#   remote side.
#
#   If a matching session is found with tcpConnState = 5 (ESTABLISHED), the
#   script returns OK.
#
#   If no matching session is found, or if the session exists but is not in the
#   ESTABLISHED state, the script returns CRITICAL.
#
#   If an execution or SNMP query error occurs, the script returns UNKNOWN.
#
# Monitoring states:
#   OK       = 0
#   CRITICAL = 2
#   UNKNOWN  = 3
# ==============================================================================

import argparse
import ipaddress
import re
import subprocess
import sys

OK = 0
CRITICAL = 2
UNKNOWN = 3

OID_TCP_CONN_STATE = "1.3.6.1.2.1.6.13.1.1"


def valid_ipv4(value):
    """Validate and return an IPv4 address supplied on the command line."""
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid IPv4 address: {value}") from exc


def valid_port(value):
    """Validate and return a TCP port number."""
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Port must be an integer") from exc

    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("Port must be between 1 and 65535")

    return port


def positive_integer(value):
    """Validate and return a strictly positive integer."""
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Value must be an integer") from exc

    if number < 1:
        raise argparse.ArgumentTypeError("Value must be greater than zero")

    return number


def parse_args():
    """
    Parse command-line arguments.

    Expected arguments:
      -H / --host      : IP address or DNS name of the SNMP device
      -C / --community : SNMP v2c community
      -n / --neighbor  : IPv4 address of the eBGP neighbor to monitor
      -p / --port      : BGP TCP port, default 179
      -t / --timeout   : SNMP timeout in seconds, default 10
    """
    parser = argparse.ArgumentParser(
        description="Check an eBGP TCP peer state through the SNMP TCP-MIB"
    )
    parser.add_argument("-H", "--host", required=True, help="SNMP target host")
    parser.add_argument("-C", "--community", required=True, help="SNMP v2c community")
    parser.add_argument(
        "-n",
        "--neighbor",
        required=True,
        type=valid_ipv4,
        help="eBGP neighbor IPv4 address",
    )
    parser.add_argument(
        "-p",
        "--port",
        default=179,
        type=valid_port,
        help="BGP TCP port, default 179",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        default=10,
        type=positive_integer,
        help="SNMP timeout in seconds, default 10",
    )
    return parser.parse_args()


def run_snmpwalk(host, community, timeout):
    """
    Run snmpwalk against the tcpConnState OID.

    The -On option forces numeric OID output to make parsing predictable.

    Returns:
      - snmpwalk standard output as a list of lines

    Exits with UNKNOWN if:
      - the snmpwalk command is unavailable
      - the command exceeds the timeout
      - snmpwalk returns an error
    """
    cmd = [
        "snmpwalk",
        "-v2c",
        "-c",
        community,
        "-t",
        str(timeout),
        "-r",
        "1",
        "-On",
        host,
        OID_TCP_CONN_STATE,
    ]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout + 2,
            check=False,
        )
    except FileNotFoundError:
        print("UNKNOWN - snmpwalk command not found | peer_established=0")
        sys.exit(UNKNOWN)
    except subprocess.TimeoutExpired:
        print("UNKNOWN - snmpwalk timeout | peer_established=0")
        sys.exit(UNKNOWN)

    if result.returncode != 0:
        error_message = result.stderr.strip() or "unknown SNMP error"
        print(f"UNKNOWN - snmpwalk failed: {error_message} | peer_established=0")
        sys.exit(UNKNOWN)

    return result.stdout.splitlines()


def ip_from_parts(parts):
    """
    Rebuild an IPv4 address from four OID components.

    Example:
      ["192", "0", "2", "10"] becomes "192.0.2.10"
    """
    return ".".join(parts)


def extract_state(line):
    """
    Extract the tcpConnState value from an snmpwalk output line.

    Supported formats:
      INTEGER: 5
      established(5)
      5

    Returns:
      - an integer representing the TCP state
      - None if no usable value is found
    """
    match = re.search(r"\((\d+)\)", line)
    if match:
        return int(match.group(1))

    match = re.search(r"INTEGER:\s*(\d+)", line)
    if match:
        return int(match.group(1))

    match = re.search(r"\s(\d+)\s*$", line)
    if match:
        return int(match.group(1))

    return None


def main():
    """
    Execute the monitoring check.

    Steps:
      1. Parse command-line arguments.
      2. Run snmpwalk against tcpConnState.
      3. Parse every returned TCP session.
      4. Search for a session containing:
           - the requested eBGP neighbor
           - BGP TCP port 179 on the local or remote side
      5. Check the tcpConnState value:
           - 5 = ESTABLISHED
           - any other value = not established
      6. Return the appropriate monitoring state.
    """
    args = parse_args()
    lines = run_snmpwalk(args.host, args.community, args.timeout)

    matching_sessions = []
    base = f".{OID_TCP_CONN_STATE}."

    for line in lines:
        if base not in line:
            continue

        oid_part = line.split("=", 1)[0].strip()

        if not oid_part.startswith(base):
            continue

        suffix = oid_part.removeprefix(base)
        parts = suffix.split(".")

        if len(parts) != 10:
            continue

        local_ip = ip_from_parts(parts[0:4])
        local_port = int(parts[4])
        remote_ip = ip_from_parts(parts[5:9])
        remote_port = int(parts[9])
        state = extract_state(line)

        if state is None:
            continue

        if args.neighbor in (local_ip, remote_ip) and args.port in (
            local_port,
            remote_port,
        ):
            matching_sessions.append(
                {
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "state": state,
                }
            )

    if not matching_sessions:
        print(
            f"CRITICAL - TCP BGP session to neighbor {args.neighbor} was not found "
            f"on {args.host} | peer_established=0"
        )
        sys.exit(CRITICAL)

    established_sessions = [
        session for session in matching_sessions if session["state"] == 5
    ]

    if established_sessions:
        session = established_sessions[0]
        print(
            f"OK - TCP BGP session to neighbor {args.neighbor} is ESTABLISHED on "
            f"{args.host} ({session['local_ip']}:{session['local_port']} -> "
            f"{session['remote_ip']}:{session['remote_port']}, tcpConnState=5) | "
            "peer_established=1"
        )
        sys.exit(OK)

    states = ", ".join(
        f"{session['local_ip']}:{session['local_port']}->"
        f"{session['remote_ip']}:{session['remote_port']} "
        f"tcpConnState={session['state']}"
        for session in matching_sessions
    )

    print(
        f"CRITICAL - TCP BGP session to neighbor {args.neighbor} is not "
        f"ESTABLISHED on {args.host}: {states} | peer_established=0"
    )
    sys.exit(CRITICAL)


if __name__ == "__main__":
    main()
