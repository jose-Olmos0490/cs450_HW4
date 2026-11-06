"""
resolve.py: a recursive resolver built using dnspython
"""

import argparse

import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.flags

FORMATS = (("CNAME", "{alias} is an alias for {name}"),
           ("A", "{name} has address {address}"),
           ("AAAA", "{name} has IPv6 address {address}"),
           ("MX", "{name} mail is handled by {preference} {exchange}"))

ROOT_SERVERS = ("198.41.0.4",
                "199.9.14.201",
                "192.33.4.12",
                "199.7.91.13",
                "192.203.230.10",
                "192.5.5.241",
                "192.112.36.4",
                "198.97.190.53",
                "192.36.148.17",
                "192.58.128.30",
                "193.0.14.129",
                "199.7.83.42",
                "202.12.27.33")

CACHE = {}            # (dns.name.Name, rdtype) -> Message or None
ZONE_SERVERS = {}     # zone dns.name.Name -> list of IPv4 strings
RESOLVING_NS = set()  # NS names currently being resolved (cycle guard)

FAILED = set()


def text(name):
    """Format a dns name without the trailing dot, like host does."""
    return name.to_text(omit_final_dot=True)


def get_referral_ips(response):
    """
    Return the IPv4 addresses from the additional section of a referral
    that belong to nameservers listed in the authority section.
    """
    ns_names = set()
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            for rdata in rrset:
                ns_names.add(rdata.target)

    ips = []
    for rrset in response.additional:
        if rrset.rdtype == dns.rdatatype.A and rrset.name in ns_names:
            for rdata in rrset:
                ips.append(rdata.address)
    return ips


def closest_servers(name):
    """
    Return the servers for the deepest zone we already know about,
    walking up from name toward the root.
    """
    n = name
    while True:
        if n in ZONE_SERVERS:
            return list(ZONE_SERVERS[n])
        if n == dns.name.root:
            return list(ROOT_SERVERS)
        n = n.parent()


def resolve_ns_ip(ns_name):
    """
    Resolve an NS name with no glue to IPv4 addresses by looking up its A record.
    The RESOLVING_NS set stops infinite loops when nameservers depend on
    each other for their own addresses.
    """
    if ns_name in RESOLVING_NS:
        return []
    RESOLVING_NS.add(ns_name)
    try:
        response = lookup(ns_name, dns.rdatatype.A)
    finally:
        RESOLVING_NS.discard(ns_name)

    if response is None:
        return []
    ips = []
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.A:
            for rdata in rrset:
                ips.append(rdata.address)
    return ips


def _ask(target_name, qtype, servers):
    """
    Query the given servers, following referrals, until an answer appears.
    Returns the response, or None if nothing answered.
    """
    outbound_query = dns.message.make_query(target_name, qtype)
    servers = list(servers)
    tried = set()

    while servers:
        server = servers.pop(0)
        if server in tried or server in FAILED:
            continue
        tried.add(server)
        try:
            response = dns.query.udp(outbound_query, server, 3)
        except Exception:
            FAILED.add(server)
            continue

        if response.answer or response.flags & dns.flags.AA:
            return response

        next_ips = get_referral_ips(response)
        if not next_ips:
            for rrset in response.authority:
                if rrset.rdtype == dns.rdatatype.NS:
                    for rdata in rrset:
                        next_ips.extend(resolve_ns_ip(rdata.target))
                        if next_ips:
                            break
                if next_ips:
                    break    

        if next_ips:
            # Remember which servers handle this zone so later lookups
            # under it skip the parent zones.
            for rrset in response.authority:
                if rrset.rdtype == dns.rdatatype.NS:
                    ZONE_SERVERS[rrset.name] = list(next_ips)
                    break

        servers.extend(next_ips)

    return None


def _lookup_uncached(target_name, qtype):
    """
    Start at the closest known zone. If that fails, fall back to the roots.
    """
    start = closest_servers(target_name)
    response = _ask(target_name, qtype, start)
    if response is None and start != list(ROOT_SERVERS):
        response = _ask(target_name, qtype, ROOT_SERVERS)
    return response


def lookup(target_name, qtype):
    """
    Cached wrapper around _lookup_uncached. Failed lookups (None) are
    cached too, so they are not retried.
    """
    key = (target_name, qtype)
    if key not in CACHE:
        CACHE[key] = _lookup_uncached(target_name, qtype)
    return CACHE[key]


def collect_results(name):
    """
    Parse final answers into the structure print_results needs.
    Follows CNAME chains, then queries A/AAAA/MX on the final name.
    """
    full_response = {"CNAME": [], "A": [], "AAAA": [], "MX": []}
    current = dns.name.from_text(name)

    # Follow the CNAME chain, one link at a time.
    for _ in range(10):  # cap to avoid CNAME loops
        response = lookup(current, dns.rdatatype.CNAME)
        if response is None:
            break
        target = None
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.CNAME:
                target = rrset[0].target
                break
        if target is None:
            break
        full_response["CNAME"].append({"alias": text(current),
                                       "name": text.to_text()})
        current = target

    # Query records on the final name.
    response = lookup(current, dns.rdatatype.A)
    if response is not None:
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.A:
                for rdata in rrset:
                    full_response["A"].append({"name": text(rrset.name),
                                               "address": rdata.address})

    response = lookup(current, dns.rdatatype.AAAA)
    if response is not None:
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.AAAA:
                for rdata in rrset:
                    full_response["AAAA"].append({"name": text(rrset.name),
                                                  "address": rdata.address})

    response = lookup(current, dns.rdatatype.MX)
    if response is not None:
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.MX:
                for rdata in rrset:
                    full_response["MX"].append({"name": text(rrset.name),
                                                "preference": rdata.preference,
                                                "exchange": str(rdata.exchange)})

    return full_response


def print_results(results):
    """
    Print results the way the host program would.
    """
    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))


def main():
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("name", nargs="+",
                                 help="DNS name(s) to look up")
    argument_parser.add_argument("-v", "--verbose",
                                 help="increase output verbosity",
                                 action="store_true")
    program_args = argument_parser.parse_args()

    for a_domain_name in program_args.name:
        try:
            results = collect_results(a_domain_name)
        except Exception:
            results = {}

        if not any(results.get(k) for k in ("CNAME", "A", "AAAA", "MX")):
            # Never print nothing: say what happened.
            print(f"{a_domain_name}: lookup failed or no records found")
        else:
            print_results(results)


if __name__ == "__main__":
    main()