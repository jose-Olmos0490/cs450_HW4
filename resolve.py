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


def collect_results(name: str) -> dict:
    """
    This function parses final answers into the proper data structure that
    print_results requires. The main work is done within the `lookup` function.
    """
    full_response = {}
    target_name = dns.name.from_text(name)

    # lookup CNAME
    response = lookup(target_name, dns.rdatatype.CNAME)
    if response is None:
        return full_response
    cnames = []
    tmp = name
    for answers in response.answer:
        for answer in answers:
            cnames.append({"name": answer, "alias": tmp})
            tmp = answer

    # lookup A
    response = lookup(target_name, dns.rdatatype.A)
    if response is None:
        return full_response
    arecords = []
    for answers in response.answer:
        a_name = answers.name
        for answer in answers:
            if answer.rdtype == 1:  # A record
                arecords.append({"name": a_name, "address": str(answer)})

    # lookup AAAA
    response = lookup(target_name, dns.rdatatype.AAAA)
    if response is None:
        return full_response
    aaaarecords = []
    for answers in response.answer:
        aaaa_name = answers.name
        for answer in answers:
            if answer.rdtype == 28:  # AAAA record
                aaaarecords.append({"name": aaaa_name, "address": str(answer)})

    # lookup MX
    response = lookup(target_name, dns.rdatatype.MX)
    if response is None:
        return full_response
    mxrecords = []
    for answers in response.answer:
        mx_name = answers.name
        for answer in answers:
            if answer.rdtype == 15:  # MX record
                mxrecords.append({"name": mx_name,
                                  "preference": answer.preference,
                                  "exchange": str(answer.exchange)})

    full_response["CNAME"] = cnames
    full_response["A"] = arecords
    full_response["AAAA"] = aaaarecords
    full_response["MX"] = mxrecords

    return full_response


def get_referral_ips(response: dns.message.Message) -> list:
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


def lookup(target_name: dns.name.Name,
           qtype: dns.rdata.Rdata) -> dns.message.Message:
    """
    Iteratively resolve target_name for qtype, starting at a root server
    and following referrals until an answer appears.
    """
    outbound_query = dns.message.make_query(target_name, qtype)
    servers = [ROOT_SERVERS[0]]
    tried = set()

    while servers:
        server = servers.pop(0)
        if server in tried:
            continue
        tried.add(server)
        try:
            response = dns.query.udp(outbound_query, server, 3)
        except Exception:
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

        servers.extend(next_ips)

    return None


def print_results(results: dict) -> None:
    """
    take the results of a `lookup` and print them to the screen like the host
    program would.
    """

    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))


def resolve_ns_ip(ns_name: dns.name.Name) -> list:
    """
    Resolve an NS name with no glue to IPv4 addresses by looking up its A record.
    """
    response = lookup(ns_name, dns.rdatatype.A)
    if response is None:
        return []
    ips = []
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.A:
            for rdata in rrset:
                ips.append(rdata.address)
    return ips


def main():
    """
    if run from the command line, take args and call
    printresults(lookup(hostname))
    """
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("name", nargs="+",
                                 help="DNS name(s) to look up")
    argument_parser.add_argument("-v", "--verbose",
                                 help="increase output verbosity",
                                 action="store_true")
    program_args = argument_parser.parse_args()
    for a_domain_name in program_args.name:
        print_results(collect_results(a_domain_name))


if __name__ == "__main__":
    main()