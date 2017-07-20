#!/usr/bin/env python
# coding: utf-8

import logging
import time
import ovh
import ovh.exceptions
import dns.resolver
import re
import sys
import socket

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)

client = ovh.Client()
PATTERN_DOMAIN = re.compile(r'^(.*)\.([^\.]+\.[^\.]+)$')
PATTERN_SUB_DOMAIN = re.compile(r'^(.*)\.([^\.]+)$')
REGEX_REMOVE_FINAL_DOT = re.compile(r"""(.*)\.$""")


def retrieve_domain_and_record_name(domain):
    """
    Split domain name into sub_domain and primary domain
    """
    result = PATTERN_DOMAIN.findall(domain)
    record_name = '_acme-challenge'
    if result:
        sub_domain, domain = result[0]
        sub_domain, domain = handling_special_tlds_case(sub_domain, domain)
        record_name = "{0}.{1}".format('_acme-challenge', sub_domain)

    return (record_name, domain)


def handling_special_tlds_case(sub_domain, domain):
    """Some tlds are formatted in two parts: for example, .asso.fr
       We have to retrive the right domain and subdomain to match with OVH API
    """
    try:
        client.get("/domain/zone/{0}".format(domain))
    except ovh.exceptions.ResourceNotFoundError as exception_catched:
        result = PATTERN_SUB_DOMAIN.findall(sub_domain)
        if not result:
            raise exception_catched
        sub_domain, alternative_sub_domain = result[0]
        return handling_special_tlds_case(sub_domain, "{0}.{1}".format(alternative_sub_domain, domain))
    return (sub_domain, domain)


def check_if_record_is_deployed(domain, dns_record, token):
    """
    Retrieve names servers of the domain, and check DNS record presence.
    """
    dns_servers = dns.resolver.query(domain, 'NS')
    resolver = dns.resolver.Resolver()
    resolver.nameservers = []
    for dns_server in dns_servers:
        addresses = socket.getaddrinfo(dns_server.to_text(), 53)
        for family, socktype, proto, canonname, sockaddr in addresses:
            resolver.nameservers.append(sockaddr[0])
    while True:
        logger.debug("Testing DNS record against " + ', '.join(resolver.nameservers))
        txt_values = []
        try:
            txt_records = resolver.query('{}.{}'.format(dns_record, domain), 'TXT')
            for txt_record in txt_records:
                txt_values.append(txt_record.to_text())
            for txt_value in txt_values:
                if token in txt_value:
                    return
        except dns.resolver.NXDOMAIN:
            logger.info(" + Record not available yet. Checking again in 10s...")
        logger.debug("Got: " + str(', '.join(txt_values)) + " /  Expecting: " + str(token))
        time.sleep(10)


def refresh_ovh_dns_zone(domain):
    """
    Refresh DNS Zone against OVH API
    """
    client.post('/domain/zone/{0}/refresh'.format(domain))
    logger.info("+ Zone refreshed on OVH side")
    soa = client.get('/domain/zone/{0}/soa'.format(domain))
    logger.debug("+ SOA SERIAL of zone: {0}".format(soa['serial']))


def create_txt_record(args):
    """
    Create TXT record for the Dehydrated ACME challenge
    """
    domain, token = args[0], args[2]

    record_name, domain = retrieve_domain_and_record_name(domain)

    dns_record = client.post("/domain/zone/{0}/record".format(domain), fieldType='TXT',
                             subDomain=record_name, target=token, ttl=1)
    record_id = dns_record['id']
    logger.debug("+ TXT record created, ID: {0}".format(record_id))
    refresh_ovh_dns_zone(domain)

    check_if_record_is_deployed(domain, record_name, token)


def delete_txt_record(args):
    """
    Delete TXT record from DNS zone after challenge have been sucessfully answered
    """
    domain, token = args[0], args[2]
    if not domain:
        logger.info(" + http_request() error in letsencrypt.sh?")
        return

    record_name, domain = retrieve_domain_and_record_name(domain)

    records = client.get("/domain/zone/{0}/record".format(domain), fieldType='TXT', subDomain=record_name)

    if len(records) <= 0:
        raise Exception("No record found for {0}".format(record_name))
    if len(records) > 1:
        raise Exception("Too many record found for {0}. Please clean your DNS".format(record_name))

    logger.debug(" + Deleting TXT record name: {0}".format(record_name))
    client.delete('/domain/zone/{0}/record/{1}'.format(domain, records[0]))
    refresh_ovh_dns_zone(domain)


def deploy_cert(args):
    domain, privkey_pem, cert_pem, fullchain_pem, chain_pem, timestamp = args
    logger.info(' + ssl_certificate: {0}'.format(fullchain_pem))
    logger.info(' + ssl_certificate_key: {0}'.format(privkey_pem))
    return


def unchanged_cert(args):
    logger.info(' + Certificate still valid. Nothing to do here')
    return


def invalid_challenge(args):
    logger.info(' + Challenge was invalid, please have a look')
    return

def exit_hook(args):
    logger.info(' + Exiting OVH hook')
    return

def startup_hook(args):
    logger.info(' + Startup OVH hook')
    return

def main(argv):
    ops = {
        'deploy_challenge': create_txt_record,
        'clean_challenge': delete_txt_record,
        'deploy_cert': deploy_cert,
        'unchanged_cert': unchanged_cert,
        'invalid_challenge': invalid_challenge,
        'exit_hook': exit_hook,
        'startup_hook': startup_hook,
    }
    logger.info(" + OVH hook executing: {0}".format(argv[0]))
    ops[argv[0]](argv[1:])


if __name__ == '__main__':
    main(sys.argv[1:])
