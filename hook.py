#!/usr/bin/env python
# coding: utf-8

import logging
import time
import ovh
import ovh.exceptions
import dns.resolver
import dns.exception
import re
import sys
import socket

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

client = ovh.Client()
PATTERN_DOMAIN = re.compile(r'^(.*)\.([^\.]+\.[^\.]+)$')
PATTERN_SUB_DOMAIN = re.compile(r'^(.*)\.([^\.]+)$')
PATTERN_LOG_LEVEL = re.compile(r'^--level=(\w+)$')


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
    """
    Some tlds are formatted in two parts: for example, .asso.fr
    We have to retrieve the corresponding domain and subdomain to match with OVH API
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
    resolver.timeout = 3
    resolver.lifetime = 5
    for dns_server in dns_servers:
        addresses = socket.getaddrinfo(dns_server.to_text(), 53, 0, 0, socket.IPPROTO_TCP)
        for family, socktype, proto, canonname, sockaddr in addresses:
            resolver.nameservers.append(sockaddr[0])
    while True:
        logger.debug(" + Testing DNS record against %s", ', '.join(resolver.nameservers))
        txt_values = []
        try:
            txt_records = resolver.query('{}.{}'.format(dns_record, domain), 'TXT')
            for txt_record in txt_records:
                txt_values.append(txt_record.to_text())
            for txt_value in txt_values:
                if token in txt_value:
                    return
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            logger.debug(" + Record not available yet. Checking again in 10s...")
        except dns.exception.Timeout:
            logger.debug(" + DNS Request timeout. Checking again in 10s...")
        logger.debug(" + %s DNS entry value: %s ; expecting: '%s'", dns_record, ', '.join(txt_values), token)
        time.sleep(10)


def refresh_ovh_dns_zone(domain):
    """
    Refresh DNS Zone against OVH API
    """
    client.post('/domain/zone/{0}/refresh'.format(domain))
    logger.debug(" + Zone refreshed on OVH side")
    soa = client.get('/domain/zone/{0}/soa'.format(domain))
    logger.debug(" + SOA SERIAL of zone: %d", soa['serial'])


def create_txt_record(args):
    """
    Create TXT record for the Dehydrated ACME challenge
    """
    domain, token = args[0], args[2]

    logger.info("Deploying challenge for '%s' to OVH DNS", domain)

    record_name, domain = retrieve_domain_and_record_name(domain)

    dns_record = client.post("/domain/zone/{0}/record".format(domain), fieldType='TXT',
                             subDomain=record_name, target=token, ttl=1)
    record_id = dns_record['id']
    logger.debug(" + TXT record created, ID: %d", record_id)
    refresh_ovh_dns_zone(domain)

    logger.info("Challenge for '%s' deployed, waiting for DNS refresh", domain)
    check_if_record_is_deployed(domain, record_name, token)


def delete_txt_record(args):
    """
    Delete TXT record from DNS zone after challenge have been sucessfully answered
    """
    domain, token = args[0], args[2]

    logger.info("Cleaning OVH DNS entries for '%s'", domain)

    record_name, domain = retrieve_domain_and_record_name(domain)

    records = client.get("/domain/zone/{0}/record".format(domain), fieldType='TXT', subDomain=record_name)

    record_to_delete = None
    for record_id in records:
        record = client.get("/domain/zone/{0}/record/{1}".format(domain, record_id))
        if record["target"] == token:
            record_to_delete = record_id
            break
    else:
        raise Exception("No DNS record matches for {0} domain and given ACME token".format(record_name))

    logger.debug(" + Deleting TXT record name: %s", record_name)
    client.delete('/domain/zone/{0}/record/{1}'.format(domain, record_to_delete))
    refresh_ovh_dns_zone(domain)


def deploy_cert(args):
    """
    deploy_cert is triggered when certificate have been generated and available on filesystem.
    You can modify this function to move the certificates to your web-servers directory, and refresh web-servers to serve the new certificates.
    """
    domain, privkey_pem, cert_pem, fullchain_pem, chain_pem, timestamp = args
    logger.info("Certificate successfully created for '%s'.", domain)
    logger.info("Private key: %s", privkey_pem)
    logger.info("Full chain certificate: %s", fullchain_pem)
    return


def unchanged_cert(args):
    domain = args[0]
    logger.info("Certificate for '%s' is still valid.", domain)
    return

def invalid_challenge(args):
    domain, response = args[0], args[1]
    logger.warning("Challenge for domain '%s' was invalid, please have a look: %s", domain, response)
    return

def request_failure(args):
    status_code, reason = args[0], args[1]
    logger.warning("Request to Let's Encrypt failed: %s", reason)
    return

def main(argv):
    ops = {
        'deploy_challenge': create_txt_record,
        'clean_challenge': delete_txt_record,
        'deploy_cert': deploy_cert,
        'unchanged_cert': unchanged_cert,
        'invalid_challenge': invalid_challenge,
        'request_failure': request_failure,
    }

    # Log level
    log_level = PATTERN_LOG_LEVEL.findall(argv[0])
    if log_level:
        level = log_level[0].lower()
        if level in ('warn', 'warning'):
            logger.setLevel(logging.WARNING)
        elif level == 'info':
            logger.setLevel(logging.INFO)
        elif level == 'debug':
            logger.setLevel(logging.DEBUG)
        argv.pop(0)

    action = argv[0]
    args = argv[1:]
    if action not in ops:
        return

    ops[action](args)


if __name__ == '__main__':
    main(sys.argv[1:])
