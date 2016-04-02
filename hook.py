#!/usr/bin/env python
# coding: utf-8

import logging
import time
import ovh
import re
import subprocess
import sys

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)

client = ovh.Client()
DNS_SERVER_DIG = "208.67.220.220" # DNS from OpenDNS, usually fast
PATTERN_DOMAIN = re.compile(r'^(.*)\.([^\.]+\.[^\.]+)$')


def retrieve_domain_and_record_name(domain):
    result = PATTERN_DOMAIN.findall(domain)
    record_name = '_acme-challenge'
    if result:
        sub_domain, domain = result[0]
        record_name = "{0}.{1}".format('_acme-challenge', sub_domain)

    return (record_name, domain)


def check_if_record_is_deployed(domain, token):
    while True:
        result = subprocess.Popen(['dig', '@{0}'.format(DNS_SERVER_DIG), '-t', 'TXT', domain, '+short'],
                                  stdout=subprocess.PIPE).communicate()[0]
        if token in str(result):
            return
        logger.debug("Got: " + str(result) + " /  Expecting: " + str(token))
        logger.info(" + Record not available yet. Checking again in 10s...")
        time.sleep(10)


def refresh_ovh_dns_zone(domain):
    client.post('/domain/zone/{0}/refresh'.format(domain))
    logger.info("+ Zone refreshed on OVH side")
    soa = client.get('/domain/zone/{0}/soa'.format(domain))
    logger.debug("+ SOA SERIAL of zone: {0}".format(soa['serial']))


def create_txt_record(args):
    domain, token = args[0], args[2]

    record_name, domain = retrieve_domain_and_record_name(domain)

    dns_record = client.post("/domain/zone/{0}/record".format(domain), fieldType='TXT',
                             subDomain=record_name, target=token, ttl=1)
    record_id = dns_record['id']
    logger.debug("+ TXT record created, ID: {0}".format(record_id))
    refresh_ovh_dns_zone(domain)

    check_if_record_is_deployed(record_name + "." + domain, token)


def delete_txt_record(args):
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


def main(argv):
    ops = {
        'deploy_challenge': create_txt_record,
        'clean_challenge' : delete_txt_record,
        'deploy_cert'     : deploy_cert,
        'unchanged_cert'  : unchanged_cert,
    }
    logger.info(" + OVH hook executing: {0}".format(argv[0]))
    ops[argv[0]](argv[1:])


if __name__ == '__main__':
    main(sys.argv[1:])
