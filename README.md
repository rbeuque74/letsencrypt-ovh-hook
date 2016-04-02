# OVH hook for letsencrypt.sh ACME client

This a hook for [letsencrypt.sh](https://github.com/lukas2511/letsencrypt.sh) (a [Let's Encrypt](https://letsencrypt.org/) ACME client) that allows you to use [OVH](https://www.ovh.com/) DNS records to respond to `dns-01` challenges. Requires Python and your OVH API Credentials being set in the ovh.conf file.

Based on [kappataumu](https://github.com/kappataumu/letsencrypt-cloudflare-hook) work.

## Setup

```
$ git clone https://github.com/lukas2511/letsencrypt.sh
$ cd letsencrypt.sh
$ mkdir hooks
$ git clone https://github.com/rbeuque74/letsencrypt-ovh-hook hooks/ovh
$ pip install -r hooks/ovh/requirements.txt
$ cp hooks/ovh/ovh.conf.dist ./ovh.conf
$ editor ovh.conf
```


## Usage

```
$ ./letsencrypt.sh -s example.ovh.csr -d example.ovh -t dns-01 -k 'hooks/ovh/hook.py'
#
# !! WARNING !! No main config file found, using default config!
#
Processing example.ovh
 + Requesting challenge for example.ovh...
 + OVH hook executing: deploy_challenge
 + Zone refreshed on OVH side
 + Record not available yet. Checking again in 10s...
 + Record not available yet. Checking again in 10s...
 + Record not available yet. Checking again in 10s...
 + Record not available yet. Checking again in 10s...
 + Responding to challenge for example.ovh...
 + OVH hook executing: clean_challenge
 + Deleting TXT record name: _acme-challenge
 + Zone refreshed on OVH side
 + Challenge is valid!
 + Requesting certificate...
 + Checking certificate...
-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----
 + Done!
```

