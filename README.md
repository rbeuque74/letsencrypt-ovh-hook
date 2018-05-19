# OVH hook for dehydrated ACME client

This a hook for [dehydrated](https://github.com/lukas2511/dehydrated) (a [Let's Encrypt](https://letsencrypt.org/) ACME client) that allows you to use [OVH](https://www.ovh.com/) DNS records to respond to `dns-01` challenges. Requires Python and your OVH API Credentials being set in the ovh.conf file.

Let's Encrypt validation is usually done by file: you will have to add a specified file into a specific folder, or even you will have to start Let's Encrypt program instead of your web-server to serve the validation file.
With DNS validation, you don't have to touch anything on your web-server, you just have to modify a record on your domain name DNS entries, and you're all set.

OVH Hook for [dehydrated](https://github.com/lukas2511/dehydrated) take care of that part: it will automatically connect to the OVH API and modify your DNS record in order to match the Let's Encrypt challenge. At the end, you will receive your SSL certificate without any connection to your web-server !


Based on [kappataumu](https://github.com/kappataumu/letsencrypt-cloudflare-hook) work for a competitor DNS validation hook.

## Setup

```
$ git clone https://github.com/lukas2511/dehydrated
$ cd dehydrated
$ mkdir hooks
$ git clone https://github.com/rbeuque74/letsencrypt-ovh-hook hooks/ovh
$ pip install -r hooks/ovh/requirements.txt
$ cp hooks/ovh/ovh.conf.dist ./ovh.conf
$ editor ovh.conf
```


## Usage

```
$ ./dehydrated -s example.ovh.csr -d example.ovh -t dns-01 -k 'hooks/ovh/hook.py'
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

With configuration file:

```
$ cat config
HOOK=hooks/ovh/hook.py
CHALLENGETYPE="dns-01"

$ ./dehydrated -c
[ ... ]
 + Done!
```


### Log level

Verbosity of OVH dehydrated hook can be configured using the ```level``` option:

```
$ cat config
# warn level will only display errors
HOOK=hooks/ovh/hook.py --level=warn

# info level will display all humans readable logs (info is the default value if level option is not provided)
HOOK=hooks/ovh/hook.py --level=info

# for all debugging log
HOOK=hooks/ovh/hook.py --level=debug
```

If ```level``` option is not provided, the default value ```info``` will be used.
