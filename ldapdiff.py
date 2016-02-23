#!/usr/bin/env
#Monitor changes in certain ldap groups and create pagerduty alerts when users are added/removed
import sys, ldap, json, requests

########## CONFIG #########
groups = ['secops', 'engineering', 'developers']
ldap_url = 'ldaps://yourldap.ur.com:5636/'
basedn = 'ou=groups,dc=company,dc=com'

service_key = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXX'
pg_url = 'https://events.pagerduty.com/generic/2010-04-15/create_event.json'
########## CONFIG #########




def send_alert(name, body):
        # post to pagerduty
        headers = {'content-type': 'application/json'}
        payload = {
            'service_key': service_key,
            'description': name,
            'event_type': 'trigger',
            'client': 'LdapDiff',
            'details': {
                "information": body,
            },
        }

        try:
                response = requests.post(pg_url, data=json.dumps(payload), headers=headers)
        except Exception, e:
                print "[-] Error: %s" % e
                sys.exit()


def compare(groups):
        try:
                for i in groups:
                        l = ldap.initialize(ldap_url)
                        l.simple_bind_s()
                        xtr = l.search_s('cn='+i+','+basedn, ldap.SCOPE_BASE)
                        usr = xtr[0][1]['memberUid']
                        usr.sort()
                        orig = open('orig/'+i+'.txt').read().split('\n')
                        rmvdusr = list(set(orig[:-1]) - set(usr))
                        addusr = list(set(usr) - set(orig[:-1]))
                        if rmvdusr:
                                name = "User(s) deleted from group %s:" % i
                                body = rmvdusr
                                print name
                                print body
                                send_alert(name,body)
                        if addusr:
                                name = "User(s) added to group %s:" % i
                                body = addusr
                                print name
                                print body
                                send_alert(name,body)
                l.unbind_s()

        except Exception, e:
                print "[-] Error: %s" % e
                l.unbind_s()
                sys.exit()


def main():
        compare(groups)

if __name__ == "__main__":
        main()
