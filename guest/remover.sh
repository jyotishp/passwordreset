#!/bin/bash

admin_password="Yes!ThisIsCorrectPassword@313"
admin_dn="cn=admin"
base_dn="ou=Guest,ou=Users,dc=iiit,dc=ac,dc=in"
ldap_host="ldap://ldap.iiit.ac.in"
to="someone@something"

expired_users=$(ldapsearch -H $ldap_host -x -b "$base_dn" "sambaSID>=`date +%s`" uid | grep uid: | awk '{print $2}')

for user in $expired_users
do
  email=ldapsearch -H $ldap_host -x -b "$base_dn" "uid=$user"
  if ldapdelete -H ldap://ldap.iiit.ac.in -x "uid=$user,$base_din" -D $admin_dn -w $admin_password >/dev/null 2>&1; then
    logger --prio-prefix "Guest remover" $email
  else
    error=$(ldapdelete -H ldap://ldap.iiit.ac.in -x "uid=$user,$base_din" -D $admin_dn -w $admin_password 2>&1)
    logger --prio-prefix "Guest remover" $error
    echo "$email: $error" | mailx -r "passwordreset@iiit.ac.in" -s "[Error] Failed to delete a user" $to
fi
done
