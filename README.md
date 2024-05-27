# LDAPreckon

## Overiview
LDAPreckon is a Python script designed for enumerating LDAP information from a Domain Controller. This tool can be used to extract various pieces of information, including user accounts, privileged accounts, groups, and computer objects within an Active Directory environment.

## Features
- User and Group Enumeration: Enumerates domain users, groups, and their memberships.
- Privileged Accounts Identification: Lists accounts with administrative privileges.
- Computer Enumeration: Lists computer objects within the domain.
- Service Account Identification: Identifies service accounts.
- Password in Description Field Detection: Searches for users with potential passwords in their description fields.
- Kerberoastable and ASREPRoastable Users Detection: Identifies users vulnerable to Kerberoasting and ASREPRoasting attacks.
- Unconstrained Delegation Detection: Lists users and computers with unconstrained delegation enabled.
- Output to File: Optionally saves query results to a specified output file.


## Requirements
Python 3.x
ldap3 library
You can install the required library using pip:
```sh
pip install ldap3
```
## Usage
```sh
python ldap_enum.py DCIP -U username -P password [options]
```

### Positional Arguments
- DCIP: IP address of the Domain Controller.
**Required Arguments**
- -U, --username: Username of the domain.
- -P, --password: Password of the domain user.
**Optional Arguments**
- -us, --users: Search only for domain users.
- -ug, --usergroup USERNAME: Search for groups that a specific user belongs to.
- -a, --admins: Search only for domain admins.
- -g, --gadmins: Search only for groups with admin privileges.
- -ad, --admincount: Search for accounts with admin count set to 1.
- -c, --computers: Show only computer objects.
- -s, --services: Show only service accounts.
- -pw, --pwdusers: Search for users with potential passwords in their description fields.
- -unp, --unprivusers: Search for users with no privileges.
- -k, --kerberoast: Search for Kerberoastable users.
- -as, --asreproast: Search for ASREPRoastable users.
- -uu, --uncusers: Search for users with unconstrained delegation.
- -uc, --unccopmuters: Search for computers with unconstrained delegation.
- -o, --output_file FILE: Specify an output file to save the query results.

## Example
```sh
python ldap_enum.py 192.168.1.100 -U admin -P password -us -o results.txt
```
