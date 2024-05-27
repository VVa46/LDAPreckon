from ldap3 import Server, Connection, BASE, ALL
import argparse

COLORS = {
    'blue': 94,
    'green': 92,
    'yellow': 93,
    'red': 91
}

def color_print(text, color):
    """Print text in the specified color."""
    try:
        code = COLORS[color]
    except KeyError:
        raise KeyError(f'Invalid text color: {color}')
    
    print(f'\033[{code}m{text}\033[0m')

def search_root_dse(dc_ip, dc_port=389):
    try:
        server = Server(dc_ip, port=dc_port)
        conn = Connection(server)
        
        # Bind to LDAP server anonymously
        conn.bind()
        
        # Search the root DSE with an empty search filter
        conn.search(search_base="", search_filter="(objectClass=*)", search_scope=BASE, attributes=["*"])
        
        if conn.entries:
            # Print information from the root DSE
            for entry in conn.entries:
                domain = entry["rootDomainNamingContext"].value
                return domain
        else:
            color_print("[-] No entries found in root DSE.",'yellow')
            exit(1)
    except Exception as e:
        color_print("Error:", e,'red')
    finally:
        conn.unbind()


def establish_connection(dc_ip, username, password, dc_port):
    try:
        # Set up LDAP connection
        server = Server(dc_ip, port=dc_port, get_info=ALL)
        conn = Connection(server, user=username, password=password, auto_bind=True)
        
        # Check if the connection is successful and print the user connected
        if conn.bound:
            color_print("[+] Connection successful.",'green')
            user_con = conn.extend.standard.who_am_i()
            color_print("[+] Logged in as " + user_con.removeprefix("u:"),'green')
            return conn
        else:
            color_print("Failed to bind to LDAP server.",'red')
            return None
    except Exception as e:
        color_print("Error:", e,'red')
        quit()


def close_connection(conn):
    # Close the connection
    try:
        conn.unbind()
    except Exception as e:
        color_print("Error while closing connection:", e,'red')

# print to file the output
def save_to_file(print_me):
    if args.output_file:
        with open(f'{args.output_file}', 'a') as f:
            # Append to the specified file
            f.write(print_me + "\n")

# flag to print only once the group name, non mi è venuto in mente altro...
#view_written = False
view_written = ""
def save_routine(view, to_print):
    global view_written
    if args.output_file:
        if view != view_written:
            save_to_file(view)
            view_written = view
        save_to_file(to_print)


## LIST ALL USERS
## -us/--users
def list_users():
    #conn = establish_connection(dc_ip, username, password, dc_port)
    try:
        # Search for user entities entries
        conn.search(search_base=domain, \
                    search_filter='(&(objectCategory=person)(objectClass=user))', \
                    attributes=['sAMAccountName'])
        
        # Print users found
        if conn.entries:
            view = ("[+] Users found: ")
            color_print(view,'blue')
            for entry in conn.entries:
                to_print = (" -  " + str(entry.sAMAccountName))
                print(to_print)
                # save output
                save_routine(view, to_print)
                
        else:
            color_print("[-] No user entries found.",'yellow')
    except Exception as e:
        color_print("Error:", e,'red')
        
## LIST USER's GROUPS
## -ug/--usergroup
def list_usergroup():
    #conn = establish_connection(dc_ip, username, password, dc_port)
    to_search = args.usergroup
    try:
        # Search for user entities entries
        conn.search(search_base=domain, \
                    search_filter=f' \
                    (&(objectCategory=user) \
                    (objectClass=user) \
                    (sAMAccountName={to_search})(memberOf=*))', \
                    attributes=['*'])

        if conn.entries:
            view = ("[+] The user is in the following groups: ")            
            color_print(view,'blue')
            for entry in conn.entries:
                groups = entry.memberOf.values
                for group in groups:
                    # Extract the CN part of the distinguished name using string manipulation
                    if group.startswith("CN="):
                        group_name = group.split(",")[0][3:]  # Remove "CN=" prefix
                        to_print = f" -  {group_name}"
                        print(to_print)
                        save_routine(view, to_print)
        else:
            color_print(f"[-] No groups found for user '{username}'.",'yellow')
    except Exception as e:
        color_print("Error:", e,'red')

## LIST PRIVILEGED USERS
## -a/--admins
def list_privilegeduser():
    try:
        # Search for user entities entries
        # primaryGroupID = 513 --> "Domain Admins" group
        conn.search(search_base=domain, \
                    search_filter= \
                    '(|(sAMAccountName=Domain Admins) \
                    (sAMAccountName=DnsAdmins) \
                    (sAMAccountName=Administrators) \
                    (sAMAccountName=Account Operators) \
                    (sAMAccountName=Backup Operators) \
                    (sAMAccountName=Schema Admins) \
                    (sAMAccountName=Enterprise Admins))', \
                    attributes=['cn', 'member', 'description'])
        
        # Print Privileged users found
        if conn.entries:
            view = ("[+] Privileged users found: ")
            color_print(view,'blue')
            #print(conn.entries)
            for entry in conn.entries:
                members = list(entry.member)
                desc = str(entry.description)
                group = str(entry.cn)
                for entry in members:
                    user = entry.split(',')[0].split('=')[1]
                    if len(desc) == 2:
                        to_print = (" -  " + user + " is in the group " + group)
                    else:
                        to_print = (" -  " + user + " is in the group " + group + " --> Description field: " + desc)
                    print(to_print)
                    # save output
                    save_routine(view, to_print)
                    
        else:
            color_print("[-] No privileged user entries found.", 'yellow')
    except Exception as e:
        color_print("Error:", e,'red')

## LIST ADMIN GROUPS
## -g/--gadmins
def list_admingroup():
    try:
        # Search for administrative group
        conn.search(search_base=domain, \
                    search_filter='(&(objectCategory=group)(adminCount=1))', \
                    attributes=['cn', 'description'])
        
        # Print administrative groups found
        if conn.entries:
            view = ("[+] Groups found with administrative privileges: ")
            color_print(view,'blue')
            for entry in conn.entries:
                #print(entry)
                user = str(entry.cn)
                desc = str(entry.description)
                if len(desc) == 2:
                    to_print = (" -  " + user)
                    print(to_print)
                else:
                    to_print = (" -  " + user + " --> Description field: " + desc)
                    print(to_print)
                save_routine(view, to_print)
                
        else:
            color_print("[-] No Groups found with administrative privileges.",'yellow')
    except Exception as e:
        color_print("Error:", e,'red')

## LIST  admincount1
## -ad/--admincount
def list_admincount():
    try:
        # Search for user entities entries
        # primaryGroupID = 513 --> "Domain Admins" group
        conn.search(search_base=domain, \
                    search_filter='(adminCount=1)', \
                    attributes=['cn', 'description'])
        
        # Print Privileged users found
        if conn.entries:
            view = ("[+] Admincount1 account found: ")
            color_print(view,'blue')
            for entry in conn.entries:
                #print(entry)
                user = str(entry.cn)
                desc = str(entry.description)
                if len(desc) == 2:
                    to_print = (" -  " + user)
                else:
                    to_print = (" -  " + user + " --> Description field: " + desc)
                print(to_print)
                # save output
                save_routine(view, to_print)
                
        else:
            color_print("[-] No privileged user entries found.",'yellow')
    except Exception as e:
        color_print("Error:", e,'red')

## LIST COMPUTERS
## -c/--computers
def list_computers():
    try:
        # Search for computer entities entries
        conn.search(search_base=domain, \
                    search_filter='(objectCategory=Computer)', \
                    attributes=['cn', 'operatingSystem', 'operatingSystemVersion', 'operatingSystemServicePack', 'sAMAccountName'])
        
        # Print computes found
        if conn.entries:
            view = ("[+] Computers found: ")
            color_print(view,'blue')
            for entry in conn.entries:
                if not entry.operatingSystem or not entry.operatingSystemVersion:
                    to_print = (" -  " + str(entry.sAMAccountName))
                else:
                    to_print = (" -  " + str(entry.sAMAccountName) + "  OS: " + str(entry.operatingSystem) + str(entry.operatingSystemVersion))
                print(to_print)
                # save output
                save_routine(view, to_print)

        else:
            color_print("[-] No computer entries found.",'yellow')
    except Exception as e:
        color_print("Error:", e,'red')

## FIND SERVICE ACCOUNT
## -s/--services
def list_services():
    try:
        # Search for user entities entries
        conn.search(search_base=domain, \
                    search_filter='(servicePrincipalName=*)', \
                    attributes=['cn', 'description'])
        
        # Print Services found
        if conn.entries:
            view = ("[+] Service account found: ")
            color_print(view,'blue')
            for entry in conn.entries:
                #print(entry)
                user = str(entry.cn)
                desc = str(entry.description)
                if len(desc) == 2:
                    to_print = (" -  " + user)
                else:
                    to_print = (" -  " + user + " --> Description field: " + desc)
                print(to_print)
                # save output
                save_routine(view, to_print)

        else:
            color_print("[-] No Service account found.",'yellow')
    except Exception as e:
        color_print("Error:", e,'red')

## CHECK IF THERE IS A PASSWORD IN THE COMMENT SECTION
## -pw/pwdusers
def list_users_wpassword():
    try:
        # Search for user with a description
        conn.search(search_base=domain,\
                    search_filter= \
                    '(&(objectCategory=user) \
                    (|(description=*pass*) \
                    (description=*pwd*) \
                    (description=*log*)))', \
                    attributes=['cn', 'description','sAMAccountName'])
        
        # Print Users with possible password in the description found
        if conn.entries:
            view = ("[+] Users found with possible password in the description field: ")
            color_print(view,'blue')
            for entry in conn.entries:
                #print(entry)
                user = str(entry.sAMAccountName)
                desc = str(entry.description)
                to_print = (" -  " + user + " --> Description field: " + desc)
                print(to_print)
                # save output
                save_routine(view, to_print)
                
        else:
            color_print("[-] No users with possible password found.",'yellow')
    except Exception as e:
        color_print("Error:", e,'red')

## LIST ALL USERS WITHOUT PRIVILEGES
## -unp/unprivusers
def list_users_noprv():
    try:
        # Search for user that are NOT in known privileged groups:
        # DnsAdmins, Enterprise Admins, Administrators, Domain Admins
        conn.search(search_base=domain, \
                    search_filter= \
                    f'(&(&(objectCategory=user)(objectClass=user) \
                    (!(|(memberOf=CN=DnsAdmins,CN=Users,{domain}) \
                    (memberOf=CN=Enterprise Admins,CN=Users,{domain}) \
                    (memberOf=CN=Administrators,CN=Users,{domain}) \
                    (memberOf=CN=Domain Admins,CN=Users,{domain})))))', \
                    attributes=['*'])
        
        # Print unpriv users found
        if conn.entries:
            view = ("[+] Users with no known privileges found: ")
            color_print(view,'blue')
            for entry in conn.entries:
                to_print = (" -  " + str(entry.sAMAccountName))
                print(to_print)
                # save output
                save_routine(view, to_print)
                
        else:
            color_print("[-] No user entries found.",'yellow')
    except Exception as e:
        print("Error:", e)

## LIST KERBEROSTABLE USERS
## KERBEROAST
## (&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
## -k/--kerberoast
def list_kerberusers():
    try:
        conn.search(search_base=domain, \
                    search_filter= \
                    '(&(objectClass=user)(servicePrincipalName=*) \
                    (!(cn=krbtgt)) \
                    (!(userAccountControl:1.2.840.113556.1.4.803:=2)))', \
                    attributes=['sAMAccountName', 'description'])
        
        # Print kerberostable users found
        if conn.entries:
            view = ("[+] Kerberoastable users found: ")
            color_print(view,'blue')
            for entry in conn.entries:
                desc = str(entry.description)
                if len(desc) == 2:
                    to_print = (" -  " + str(entry.sAMAccountName)) 
                    print(to_print)
                else:
                    to_print = (" -  " + str(entry.sAMAccountName) + " --> Description field: " + desc) 
                    print(to_print)
                # save output
                save_routine(view, to_print)
                
        else:
            color_print("[-] No roastableuser found.",'yellow')
    except Exception as e:
        color_print("Error:", e,'red')

## LIST ASREPROAST USERS
## ASREPROAST
## (&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))
## -as/--asreproast
def list_asrepusers():
    try:
        conn.search(search_base=domain, \
                    search_filter= \
                    '(&(objectClass=user) \
                    (userAccountControl:1.2.840.113556.1.4.803:=4194304))', \
                    attributes=['*'])
        
        # Print computes found
        if conn.entries:
            view = ("[+] ASREP-roastable users found: ")
            color_print(view,'blue')
            for entry in conn.entries:
                to_print = (" -  " + str(entry.sAMAccountName))
                print(to_print)
                # save output
                save_routine(view, to_print)
                
        else:
            color_print("[-] No ASREProastable user found.",'yellow')
    except Exception as e:
        color_print("Error:", e,'red')
        
## UNCONSTRAINED USERS    
## "(&(&(objectCategory=person)(objectClass=user))(userAccountControl:1.2.840.113556.1.4.803:=524288))"
## -uu/--uncuser
def list_uncostrainedusers():
    try:
        conn.search(search_base=domain, \
                    search_filter= \
                    '(&(&(objectCategory=person) \
                    (objectClass=user)) \
                    (userAccountControl:1.2.840.113556.1.4.803:=524288))', \
                    attributes=['*'])
        
        # Print computes found
        if conn.entries:
            view = ("[+] Unconstrained users found: ")
            color_print(view,'blue')
            for entry in conn.entries:
                to_print = (" -  " + str(entry.sAMAccountName))
                print(to_print)
                # save output
                save_routine(view, to_print)
            
        else:
            color_print("[-] No unconstrained user found.",'yellow')
    except Exception as e:
        color_print("Error:", e,'red')

## LIST UNCONSTRAINED COMPUTERS
## (&(&(objectCategory=person)(objectClass=user))(userAccountControl:1.2.840.113556.1.4.803:=524288))
## -uc/--unccopmuters
def list_uncostrainecomputers():
    try:
        conn.search(search_base=domain, \
                    search_filter= \
                    '(&(&(objectCategory=person) \
                    (objectClass=user)) \
                    (userAccountControl:1.2.840.113556.1.4.803:=524288))', \
                    attributes=['*'])
        
        # Print computes found
        if conn.entries:
            view = ("[+] Unconstrained computers found: ")
            color_print(view,'blue')
            for entry in conn.entries:
                to_print = (" -  " + str(entry.sAMAccountName)) 
                print(to_print)
                # save output
                save_routine(view, to_print)

        else:
            color_print("[-] No unconstrained computer found.",'yellow')
    except Exception as e:
        color_print("Error:", e,'red')


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(
                prog='LDAPreckon', 
                description="LDAP enumeration tool.",
                usage="python3 LDAPrecon.py DCIP -U username -P password",
                epilog="GG")
    
    parser.add_argument("DCIP", type=str, help="Domain Controller IP address.")
    parser.add_argument('-U', '--username',required=True, help="Username of the domain")
    parser.add_argument('-P', '--password', required=True, help="Password of the domain user")
    parser.add_argument('-us', '--users', required=False, action="store_true", help="Search ONLY domain users")
    parser.add_argument('-ug', '--usergroup', required=False, action="store", help="Search user's groups")
    parser.add_argument('-a', '--admins', required=False, action="store_true", help="Search ONLY domain admins")
    parser.add_argument('-g', '--gadmins', required=False, action="store_true", help="Search ONLY domain group with admin privileges")
    parser.add_argument('-ad', '--admincount', required=False, action="store_true", help="Search for admins")
    parser.add_argument('-c', '--computers', required=False, action="store_true", help="Show ONLY computer objects")
    parser.add_argument('-s', '--services', required=False, action="store_true", help="Show ONLY service accounts")
    parser.add_argument('-pw', '--pwdusers', required=False, action="store_true", help="Search for users with possible password in the description field")
    parser.add_argument('-unp', '--unprivusers', required=False, action="store_true", help="Search for users with no privileges")
    parser.add_argument('-k', '--kerberoast', required=False, action="store_true", help="Search for Kerberoastable users")
    parser.add_argument('-as', '--asreproast', required=False, action="store_true", help="Search for Asreproastable users")
    parser.add_argument('-uu', '--uncusers', required=False, action="store_true", help="Search for Unconstrained users")
    parser.add_argument('-uc', '--unccopmuters', required=False, action="store_true", help="Search for Unconstrained users")
    parser.add_argument('-o', '--output_file', required=False, help="Output file to store query results",action='store')

    args = parser.parse_args()
    
    
    dc_ip = args.DCIP
    dc_port = 389
    username = args.username
    password = args.password
    domain = search_root_dse(dc_ip)

    
    # OPEN THE CONNECTION
    conn = establish_connection(dc_ip, username, password, dc_port)
    
    # Check if 1 or more optional argument is specified and execute it,
    # if no optional argument are specified prints all the queries
    specified_queries = []

    if args.users:
        specified_queries.append(list_users())
    if args.usergroup:
        specified_queries.append(list_usergroup())
    if args.admins:
        specified_queries.append(list_privilegeduser())
    if args.services:
        specified_queries.append(list_services())
    if args.computers:
        specified_queries.append(list_computers())
    if args.gadmins:
        specified_queries.append(list_admingroup())        
    if args.pwdusers:
        specified_queries.append(list_users_wpassword())
    if args.admincount:
        specified_queries.append(list_admincount())
    if args.kerberoast:
        specified_queries.append(list_kerberusers())
    if args.asreproast:
        specified_queries.append(list_asrepusers())
    if args.uncusers:
        specified_queries.append(list_uncostrainedusers())
    if args.unccopmuters:
        specified_queries.append(list_uncostrainecomputers())
    if args.unprivusers:
        specified_queries.append(list_users_noprv())

    # RUN ONLY THE SELECTED QUERY
    if specified_queries:
        for query in specified_queries:
            query       
    else:
        list_users()
        list_users_noprv()
        list_privilegeduser()
        list_services()
        list_admingroup()
        list_computers()
        list_users_wpassword()
        list_kerberusers()
        list_asrepusers()
        list_uncostrainedusers()
        list_uncostrainecomputers()

    # CLOSE THE CONNECTION
    close_connection(conn)
