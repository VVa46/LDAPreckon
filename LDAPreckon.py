from ldap3 import Server, Connection, BASE, ALL
import argparse

COLORS = {
    'blue': 94,
    'green': 92,
    'yellow': 93,
    'red': 91
}

def color_print(text, color):
    """Stampa il testo nel colore specificato."""
    try:
        code = COLORS[color]
    except KeyError:
        raise KeyError(f'Colore testo non valido: {color}')
    
    print(f'\033[{code}m{text}\033[0m')

def search_root_dse(dc_ip, dc_port=389):
    """Cerca il root DSE per ottenere il dominio di base."""
    try:
        server = Server(dc_ip, port=dc_port)
        conn = Connection(server)
        
        # Bind al server LDAP anonimamente
        conn.bind()
        
        # Cerca il root DSE con un filtro di ricerca vuoto
        conn.search(search_base="", search_filter="(objectClass=*)", search_scope=BASE, attributes=["*"])
        
        if conn.entries:
            # Stampa le informazioni dal root DSE
            for entry in conn.entries:
                domain = entry["rootDomainNamingContext"].value
                return domain
        else:
            color_print("[-] Nessuna entry trovata nel root DSE.",'yellow')
            exit(1)
    except Exception as e:
        color_print(f"Errore: {e}",'red')
        exit(1)
    finally:
        conn.unbind()


def establish_connection(dc_ip, username, password, dc_port):
    """Stabilisce la connessione al server LDAP."""
    try:
        # Configura la connessione LDAP
        server = Server(dc_ip, port=dc_port, get_info=ALL)
        conn = Connection(server, user=username, password=password, auto_bind=True)
        
        # Verifica se la connessione è riuscita e stampa l'utente connesso
        if conn.bound:
            color_print("[+] Connessione riuscita.",'green')
            user_con = conn.extend.standard.who_am_i()
            color_print("[+] Connesso come " + user_con.removeprefix("u:"),'green')
            return conn
        else:
            color_print("Impossibile fare bind al server LDAP.",'red')
            return None
    except Exception as e:
        color_print(f"Errore: {e}",'red')
        exit(1)


def close_connection(conn):
    """Chiude la connessione LDAP."""
    try:
        if conn and conn.bound:
            conn.unbind()
    except Exception as e:
        color_print(f"Errore durante la chiusura della connessione: {e}",'red')

def save_to_file(print_me):
    """Salva l'output nel file specificato."""
    if args.output_file:
        try:
            with open(f'{args.output_file}', 'a', encoding='utf-8') as f:
                # Aggiunge al file specificato
                f.write(print_me + "\n")
        except Exception as e:
            color_print(f"Errore nel salvataggio del file: {e}", 'red')

# Flag per stampare solo una volta il nome del gruppo
view_written = ""
def save_routine(view, to_print):
    """Routine per salvare l'output evitando duplicati delle intestazioni."""
    global view_written
    if args.output_file:
        if view != view_written:
            save_to_file(view)
            view_written = view
        save_to_file(to_print)

def is_description_empty(desc):
    """Verifica se la descrizione è vuota o contiene solo placeholder."""
    return desc is None or str(desc) in ["[]", "", "None"]

def check_connection(conn):
    """Verifica se la connessione è ancora attiva."""
    if not conn or not conn.bound:
        color_print("[-] Connessione non attiva.", 'red')
        return False
    return True

## ELENCA TUTTI GLI UTENTI
## -us/--users
def list_users():
    """Elenca tutti gli utenti del dominio."""
    if not check_connection(conn):
        return
        
    try:
        # Cerca le entità utente
        conn.search(search_base=domain, 
                    search_filter='(&(objectCategory=person)(objectClass=user))', 
                    attributes=['sAMAccountName'])
        
        # Stampa gli utenti trovati
        if conn.entries:
            view = "[+] Utenti trovati:"
            color_print(view,'blue')
            for entry in conn.entries:
                to_print = f" -  {str(entry.sAMAccountName)}"
                print(to_print)
                # Salva output
                save_routine(view, to_print)
                
        else:
            color_print("[-] Nessun utente trovato.",'yellow')
    except Exception as e:
        color_print(f"Errore: {e}",'red')
        
## ELENCA I GRUPPI DELL'UTENTE
## -ug/--usergroup
def list_usergroup():
    """Elenca i gruppi di un utente specifico."""
    if not check_connection(conn):
        return
        
    if not args.usergroup:
        color_print("[-] Nome utente non specificato per la ricerca gruppi.", 'red')
        return
        
    to_search = args.usergroup
    try:
        # Cerca le entità utente
        conn.search(search_base=domain, 
                    search_filter=f'(&(objectCategory=user)(objectClass=user)(sAMAccountName={to_search})(memberOf=*))', 
                    attributes=['*'])

        if conn.entries:
            view = f"[+] L'utente {to_search} è nei seguenti gruppi:"            
            color_print(view,'blue')
            for entry in conn.entries:
                groups = entry.memberOf.values
                for group in groups:
                    # Estrae la parte CN del distinguished name usando manipolazione stringhe
                    if group.startswith("CN="):
                        group_name = group.split(",")[0][3:]  # Rimuove il prefisso "CN="
                        to_print = f" -  {group_name}"
                        print(to_print)
                        save_routine(view, to_print)
        else:
            color_print(f"[-] Nessun gruppo trovato per l'utente '{to_search}'.",'yellow')
    except Exception as e:
        color_print(f"Errore: {e}",'red')

## ELENCA UTENTI PRIVILEGIATI
## -a/--admins
def list_privilegeduser():
    """Elenca gli utenti con privilegi amministrativi."""
    if not check_connection(conn):
        return
        
    try:
        # Cerca le entità utente
        conn.search(search_base=domain, 
                    search_filter='(|(sAMAccountName=Domain Admins)(sAMAccountName=DnsAdmins)(sAMAccountName=Administrators)(sAMAccountName=Account Operators)(sAMAccountName=Backup Operators)(sAMAccountName=Schema Admins)(sAMAccountName=Enterprise Admins))', 
                    attributes=['cn', 'member', 'description'])
        
        # Stampa gli utenti privilegiati trovati
        if conn.entries:
            view = "[+] Utenti privilegiati trovati:"
            color_print(view,'blue')
            for entry in conn.entries:
                members = list(entry.member) if entry.member else []
                desc = str(entry.description) if entry.description else ""
                group = str(entry.cn)
                for member in members:
                    user = member.split(',')[0].split('=')[1]
                    if is_description_empty(desc):
                        to_print = f" -  {user} è nel gruppo {group}"
                    else:
                        to_print = f" -  {user} è nel gruppo {group} --> Campo Descrizione: {desc}"
                    print(to_print)
                    # Salva output
                    save_routine(view, to_print)
                    
        else:
            color_print("[-] Nessun utente privilegiato trovato.", 'yellow')
    except Exception as e:
        color_print(f"Errore: {e}",'red')

## ELENCA GRUPPI ADMIN
## -g/--gadmins
def list_admingroup():
    """Elenca i gruppi con privilegi amministrativi."""
    if not check_connection(conn):
        return
        
    try:
        # Cerca i gruppi amministrativi
        conn.search(search_base=domain, 
                    search_filter='(&(objectCategory=group)(adminCount=1))', 
                    attributes=['cn', 'description'])
        
        # Stampa i gruppi amministrativi trovati
        if conn.entries:
            view = "[+] Gruppi trovati con privilegi amministrativi:"
            color_print(view,'blue')
            for entry in conn.entries:
                group_name = str(entry.cn)
                desc = str(entry.description) if entry.description else ""
                if is_description_empty(desc):
                    to_print = f" -  {group_name}"
                else:
                    to_print = f" -  {group_name} --> Campo Descrizione: {desc}"
                print(to_print)
                save_routine(view, to_print)
                
        else:
            color_print("[-] Nessun gruppo con privilegi amministrativi trovato.",'yellow')
    except Exception as e:
        color_print(f"Errore: {e}",'red')

## ELENCA admincount=1
## -ad/--admincount
def list_admincount():
    """Elenca gli account con adminCount=1."""
    if not check_connection(conn):
        return
        
    try:
        # Cerca le entità utente con adminCount=1
        conn.search(search_base=domain, 
                    search_filter='(adminCount=1)', 
                    attributes=['cn', 'description'])
        
        # Stampa gli utenti privilegiati trovati
        if conn.entries:
            view = "[+] Account con adminCount=1 trovati:"
            color_print(view,'blue')
            for entry in conn.entries:
                user = str(entry.cn)
                desc = str(entry.description) if entry.description else ""
                if is_description_empty(desc):
                    to_print = f" -  {user}"
                else:
                    to_print = f" -  {user} --> Campo Descrizione: {desc}"
                print(to_print)
                # Salva output
                save_routine(view, to_print)
                
        else:
            color_print("[-] Nessun account con adminCount=1 trovato.",'yellow')
    except Exception as e:
        color_print(f"Errore: {e}",'red')

## ELENCA COMPUTER
## -c/--computers
def list_computers():
    """Elenca tutti i computer del dominio."""
    if not check_connection(conn):
        return
        
    try:
        # Cerca le entità computer
        conn.search(search_base=domain, 
                    search_filter='(objectCategory=Computer)', 
                    attributes=['cn', 'operatingSystem', 'operatingSystemVersion', 'operatingSystemServicePack', 'sAMAccountName'])
        
        # Stampa i computer trovati
        if conn.entries:
            view = "[+] Computer trovati:"
            color_print(view,'blue')
            for entry in conn.entries:
                if not entry.operatingSystem or not entry.operatingSystemVersion:
                    to_print = f" -  {str(entry.sAMAccountName)}"
                else:
                    to_print = f" -  {str(entry.sAMAccountName)}  OS: {str(entry.operatingSystem)} {str(entry.operatingSystemVersion)}"
                print(to_print)
                # Salva output
                save_routine(view, to_print)

        else:
            color_print("[-] Nessun computer trovato.",'yellow')
    except Exception as e:
        color_print(f"Errore: {e}",'red')

## TROVA ACCOUNT DI SERVIZIO
## -s/--services
def list_services():
    """Elenca gli account di servizio."""
    if not check_connection(conn):
        return
        
    try:
        # Cerca le entità utente con SPN
        conn.search(search_base=domain, 
                    search_filter='(servicePrincipalName=*)', 
                    attributes=['cn', 'description'])
        
        # Stampa i servizi trovati
        if conn.entries:
            view = "[+] Account di servizio trovati:"
            color_print(view,'blue')
            for entry in conn.entries:
                user = str(entry.cn)
                desc = str(entry.description) if entry.description else ""
                if is_description_empty(desc):
                    to_print = f" -  {user}"
                else:
                    to_print = f" -  {user} --> Campo Descrizione: {desc}"
                print(to_print)
                # Salva output
                save_routine(view, to_print)

        else:
            color_print("[-] Nessun account di servizio trovato.",'yellow')
    except Exception as e:
        color_print(f"Errore: {e}",'red')

## VERIFICA SE C'È UNA PASSWORD NEL CAMPO COMMENTO
## -pw/pwdusers
def list_users_wpassword():
    """Cerca utenti con possibili password nel campo descrizione."""
    if not check_connection(conn):
        return
        
    try:
        # Cerca utenti con una descrizione che potrebbe contenere password
        conn.search(search_base=domain,
                    search_filter='(&(objectCategory=user)(|(description=*pass*)(description=*pwd*)(description=*log*)))', 
                    attributes=['cn', 'description','sAMAccountName'])
        
        # Stampa gli utenti con possibili password nella descrizione
        if conn.entries:
            view = "[+] Utenti trovati con possibile password nel campo descrizione:"
            color_print(view,'blue')
            for entry in conn.entries:
                user = str(entry.sAMAccountName)
                desc = str(entry.description) if entry.description else ""
                to_print = f" -  {user} --> Campo Descrizione: {desc}"
                print(to_print)
                # Salva output
                save_routine(view, to_print)
                
        else:
            color_print("[-] Nessun utente con possibile password trovato.",'yellow')
    except Exception as e:
        color_print(f"Errore: {e}",'red')

## ELENCA TUTTI GLI UTENTI SENZA PRIVILEGI
## -unp/unprivusers
def list_users_noprv():
    """Elenca gli utenti senza privilegi noti."""
    if not check_connection(conn):
        return
        
    try:
        # Cerca utenti che NON sono in gruppi privilegiati noti:
        # DnsAdmins, Enterprise Admins, Administrators, Domain Admins
        conn.search(search_base=domain, 
                    search_filter=f'(&(&(objectCategory=user)(objectClass=user)(!(|(memberOf=CN=DnsAdmins,CN=Users,{domain})(memberOf=CN=Enterprise Admins,CN=Users,{domain})(memberOf=CN=Administrators,CN=Users,{domain})(memberOf=CN=Domain Admins,CN=Users,{domain})))))', 
                    attributes=['sAMAccountName'])
        
        # Stampa gli utenti non privilegiati trovati
        if conn.entries:
            view = "[+] Utenti senza privilegi noti trovati:"
            color_print(view,'blue')
            for entry in conn.entries:
                to_print = f" -  {str(entry.sAMAccountName)}"
                print(to_print)
                # Salva output
                save_routine(view, to_print)
                
        else:
            color_print("[-] Nessun utente senza privilegi trovato.",'yellow')
    except Exception as e:
        color_print(f"Errore: {e}",'red')

## ELENCA UTENTI KERBEROASTABILI
## KERBEROAST
## -k/--kerberoast
def list_kerberusers():
    """Elenca gli utenti vulnerabili a Kerberoasting."""
    if not check_connection(conn):
        return
        
    try:
        conn.search(search_base=domain, 
                    search_filter='(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))', 
                    attributes=['sAMAccountName', 'description'])
        
        # Stampa gli utenti kerberoastabili trovati
        if conn.entries:
            view = "[+] Utenti Kerberoastabili trovati:"
            color_print(view,'blue')
            for entry in conn.entries:
                desc = str(entry.description) if entry.description else ""
                if is_description_empty(desc):
                    to_print = f" -  {str(entry.sAMAccountName)}"
                else:
                    to_print = f" -  {str(entry.sAMAccountName)} --> Campo Descrizione: {desc}"
                print(to_print)
                # Salva output
                save_routine(view, to_print)
                
        else:
            color_print("[-] Nessun utente Kerberoastabile trovato.",'yellow')
    except Exception as e:
        color_print(f"Errore: {e}",'red')

## ELENCA UTENTI ASREPROAST
## ASREPROAST
## -as/--asreproast
def list_asrepusers():
    """Elenca gli utenti vulnerabili a ASREPRoasting."""
    if not check_connection(conn):
        return
        
    try:
        conn.search(search_base=domain, 
                    search_filter='(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))', 
                    attributes=['sAMAccountName', 'description'])
        
        # Stampa gli utenti ASREProastabili trovati
        if conn.entries:
            view = "[+] Utenti ASREP-roastabili trovati:"
            color_print(view,'blue')
            for entry in conn.entries:
                desc = str(entry.description) if entry.description else ""
                if is_description_empty(desc):
                    to_print = f" -  {str(entry.sAMAccountName)}"
                else:
                    to_print = f" -  {str(entry.sAMAccountName)} --> Campo Descrizione: {desc}"
                print(to_print)
                # Salva output
                save_routine(view, to_print)
                
        else:
            color_print("[-] Nessun utente ASREProastabile trovato.",'yellow')
    except Exception as e:
        color_print(f"Errore: {e}",'red')
        
## UTENTI NON VINCOLATI (UNCONSTRAINED)   
## -uu/--uncuser
def list_uncostrainedusers():
    """Elenca gli utenti con delegazione non vincolata."""
    if not check_connection(conn):
        return
        
    try:
        conn.search(search_base=domain, 
                    search_filter='(&(&(objectCategory=person)(objectClass=user))(userAccountControl:1.2.840.113556.1.4.803:=524288))', 
                    attributes=['sAMAccountName', 'description'])
        
        # Stampa gli utenti non vincolati trovati
        if conn.entries:
            view = "[+] Utenti non vincolati trovati:"
            color_print(view,'blue')
            for entry in conn.entries:
                desc = str(entry.description) if entry.description else ""
                if is_description_empty(desc):
                    to_print = f" -  {str(entry.sAMAccountName)}"
                else:
                    to_print = f" -  {str(entry.sAMAccountName)} --> Campo Descrizione: {desc}"
                print(to_print)
                # Salva output
                save_routine(view, to_print)
            
        else:
            color_print("[-] Nessun utente non vincolato trovato.",'yellow')
    except Exception as e:
        color_print(f"Errore: {e}",'red')

## ELENCA COMPUTER NON VINCOLATI
## -uc/--unccomputers
def list_uncostrainedcomputers():
    """Elenca i computer con delegazione non vincolata."""
    if not check_connection(conn):
        return
        
    try:
        conn.search(search_base=domain, 
                    search_filter='(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))', 
                    attributes=['sAMAccountName', 'description', 'operatingSystem'])
        
        # Stampa i computer non vincolati trovati
        if conn.entries:
            view = "[+] Computer non vincolati trovati:"
            color_print(view,'blue')
            for entry in conn.entries:
                os_info = str(entry.operatingSystem) if entry.operatingSystem else "N/A"
                desc = str(entry.description) if entry.description else ""
                if is_description_empty(desc):
                    to_print = f" -  {str(entry.sAMAccountName)} (OS: {os_info})"
                else:
                    to_print = f" -  {str(entry.sAMAccountName)} (OS: {os_info}) --> Campo Descrizione: {desc}"
                print(to_print)
                # Salva output
                save_routine(view, to_print)

        else:
            color_print("[-] Nessun computer non vincolato trovato.",'yellow')
    except Exception as e:
        color_print(f"Errore: {e}",'red')


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(
                prog='LDAPreckon', 
                description="Strumento di enumerazione LDAP per penetration testing.",
                usage="python3 LDAPrecon.py DCIP -U username -P password",
                epilog="Strumento per red team - utilizzare solo con autorizzazione")
    
    parser.add_argument("DCIP", type=str, help="Indirizzo IP del Domain Controller.")
    parser.add_argument('-U', '--username', required=True, help="Username del dominio")
    parser.add_argument('-P', '--password', required=True, help="Password dell'utente del dominio")
    parser.add_argument('-us', '--users', required=False, action="store_true", help="Cerca SOLO gli utenti del dominio")
    parser.add_argument('-ug', '--usergroup', required=False, action="store", help="Cerca i gruppi dell'utente")
    parser.add_argument('-a', '--admins', required=False, action="store_true", help="Cerca SOLO gli admin del dominio")
    parser.add_argument('-g', '--gadmins', required=False, action="store_true", help="Cerca SOLO i gruppi con privilegi admin")
    parser.add_argument('-ad', '--admincount', required=False, action="store_true", help="Cerca account con adminCount=1")
    parser.add_argument('-c', '--computers', required=False, action="store_true", help="Mostra SOLO gli oggetti computer")
    parser.add_argument('-s', '--services', required=False, action="store_true", help="Mostra SOLO gli account di servizio")
    parser.add_argument('-pw', '--pwdusers', required=False, action="store_true", help="Cerca utenti con possibili password nel campo descrizione")
    parser.add_argument('-unp', '--unprivusers', required=False, action="store_true", help="Cerca utenti senza privilegi")
    parser.add_argument('-k', '--kerberoast', required=False, action="store_true", help="Cerca utenti Kerberoastabili")
    parser.add_argument('-as', '--asreproast', required=False, action="store_true", help="Cerca utenti ASREProastabili")
    parser.add_argument('-uu', '--uncusers', required=False, action="store_true", help="Cerca utenti non vincolati")
    parser.add_argument('-uc', '--unccomputers', required=False, action="store_true", help="Cerca computer non vincolati")
    parser.add_argument('-o', '--output_file', required=False, help="File di output per salvare i risultati", action='store')

    args = parser.parse_args()
    
    dc_ip = args.DCIP
    dc_port = 389
    username = args.username
    password = args.password
    
    # Ottieni il dominio di base
    domain = search_root_dse(dc_ip)
    
    # APRI LA CONNESSIONE
    conn = establish_connection(dc_ip, username, password, dc_port)
    
    if not conn:
        color_print("[-] Impossibile stabilire la connessione. Uscita.", 'red')
        exit(1)
    
    try:
        # Verifica se sono specificati uno o più argomenti opzionali ed eseguili,
        # se non sono specificati argomenti opzionali esegue tutte le query
        queries_executed = False

        if args.users:
            list_users()
            queries_executed = True
        if args.usergroup:
            list_usergroup()
            queries_executed = True
        if args.admins:
            list_privilegeduser()
            queries_executed = True
        if args.services:
            list_services()
            queries_executed = True
        if args.computers:
            list_computers()
            queries_executed = True
        if args.gadmins:
            list_admingroup()
            queries_executed = True       
        if args.pwdusers:
            list_users_wpassword()
            queries_executed = True
        if args.admincount:
            list_admincount()
            queries_executed = True
        if args.kerberoast:
            list_kerberusers()
            queries_executed = True
        if args.asreproast:
            list_asrepusers()
            queries_executed = True
        if args.uncusers:
            list_uncostrainedusers()
            queries_executed = True
        if args.unccomputers:
            list_uncostrainedcomputers()
            queries_executed = True
        if args.unprivusers:
            list_users_noprv()
            queries_executed = True

        # ESEGUI TUTTE LE QUERY SE NESSUNA È STATA SPECIFICATA
        if not queries_executed:
            color_print("\n[*] Esecuzione di tutte le query disponibili...\n", 'blue')
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
            list_uncostrainedcomputers()
            list_admincount()

    except KeyboardInterrupt:
        color_print("\n[!] Interruzione da utente. Chiusura...", 'yellow')
    except Exception as e:
        color_print(f"[!] Errore durante l'esecuzione: {e}", 'red')
    finally:
        # CHIUDI LA CONNESSIONE
        close_connection(conn)
        if args.output_file:
            color_print(f"\n[+] Risultati salvati in: {args.output_file}", 'green')
