import ipaddress
from tkinter import *

PRGNAME = 'IP Calc'
PRGFONTTXT = ('TkFixedFont', 9)
ERRINPUT = 'example 1: 192.168.3.15/27 \nexample 2: 172.28.28.172/255.255.255.0'
X,Y = 500,300
DIM = f'{X}x{Y}'


def ip_check(ip_input_str: str):
    '''
    Валидация ip адреса
    '''
    global ERRINPUT
    try:
        ipaddress.ip_interface(ip_input_str)
        return True
    except (ipaddress.AddressValueError, ValueError) as err:
        ln = 0
        msg = []
        for i in str(err).split():
            if ln > 25:
                ln = len(i)
                msg.append('\n')
                msg.append(i)
            else:
                ln += len(i)
                msg.append(i)

        ERRINPUT = ' '.join(msg)
        f3.pack_forget()
        return False


def private_check(ip):
    '''
    Проверка вхождения в приватный пул
    '''
    private_nets = ('10.0.0.0/8', '172.16.0.0/12', '169.254.0.0/16', '100.64.0.0/10', '192.168.0.0/16')
    a = ipaddress.ip_address(ip)
    for net in private_nets:
        if a in ipaddress.ip_network(net):
            return True
    return False


def internet_check(ip):
    '''
    Проверка вхождения в Интернет
    '''
    non_internet_nets = ('10.0.0.0/8', '172.16.0.0/12', '169.254.0.0/16', '100.64.0.0/10', '192.168.0.0/16', '127.0.0.0/8', '224.0.0.0/4')
    a = ipaddress.ip_address(ip)
    return all([a not in ipaddress.ip_network(i) for i in non_internet_nets])


def loopback_check(ip):
    '''
    Проверка вхождения в пул loopback интерфейсов
    '''
    return ipaddress.ip_address(ip) in ipaddress.ip_network('127.0.0.0/8')


def multicast_check(ip):
    '''
    Проверка вхождения в пул multicast
    '''
    return ipaddress.ip_address(ip) in ipaddress.ip_network('224.0.0.0/4')


def ipmin(ip_interface):
    if int(ip_interface.with_prefixlen.split('/')[-1]) >= 31:
        return ip_interface.network[0]
    else:
        return ip_interface.network[1]


def ipmax(ip_interface):
    if int(ip_interface.with_prefixlen.split('/')[-1]) == 32:
        return ip_interface.network[0]
    elif int(ip_interface.with_prefixlen.split('/')[-1]) == 31:
        return ip_interface.network[-1]
    else:
        return ip_interface.network[-2]


def ip_solve(ip_int: ipaddress.ip_interface) -> dict:
    return {'ip':ip_int.ip, 'netmask': ip_int.netmask, 'prefix': ip_int.with_prefixlen.split('/')[-1],
            'wildcard': ip_int.hostmask, 'network': ip_int.network[0], 'ipmin': ipmin(ip_int),
            'ipmax': ipmax(ip_int), 'broadcast': ip_int.network[-1], 'hosts': ip_int.network.num_addresses
            }


def set_addr():
    global ERRINPUT
    ip_str = field.get()
    if ip_check(ip_str):
        ip_data = ip_solve(ipaddress.ip_interface(ip_str))
        ERRINPUT = ''
        errlabel.configure(text=ERRINPUT)
        f3.pack()

        if private_check(ip_data['ip']):
            priv_l.pack()
        else:
            priv_l.pack_forget()

        if internet_check(ip_data['ip']):
            int_l.pack()
        else:
            int_l.pack_forget()

        if loopback_check(ip_data['ip']):
            loop_l.pack()
        else:
            loop_l.pack_forget()

        if multicast_check(ip_data['ip']):
            mul_l.pack()
        else:
            mul_l.pack_forget()

        addrT.configure(state='normal')
        addrT.delete(1.0, END)
        addrT.insert(1.0, ip_data['ip'])
        addrT.configure(state='disabled')

        netmT.configure(state='normal')
        netmT.delete(1.0, END)
        netmT.insert(1.0, ip_data['netmask'])
        netmT.configure(state='disabled')

        wildcT.configure(state='normal')
        wildcT.delete(1.0, END)
        wildcT.insert(1.0, ip_data['wildcard'])
        wildcT.configure(state='disabled')

        netwT.configure(state='normal')
        netwT.delete(1.0, END)
        netwT.insert(1.0, ip_data['network'])
        netwT.configure(state='disabled')

        hostmT.configure(state='normal')
        hostmT.delete(1.0, END)
        hostmT.insert(1.0, ip_data['ipmin'])
        hostmT.configure(state='disabled')

        hostmxT.configure(state='normal')
        hostmxT.delete(1.0, END)
        hostmxT.insert(1.0, ip_data['ipmax'])
        hostmxT.configure(state='disabled')

        bcastT.configure(state='normal')
        bcastT.delete(1.0, END)
        bcastT.insert(1.0, ip_data['broadcast'])
        bcastT.configure(state='disabled')

        hostsT.configure(state='normal')
        hostsT.delete(1.0, END)
        hostsT.insert(1.0, ip_data['hosts'])
        hostsT.configure(state='disabled')

    else:
        if ip_str == '':
            ERRINPUT = 'ip address not entered\n\nexample 1: 10.180.0.50/24 \nexample 2: 100.64.7.12/255.255.252.0'
            errlabel.configure(text=ERRINPUT)
        else:
            errlabel.configure(text=ERRINPUT)


def clip_(f):
    # window.withdraw()
    window.clipboard_clear()
    window.clipboard_append(f.get('1.0', END))


if __name__ == '__main__':
    window = Tk()
    window.title(PRGNAME)
    window.geometry(DIM)
    window.resizable(0, 0)

    # Frames
    f1 = LabelFrame(padx=1, pady=1, text='Detail IP Data', width=32)
    f2 = Frame(padx=1, pady=1)
    f3 = LabelFrame(f2, padx=1, pady=1, text='More Info')

    # Little Frames
    f_addr = Frame(f1)
    f_netm = Frame(f1)
    f_pref = Frame(f1)
    f_wildc = Frame(f1)
    f_netw = Frame(f1)
    f_hostm = Frame(f1)
    f_hostmx = Frame(f1)
    f_bcast = Frame(f1)
    f_hosts = Frame(f1)

    f_private = Frame(f3)
    f_internet = Frame(f3)
    f_loopback = Frame(f3)
    f_multicast = Frame(f3)

    # Labels
    addr = Label(f_addr, text='Address:    ')
    netm = Label(f_netm, text='Netmask:   ')
    wildc  = Label(f_wildc, text='Wildcard:   ')
    netw = Label(f_netw, text='Network:    ')
    hostm = Label(f_hostm, text='HostMin:    ')
    hostmx = Label(f_hostmx, text='HostMax:   ')
    bcast = Label(f_bcast, text='Broadcast: ')
    hosts = Label(f_hosts, text='Hosts:        ')
    errlabel = Label(f2, font=('TkFixedFont', 7), text=ERRINPUT)

    priv_l = Label(f3, text='Private IP Address', width=28, justify='left')
    int_l = Label(f3, text='Internet IP Address')
    loop_l = Label(f3, text='Loopback Interface')
    mul_l = Label(f3, text='Multicast IP Address')

    #Text
    addrT = Text(f_addr, height=1, borderwidth=0, width=15, relief='flat', font=PRGFONTTXT,)
    netmT = Text(f_netm, height=1, borderwidth=0, width=15, relief='flat', font=PRGFONTTXT)
    wildcT  = Text(f_wildc, height=1, borderwidth=0, width=15, relief='flat', font=PRGFONTTXT)
    netwT = Text(f_netw, height=1, borderwidth=0, width=15, relief='flat', font=PRGFONTTXT)
    hostmT = Text(f_hostm, height=1, borderwidth=0, width=15, relief='flat', font=PRGFONTTXT)
    hostmxT = Text(f_hostmx, height=1, borderwidth=0, width=15, relief='flat', font=PRGFONTTXT)
    bcastT = Text(f_bcast, height=1, borderwidth=0, width=15, relief='flat', font=PRGFONTTXT)
    hostsT = Text(f_hosts, height=1, borderwidth=0, width=15, relief='flat', font=PRGFONTTXT)

    # Fields
    field = Entry(f2, width=28, justify='left')

    # Buttons
    b1 = Button(f2, text='Go!', width=8, justify='left', bd=1, command=set_addr)
    b_addr_copy = Button(f_addr, text='^',  justify='left', bd=1, padx=1, pady=1, command=lambda: clip_(addrT))
    b_netm_copy = Button(f_netm, text='^',  justify='left', bd=1, padx=1, pady=1, command=lambda: clip_(netmT))
    b_wildc_copy = Button(f_wildc, text='^',  justify='left', bd=1, padx=1, pady=1, command=lambda: clip_(wildcT))
    b_netw_copy = Button(f_netw, text='^',  justify='left', bd=1, padx=1, pady=1, command=lambda: clip_(netwT))
    b_hostm_copy = Button(f_hostm, text='^',  justify='left', bd=1, padx=1, pady=1, command=lambda: clip_(hostmT))
    b_hostmx_copy = Button(f_hostmx, text='^',  justify='left', bd=1, padx=1, pady=1, command=lambda: clip_(hostmxT))
    b_bcast_copy = Button(f_bcast, text='^',  justify='left', bd=1, padx=1, pady=1, command=lambda: clip_(bcastT))
    b_hosts_copy = Button(f_hosts, text='^',  justify='left', bd=1, padx=1, pady=1, command=lambda: clip_(hostsT))

    f1.pack(side='left', fill='both', anchor='nw')
    f2.pack(side='right', anchor='nw')
    f3.pack(side='bottom')

    f_addr.pack(expand=True, anchor='nw')
    f_netm.pack(expand=True, anchor='nw')
    f_wildc.pack(expand=True, anchor='nw')
    f_netw.pack(expand=True, anchor='nw')
    f_hostm.pack(expand=True, anchor='nw')
    f_hostmx.pack(expand=True, anchor='nw')
    f_bcast.pack(expand=True, anchor='nw')
    f_hosts.pack(expand=True, anchor='nw')

    f_private.pack(expand=True, anchor='nw')
    f_internet.pack(expand=True, anchor='nw')
    f_loopback.pack(expand=True, anchor='nw')
    f_multicast.pack(expand=True, anchor='nw')

    field.pack(side='top', fill='x')
    field.focus_set()
    b1.pack(side='top')
    errlabel.pack()
    # priv_l.pack()
    # int_l.pack()
    loop_l.pack()
    # mul_l.pack()

    # address
    addr.pack(side='left', anchor='w', )
    addrT.insert(1.0, '127.0.0.1')
    addrT.configure(state='disabled')
    addrT.pack(side='left', anchor='w', fill='x')
    b_addr_copy.pack(side='left', anchor='w')
    # netmask
    netm.pack(side='left', anchor='w')
    netmT.insert(1.0, '255.0.0.0')
    netmT.configure(state='disabled')
    netmT.pack(side='left', anchor='w', fill='x')
    b_netm_copy.pack(side='left', anchor='w')
    # wildcard
    wildc.pack(side='left', anchor='w')
    wildcT.insert(1.0, '0.255.255.255')
    wildcT.configure(state='disabled')
    wildcT.pack(side='left', anchor='w', fill='x')
    b_wildc_copy.pack(side='left', anchor='w')
    # network
    netw.pack(side='left', anchor='w')
    netwT.insert(1.0, '127.0.0.0')
    netwT.configure(state='disabled')
    netwT.pack(side='left', anchor='w', fill='x')
    b_netw_copy.pack(side='left', anchor='w')
    # hostmin
    hostm.pack(side='left', anchor='w')
    hostmT.insert(1.0, '127.0.0.1')
    hostmT.configure(state='disabled')
    hostmT.pack(side='left', anchor='w', fill='x')
    b_hostm_copy.pack(side='left', anchor='w')
    # hostmax
    hostmx.pack(side='left', anchor='w')
    hostmxT.insert(1.0, '127.255.255.254')
    hostmxT.configure(state='disabled')
    hostmxT.pack(side='left', anchor='w', fill='x')
    b_hostmx_copy.pack(side='left', anchor='w')
    # broadcast
    bcast.pack(side='left', anchor='w')
    bcastT.insert(1.0, '127.255.255.255')
    bcastT.configure(state='disabled')
    bcastT.pack(side='left', anchor='w', fill='x')
    b_bcast_copy.pack(side='left', anchor='w')
    # hosts
    hosts.pack(side='left', anchor='w')
    hostsT.insert(1.0, '16777214')
    hostsT.configure(state='disabled')
    hostsT.pack(side='left', anchor='w', fill='x')
    b_hosts_copy.pack(side='left', anchor='w')

    window.mainloop()
