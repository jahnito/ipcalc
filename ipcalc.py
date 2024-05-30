import ipaddress
from tkinter import *

PRGNAME = 'IP Calc'
PRGFONTTXT = ('TkFixedFont', 9)
ERRINPUT = 'example 1: 192.168.3.15/27 \nexample 2: 172.28.28.172/255.255.255.0'
X,Y = 500,300
DIM = f'{X}x{Y}'


def ip_check(ip_input_str: str):
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
        return False


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
    # print(ip_int.ip)
    # print(ip_int.netmask)
    # print(ip_int.with_prefixlen.split('/')[-1])
    # print(ip_int.hostmask)
    # print(ip_int.network[0])
    # print(ipmin(ip_int))
    # print(ipmax(ip_int))
    # print(ip_int.network[-1])
    # print(ip_int.network.num_addresses)
    # print('***************')


def set_addr():
    global ERRINPUT
    ip_str = field.get()
    if ip_check(ip_str):
        ip_data = ip_solve(ipaddress.ip_interface(ip_str))
        ERRINPUT = ''
        errlabel.configure(text=ERRINPUT)

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


if __name__ == '__main__':
    window = Tk()
    window.title(PRGNAME)
    window.geometry(DIM)
    window.resizable(0, 0)

    # Frames
    f1 = LabelFrame(padx=1, pady=1, text='Detail IP Data', width=40)
    f2 = Frame(padx=1, pady=1)
    f3 = LabelFrame(padx=1, pady=1, text='More Info')
    f_addr = Frame(f1)
    f_netm = Frame(f1)
    f_pref = Frame(f1)
    f_wildc = Frame(f1)
    f_netw = Frame(f1)
    f_hostm = Frame(f1)
    f_hostmx = Frame(f1)
    f_bcast = Frame(f1)
    f_hosts = Frame(f1)

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

    #Text
    addrT = Text(f_addr, height=1, borderwidth=0, width=15, relief='flat', font=PRGFONTTXT)
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

    f1.pack(side='left', fill='both', anchor='nw')
    f2.pack(side='right', fill='both', anchor='nw')
    f3.pack(side='right', fill='both', anchor='nw')
    f_addr.pack(expand=True, anchor='nw')
    f_netm.pack(expand=True, anchor='nw')
    f_wildc.pack(expand=True, anchor='nw')
    f_netw.pack(expand=True, anchor='nw')
    f_hostm.pack(expand=True, anchor='nw')
    f_hostmx.pack(expand=True, anchor='nw')
    f_bcast.pack(expand=True, anchor='nw')
    f_hosts.pack(expand=True, anchor='nw')

    field.pack(side='top', fill='x')
    field.focus_set()

    b1.pack(side='top')
    errlabel.pack()

    # address
    addr.pack(side='left', anchor='w', )
    addrT.insert(1.0, '127.0.0.1')
    addrT.configure(state='disabled')
    addrT.pack(side='right', anchor='w', fill='x')
    # netmask
    netm.pack(side='left', anchor='w')
    netmT.insert(1.0, '255.0.0.0')
    netmT.configure(state='disabled')
    netmT.pack(side='right', anchor='w', fill='x')
    # wildcard
    wildc.pack(side='left', anchor='w')
    wildcT.insert(1.0, '0.255.255.255')
    wildcT.configure(state='disabled')
    wildcT.pack(side='right', anchor='w', fill='x')
    # network
    netw.pack(side='left', anchor='w')
    netwT.insert(1.0, '127.0.0.0')
    netwT.configure(state='disabled')
    netwT.pack(side='right', anchor='w', fill='x')
    # hostmin
    hostm.pack(side='left', anchor='w')
    hostmT.insert(1.0, '127.0.0.1')
    hostmT.configure(state='disabled')
    hostmT.pack(side='right', anchor='w', fill='x')
    # hostmax
    hostmx.pack(side='left', anchor='w')
    hostmxT.insert(1.0, '127.255.255.254')
    hostmxT.configure(state='disabled')
    hostmxT.pack(side='right', anchor='w', fill='x')
    # broadcast
    bcast.pack(side='left', anchor='w')
    bcastT.insert(1.0, '127.255.255.255')
    bcastT.configure(state='disabled')
    bcastT.pack(side='right', anchor='w', fill='x')
    # hosts
    hosts.pack(side='left', anchor='w')
    hostsT.insert(1.0, '16777214')
    hostsT.configure(state='disabled')
    hostsT.pack(side='right', anchor='w', fill='x')

    window.mainloop()
