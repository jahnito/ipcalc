import ipaddress
from tkinter import *

PRGNAME = 'IP Calc'
PRGFONTTXT = ('TkFixedFont', 9)
ERRINPUT = ''
X,Y = 500,300
DIM = f'{X}x{Y}'


def ip_check(ip_input_str: str):
    global ERRINPUT
    try:
        ipaddress.ip_interface(ip_input_str)
        return True
    except (ipaddress.AddressValueError, ValueError) as err:
        ERRINPUT = err
        return False


def ip_solve(ip_int: ipaddress.ip_interface) -> dict:
    print(ip_int.ip)
    # print(ipaddress.ip_network(ip_int))


def set_addr():
    global ERRINPUT
    ip_str = field.get()
    if ip_check(ip_str):
        ip_data = ip_solve(ipaddress.ip_interface(ip_str))
        ERRINPUT = ''
        errlabel.configure(text=ERRINPUT)
    else:
        errlabel.configure(text=ERRINPUT)
    # addrT.configure(state='normal')
    # addrT.delete(1.0, END)
    # addrT.insert(1.0, '192.168.3.3')
    # addrT.configure(state='disabled')


if __name__ == '__main__':
    window = Tk()
    window.title(PRGNAME)
    window.geometry(DIM)

    # Frames
    f1 = LabelFrame(padx=1, pady=1, text='Detail IP Data')
    f2 = Frame(padx=1, pady=1)
    f3 = LabelFrame(padx=1, pady=1, text='More Info')
    f_addr = Frame(f1)
    f_netm = Frame(f1)
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
    errlabel = Label(f2, font=('TkFixedFont', 7))
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
    field = Entry(f2, width=24, justify='left')
    # Buttons
    b1 = Button(f2, text='Go!', width=8, justify='left', bd=1, command=set_addr)

    f1.pack(side='left', fill='both', anchor='nw', expand=True)
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
    wildcT.insert(1.0, '0.0.0.255')
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
