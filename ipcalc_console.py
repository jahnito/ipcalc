import argparse

IPM = ipaddress.ip_interface(args.ip_mask)
IPN = IPM.network

parser = argparse.ArgumentParser('description')
parser.add_argument('-i', '--ip_mask', type=str, default='127.0.0.1/8', metavar='{ip/mask}', help='set ip addres with /mask, example: 192.168.88.1/24')
args = parser.parse_args()

# print(f'ip address: {IPM.ip}')
# print(f'netmask: {IPM.netmask}')
# print(f'network address: {IPN}')
# print(f'min ip address: {IPN[1]}')
# print(f'max ip address: {IPN[-2]}')
# print(f'broadcast address: {IPN[-1]}')
# print(f'hosts: {IPN.num_addresses}')
# print()
# print(f'private address: {IPM.is_private}')
# print(f'global address: {IPM.is_global}')
# print(f'loopback address: {IPM.is_loopback}')
# print(f'multicast address: {IPM.is_multicast}')