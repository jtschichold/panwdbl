#
# Copyright (c) 2013-2015 Luigi Mori <l@isidora.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

# Minimal IP addresses handling utils

import re

RERANGE = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
REHOST = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
RENET = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*/\d{1,2}")

ADDRESS_RANGE = "RANGE"
ADDRESS_HOST = "HOST"
ADDRESS_NET = "NET"

def address_to_value(str, check=True):
    bytes = str.split('.')
    value = int(bytes[0])
    value = (value<<8)+int(bytes[1])
    value = (value<<8)+int(bytes[2])
    value = (value<<8)+int(bytes[3])
    if check:
        ts = value_to_address(value, False) 
        if ts != str:
            raise Exception("Error: "+str+" "+ts)
    return value
        
def value_to_address(value, check=True):
    byte0 = value & 0xFF
    byte1 = (value >> 8) & 0xFF 
    byte2 = (value >> 16) & 0xFF 
    byte3 = (value >> 24) & 0xFF
    if check:
        tv = address_to_value('%d.%d.%d.%d'%(byte3, byte2, byte1, byte0), False)
        if tv != value:
            raise Exception("Error: %08x %08x"%(value, tv))
    return '%d.%d.%d.%d'%(byte3, byte2, byte1, byte0)
    
def optimize_list(addrs):
    """Pretend to optimize ip lists coalescing adjacent/overlapping IP ranges"""
    addrs.sort(cmp=lambda x,y: cmp(x.startvalue, y.startvalue))
    at = None
    naddrs = []
    for a in addrs:
        if at == None:
            at = a
            continue
        o = at.attach(a)
        if o == None:
            naddrs.append(at)
            at = a
            continue
        at = o
    naddrs.append(at)
    return naddrs

class Address:
    type = ADDRESS_RANGE
    
    def __hash__(self):
        return hash(self.__repr__())
        
    def __cmp__(self, other):
        return cmp(hash(self), hash(other))
        
    def attach(self, other):
        if other.startvalue == self.endvalue+1:
            return Address(self.start, other.end)
        return None
        
    def near(self, a):
        return (a.startvalue == self.endvalue+1)
        
    def __repr__(self):
        return self.start+"-"+self.end
        
    def __init__(self, start, end):
        self.start = start
        self.startvalue = address_to_value(start)
        if value_to_address(self.startvalue) != self.start:
            raise Exception("Error: "+start)
        self.end = end
        self.endvalue = address_to_value(end)
        if value_to_address(self.endvalue) != self.end:
            raise Exception("Error: "+end)

class HostAddress(Address):
    def __repr__(self):
        return self.start
        
    def __init__(self, host):
        Address.__init__(self, host, host)
        self.type = ADDRESS_HOST

class NetAddress(Address):
    def __repr__(self):
        return self.start+"/"+self.netmask
        
    def __init__(self, net):
        start, netmask = net.split('/')
        start = start.strip()
        netmask = netmask.strip()
        netsize = (1<<(32-int(netmask)))-1
        av = address_to_value(start)
        end = value_to_address(av+netsize)
        Address.__init__(self, start, end)
        self.netmask = netmask
        self.type = ADDRESS_NET

def create_address(str):
    m = RERANGE.match(str)
    if m != None:
        start, end = m.group(0).split('-')
        return Address(start, end)
    m = RENET.match(str)
    if m != None:
        return NetAddress(m.group(0))
    m = REHOST.match(str)
    if m != None:
        return HostAddress(m.group(0))
    raise Exception("Invalid address: "+str)

if __name__ == "__main__":
    addrs = ["72.232.84.186",
"72.232.97.234",
"72.232.97.235",
"72.232.107.25",
"72.232.107.26",
"72.232.107.28",
"72.232.107.29",
"72.232.107.32",
"72.232.107.33",
"72.232.107.34",
"72.232.107.35",
"72.232.107.37",
"72.232.107.38",
"72.232.107.39",
"72.232.117.84"]

    nets = []
    print hash(create_address("5.34.242.0"))
    print hash(create_address("5.34.242.0"))
    for a in addrs:
        nets.append(create_address(a))
    print optimize_list(nets)
