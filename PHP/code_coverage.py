#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import pefile
import pylab
import progressbar
from matplotlib.patches import Rectangle
from matplotlib.collections import PatchCollection
from matplotlib.ticker import MultipleLocator, FormatStrFormatter, FixedLocator
import gzip

EXECUTE = 1
WRITE   = 2
READ    = 4
ACTIONDICT = {'R': READ, 'W': WRITE, 'X': EXECUTE}

def prepare_graph(pe):
    maxaddr = 0
    minaddr = 0x10000000
    majorFormatter = FormatStrFormatter('%X') # change to %d to see decimal offsets
    ax = pylab.subplot(111)
    ax.arrow(pe.OPTIONAL_HEADER.AddressOfEntryPoint, 0, 0, 8, head_width=0.05, head_length=0.1, fc='k', ec='k')
    counter = 0
    for section in pe.sections:
        counter += 1
        boxes = []
        lowaddr = section.VirtualAddress
        highaddr = section.VirtualAddress + section.Misc_VirtualSize
        print(lowaddr, highaddr, section.Name)
        #ax.xaxis.set_minor_locator(FixedLocator(lowaddr, highaddr))
        boxes.append(Rectangle((lowaddr, 0), section.Misc_VirtualSize, 8, label=section.Name))
        ax.text(lowaddr, 4, str(section.Name).strip('\x00'))
        if minaddr > lowaddr: minaddr = lowaddr
        if maxaddr < highaddr: maxaddr = highaddr
        # Add collection to axes
        ax.add_collection(PatchCollection(boxes,alpha=0.5, edgecolor='None', facecolor=['r', 'b'][counter%2], label='sections'))

    interval = (maxaddr - minaddr) / 20
    interval = 0x400 * (interval / 0x400)
    print('interval =', hex(interval))
    ax.xaxis.set_major_locator(MultipleLocator(interval))
    
    pylab.subplots_adjust(left=0.02, right=0.99, bottom=0.2)
    ax.axis([minaddr, maxaddr,0,8])
    ax.xaxis.set_major_formatter(FormatStrFormatter('%X'))
    pylab.xlabel('Adress')
    pylab.ylabel('Action')
    pylab.title('Code Coverage')
    pylab.grid(True)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract and execute a DLL from a VBS script')
    parser.add_argument('-e', type=argparse.FileType('rb'), dest='executable', required=True)
    parser.add_argument('-t', type=argparse.FileType('rb'), dest='tracefile', required=True)
    args = parser.parse_args()
    try:
        pe = pefile.PE(data=args.executable.read(), fast_load=True)
    except pefile.PEFormatError:
        print('Bad PE file')
    prepare_graph(pe)

    args.tracefile.seek(0, 2)
    bar = progressbar.ProgressBar(args.tracefile.tell())
    bar.start()
    args.tracefile.seek(0)

    input  = gzip.GzipFile(mode="r",fileobj=args.tracefile)

    datadict = {}
    chunk = input.readline()
    print('1/2: parsing file')
    while chunk:
        chunk = chunk.strip().split(';')
        if len(chunk) >= 2 and chunk[0] != 'INFO':
            bar.update(args.tracefile.tell())
            action = ACTIONDICT[chunk[0]]
            address = int(chunk[1])
            if not address in datadict:datadict[address] = 0
            if action == EXECUTE:
                datadict[address] |= EXECUTE
            elif action in [READ, WRITE]:
                destaddress = int(chunk[2])
                size = int(chunk[3])
                for subaddress in range(destaddress, destaddress + size):
                    if not subaddress in datadict:datadict[subaddress] = 0
                    datadict[subaddress] |= action
        try:
            chunk = input.readline()
        except IOError:
            print('\n\nfail to decompress file')
            break
    bar.finish()
    print('2/2 drawing')
    bar = progressbar.ProgressBar(len(datadict))
    bar.start()

    for address in list(datadict):
        if  datadict[address] == 0: continue
        pylab.plot(address, datadict[address], 'b+', linewidth=2.0, antialiased=False)
        bar.update(bar.currval + 1)
    bar.finish()    
    del datadict

    pylab.draw()
    pylab.show()
