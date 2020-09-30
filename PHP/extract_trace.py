#!/usr/bin/env python
import argparse
import gzip

CHUNKLEN = 4096

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract and execute a DLL from a VBS script')
    parser.add_argument('-i', type=argparse.FileType('rb'), dest='inputfile', required=True)
    parser.add_argument('-o', type=argparse.FileType('w'), dest='outputfile', required=True)
    args = parser.parse_args()


    input  = gzip.GzipFile(mode="rb",fileobj=args.inputfile)
    chunk = input.read(CHUNKLEN)
    while chunk:
        args.outputfile.write(chunk)
        chunk = input.read(CHUNKLEN)

    input.close()
    args.inputfile.close()
    args.outputfile.close()
