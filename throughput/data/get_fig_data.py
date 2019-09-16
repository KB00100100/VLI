import re
import os
import argparse

def get_fig_data(file_path):
    with open (file_path,'r') as f0:
        for line in f0:
            data = re.findall('KBytes  (.+?) Mbits', line)
            if data:
                print data[0]

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='VLI Get Fig Data from the Raw Experimental Data.')
    parser.add_argument('--filepath', help='The raw experimental data filepath',
                        type=str, action="store", required=True)
    args = parser.parse_args()

    if not os.path.exists(args.filepath):
        parser.print_help()
        print "\nthe raw experimental filepath not found!!"
        parser.exit(1)
    get_fig_data(args.filepath)
