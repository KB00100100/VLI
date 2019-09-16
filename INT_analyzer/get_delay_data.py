import subprocess
import time
import re

if __name__ == '__main__':
    i = 100
    while i:
        p = subprocess.Popen('simple_switch_CLI',shell=True,stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                            universal_newlines=True) 
        # read the int_queue register 1: ingress_timesample 2: egress_timesample
        p.stdin.write('register_read int_delay 1')
        p.stdin.write('register_read int_delay 2')
        # subprocess communicate to get the output
        out,err = p.communicate()
        # print the queue value using the re
        ingress_delay = re.findall('int_delay\\[1\\]= (.+?)$', out, re.M)
        egress_delay = re.findall('int_delay\\[2\\]= (.+?)$', out, re.M)
        print str(int(egress_delay[0])-int(ingress_delay[0]))
        time.sleep(0.8)
        i = i - 1
