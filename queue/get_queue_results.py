import subprocess
import time
import re

if __name__ == '__main__':
    i = 100
    while i:
        p = subprocess.Popen('simple_switch_CLI',shell=True,stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                            universal_newlines=True) 
        # read the int_queue register
        p.stdin.write('register_read int_queue 2')
        # subprocess communicate to get the output
        out,err = p.communicate()
        # print the queue value using the re
        queue = re.findall('int_queue\\[2\\]= (.+?)$', out, re.M)
        print str(queue[0])
        time.sleep(0.8)
        i = i - 1
