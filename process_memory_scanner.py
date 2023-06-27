import re, yara, psutil,os,binascii

f=open(os.path.dirname(os.path.abspath(__file__))+"/rules/meterpreter_reverse_tcp.yar")
rules=yara.compile(file=f)
f.close()
for proc in psutil.process_iter():
    try:
        memory=""
        normal=""
        processName = proc.name()
        processID = proc.pid
        process_path=proc.exe()
        if processID!=os.getpid:
            maps_file = open("/proc/"+str(processID)+"/maps", 'r')
            mem_file = open("/proc/"+str(processID)+"/mem", 'rb', 0)
            for line in maps_file.readlines():
                m = re.match(r'([0-9A-Fa-f]+)-([0-9A-Fa-f]+) ([-r])', line)
                if m.group(3) == 'r':
                    start = int(m.group(1), 16)
                    end = int(m.group(2), 16)
                    mem_file.seek(start)
                    try:
                        chunk = mem_file.read(end - start).decode("latin-1")
                        memory+=chunk
                    except:
                        pass
            maps_file.close()
            mem_file.close()
            matches=rules.match(data=memory)
            if len(matches)>0:
                print(matches[0].rule,processID,processName,process_path)  
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
