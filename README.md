# bruteforce
A partir de un escaneo de versiones en servicios identifica cuales coinciden con modulos de hydra

python3 service_matcherv12.py services.txt targetedPorts.nmap 

python3 service_matcherv12.py services.txt targetedPorts.xml


El archivo services.txt corresponde a la salida de 
hydra -h

La clave está en el diccionario de sinonimos de servicios, entre lo que indica nmap y muestra hydra.