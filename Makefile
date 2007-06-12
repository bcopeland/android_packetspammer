packetspammer: packetspammer.c
	gcc  -Wall -Werror packetspammer.c -o packetspammer -lpcap

clean:
	rm -f packetspammer *~

send:	packetspammer
	scp packetspammer root@192.168.0.60:/usr/local/bin
	scp packetspammer root@192.168.0.99:/usr/local/bin

style:
	cstyle packetspammer.c
