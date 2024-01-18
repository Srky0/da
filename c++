// We do not want the warnings about the old deprecated and unsecure CRT functions since these examples can be compiled under *nix as well
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

// Include libraries
#include <stdlib.h>
#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include "conio.h"
#include "pcap.h"
#include "protocol_headers.h"

// Function declarations
void dispatcher_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);
const char* plejfer(char* poruka);

// Plejfer matrica
char kljuc[5][5] = { {'P', 'R', 'I', 'M', 'E'}, 
					 {'N', 'A', 'B', 'C', 'D'}, 
					 {'F', 'G', 'H', 'K', 'L'},  
					 {'O', 'Q', 'S', 'T', 'U'},  
					 {'V', 'W', 'X', 'Y', 'Z'} };

int icmpBrojac = 0;

//referenca na fajl u koji se upisuje
pcap_dumper_t* file_dumper;

int main()
{
	pcap_t* device_handle;
	char error_buffer[PCAP_ERRBUF_SIZE];
	// Open the capture file
	if ((device_handle = pcap_open_offline("packetsv12.pcap", // Name of the device
		error_buffer)) == NULL) // Error buffer
	{
		printf("\n Unable to open the file %s.\n", "packetsv12.pcap");
		return -1;
	}

	file_dumper = pcap_dump_open(device_handle, "encrypackets.pcap");
	if (file_dumper == NULL)
	{
		printf("\n Error opening output file\n");
		return -1;
	}

	// Check the link layer. We support only Ethernet for simplicity. 
	if (pcap_datalink(device_handle) != DLT_EN10MB)
	{
		printf("\nThis program works only on Ethernet networks.\n");
		return -1;
	}
	// Read and dispatch packets until EOF is reached 
	pcap_loop(device_handle, 0, dispatcher_handler, NULL);

	printf("Broj ICMP paketa: %d\n", icmpBrojac);

	// Close the file associated with device_handle and deallocates resources 
	pcap_close(device_handle);

	getchar();
}

void dispatcher_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	// Print packet timestamp
	printf("Paket pristigao: %ld:%ld\n", packet_header->ts.tv_sec,
		packet_header->ts.tv_usec);

	//and get its length
	int velicinaPaketa = packet_header->len;

	//kopija paketa, postavlja se na vrednosti 0
	char kopija[1000];
	memset(kopija, 0, velicinaPaketa * sizeof(char));

	//preuzimanje podataka iz Ethernet okvira i smestanje zaglavlja u kopiju
	ethernet_header* eh = (ethernet_header*)packet_data;
	memcpy(kopija, eh, sizeof(ethernet_header) * sizeof(char));

	//provera da li je IPv4
	if (ntohs(eh->type) == 0x0800)
	{
		//pristupanje IP zaglavlju i smestanje u kopiju
		ip_header* ih = (ip_header*)((unsigned char*)eh + sizeof(ethernet_header));
		memcpy(kopija + sizeof(ethernet_header), ih, (ih->header_length * 4) * sizeof(char));

		printf("Logicka adresa primaoca: %d.%d.%d.%d\n", ih->dst_addr[0], ih->dst_addr[1], ih->dst_addr[2], ih->dst_addr[3]);

		//Provera sledeceg protokola: ICMP - 1; TCP - 6; UDP - 17
		if (ih->next_protocol == 1)
		{
			printf("Protokol: ICMP");
			icmpBrojac++;
		}
		else if (ih->next_protocol == 6)
		{
			//pristupanje TCP zaglavlju
			tcp_header* th = (tcp_header*)((unsigned char*)ih + ih->header_length * 4);

			if (th->flags == 0x18)
			{

				printf("TO JE TOOOOO\n");
				printf("%.2x \n\n", th[48]);
			}

			printf("Protokol: TCP\n");
			printf("Zaglavlje:");
			// Print the packet
			for (int i = 0; i < th->header_length * 4; i++)
			{
				printf("%.2x ", th[i]);
				if ((i + 1) % 16 == 0)
					printf("\n");
			}
			printf("\n");

			//Provera da li je port 80 -> HTTP (vidi se u Wireshark-u)
			if (ntohs(th->src_port) == 80 || ntohs(th->dest_port) == 80)
			{
				printf("HTTP sadrzaj: ");
				char* app_data = (char*)((unsigned char*)th + th->header_length * 4);
				for (int i = 0; i < 16; i++)
				{
					printf("%c", app_data[i]);
				}
				printf("\n");
			}
		}
		else if (ih->next_protocol == 17)
		{
			//Pristupanje UDP zaglavlju i smestanje u kopiju
			printf("Protokol: UDP\n");
			udp_header* uh = (udp_header*)((unsigned char*)ih + ih->header_length * 4);
			memcpy(kopija + sizeof(ethernet_header) + ih->header_length * 4, uh, sizeof(udp_header));

			//Aplikativni deo
			char* app_data = (char*)((unsigned char*)uh + sizeof(udp_header));
			int app_length = ntohs(uh->datagram_length) - sizeof(udp_header);

			printf("Aplikativni deo: ");
			for (int i = 0; i < app_length; i++)
			{
				printf("%c", app_data[i]);
				if ((i + 1) % 16 == 0)
					printf("\n");
			}
			printf("\n");

			app_data[app_length] = '\0';

			//sifrovanje poruke
			char cipher[200] = "\0";
			strcpy(cipher, plejfer(app_data));
			printf("Sifrovano: %s", cipher);

			//kopiranje sifrovane poruke u kopiju aplikativnog dela paketa
			memcpy(kopija + sizeof(ethernet_header) + ih->header_length * 4 + sizeof(udp_header), cipher, app_length);

			//zapisivanje kopije u fajl
			pcap_dump((unsigned char*)file_dumper, packet_header, (const unsigned char*)kopija);
		}
	}
	//Provera da li je protokol ARP
	else if (ntohs(eh->type) == 0x0806)
	{
		printf("Protokol: ARP");
	}
	printf("\n\n");
}



//plejfer

const char* plejfer(char* poruka)
{
	//pozicija slova u redovima i kolonama matrice
	int r1 = -1, r2 = -1, k1 = -1, k2 = -1;

	int duzinaPoruke = strlen(poruka);

	//Ako je poruka neparne duzine, na kraj se dodaje neutralni karakter
	char neutralniKarakter = 'Z';
	if (duzinaPoruke % 2 == 1)
	{
		strncat(poruka, &neutralniKarakter, 1);
		duzinaPoruke += 1;
	}

	char kriptovanaPoruka[200];

	for (int i = 0; i < duzinaPoruke; i++)
	{
		//ako se u poruci pojavi slovo J menja se u slovo I
		if (poruka[i] == 'J')
		{
			poruka[i] = 'I';
		}
	}

	//Trazenje pozicije parova slova u matrici
	for (int i = 0; i < duzinaPoruke; i += 2)
	{
		for (int j = 0; j < 5; j++)
		{
			for (int k = 0; k < 5; k++)
			{
				if (kljuc[j][k] == poruka[i])
				{
					r1 = j;
					k1 = k;
				}
				if (kljuc[j][k] == poruka[i + 1])
				{
					r2 = j;
					k2 = k;
				}
			}
		}

		//ako su dva ista slova
		if (r1 == r2 && k1 == k2)
		{
			//ono ostaje isto, i dodaje se X
			kriptovanaPoruka[i] = poruka[i];
			kriptovanaPoruka[i + 1] = 'X';
		}
		else
		{
			//ako su slova u istom redu
			if (r1 == r2)
			{
				//ako je poslednja kolona, pomera se na prvu
				if (k1 == 4)
				{
					kriptovanaPoruka[i] = kljuc[r1][0];
				}
				//u suprotnom, pomera se u kolonu desno
				else
				{
					kriptovanaPoruka[i] = kljuc[r1][k1 + 1];
				}
				if (k2 == 4)
				{
					kriptovanaPoruka[i + 1] = kljuc[r2][0];
				}
				else
				{
					kriptovanaPoruka[i + 1] = kljuc[r2][k2 + 1];
				}
			}
			//ako su slova u istoj koloni
			else if (k1 == k2)
			{
				//ako je poslednji red, pomera se na prvi
				if (r1 == 4)
				{
					kriptovanaPoruka[i] = kljuc[0][k1];
				}
				//u suprotnom, pomera se u red dole
				else
				{
					kriptovanaPoruka[i] = kljuc[r1 + 1][k1];
				}
				if (r2 == 4)
				{
					kriptovanaPoruka[i + 1] = kljuc[0][k2];
				}
				else
				{
					kriptovanaPoruka[i + 1] = kljuc[r2 + 1][k2];
				}
			}
			//u slucaju da su u razlicitim redovima i kolonama, menjaju se kolone
			else
			{
				kriptovanaPoruka[i] = kljuc[r1][k2];
				kriptovanaPoruka[i + 1] = kljuc[r2][k1];
			}
		}
	}
	//zavrsava se poruka
	kriptovanaPoruka[duzinaPoruke] = '\0';
	return kriptovanaPoruka;
}





//Vizner

const char* vizner(char* poruka)
{
	char kljucVizner[] = "KLJUC";

	int duzinaPoruke = strlen(poruka);
	int i, j;
	int duzinaKljuca = strlen(kljucVizner);
	char *kriptovanaPoruka = (char *)malloc(256 * sizeof(char));
	char *noviKljuc = (char*)malloc(256 * sizeof(char));

	// generisanje novog kljuca
	for (i = 0, j = 0; i < duzinaPoruke; ++i, ++j) {
		if (j == duzinaKljuca)
			j = 0;

		noviKljuc[i] = kljucVizner[j];
	}

	noviKljuc[i] = '\0';

	// sifrovanje poruke
	for (i = 0; i < duzinaPoruke; ++i)
		kriptovanaPoruka[i] = ((poruka[i] + noviKljuc[i]) % 26) + 'A';

	kriptovanaPoruka[duzinaKljuca] = '\0';

	return (const char *)kriptovanaPoruka;
}



//homofon
const char* homofon(char* poruka)
{
	// A  A  B C  D  E  E  F  G  H  I I J  K L
    // 33 2 55 4 10 58 12 21 99 83 71 1 6 47 91
	// -------------------------------------------
	//  M  N  O  O  P  R  S T  U  U  V  W  X  Y  Z
	// 11 22 14 16 31 56 41 8 77 66 51 39 46 24 29
	char matrica_h[52] = {
		33, 2, 55, -1, 4, -1, 10, -1, 58, 12, 21, -1, 99, -1, 83, -1, 71, 1, 6, -1, 47, -1, 91, -1,
		11, -1, 22, -1, 14, 16, 31, -1, 56, -1, 41, -1, 8, -1, 77, 66, 51, -1, 39, -1, 46, -1, 24, -1, 29, -1
	};

	int duzinaPoruke = strlen(poruka);
	char *kriptovanaPoruka = (char*)malloc(256 * sizeof(char));
	int nasumicnoSlovo = 0;

	for (int i = 0; i < duzinaPoruke; i++)
	{
		int trenutnoSlovoAscii = poruka[i] - 65; // --> 0 do 25

		if (matrica_h[trenutnoSlovoAscii * 2] != -1)
		{
			// prvo slovo sigurno mora biti razlicito od -1
			// te proveravamo drugo slovo
			if (matrica_h[trenutnoSlovoAscii * 2 + 1] != -1) // ako jeste uzimamo nasumicno slovo prvo ili drugo
			{
				kriptovanaPoruka[i] = matrica_h[trenutnoSlovoAscii * 2 + nasumicnoSlovo];
				nasumicnoSlovo = ~nasumicnoSlovo;
			}
			else
			{
				kriptovanaPoruka[i] = matrica_h[trenutnoSlovoAscii * 2];
			}
		}
	}

	kriptovanaPoruka[duzinaPoruke] = '\0';

	return (const char*)kriptovanaPoruka;
}


//cezar

const char* cezar(char* proruka)
{
  int duzinaPoruke = strlen(poruka);
  char* kriptovanaPoruka = (char*)malloc(duzinaPoruke);

  for(int i = 0; i < duzinaPoruke; i++)
  {
    kriptovanaPoruka[i] = (poruka[i] - 'A' + 4) % 26 + 'A';
  }
  kriptovanPoruka[duzinaPoruke] = '\0';
  
  return (const char*)kriptovanaPoruka;
}

