#include <pcap.h>
#include <stdio.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void mac_print(const u_char*mac){
    printf("+------------Mac Address -------------+\n");
    printf("Dmac address: %02x:%02x%02x:%02x:%02x:%02x:",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    printf("\n");
    printf("Smac address: %02x:%02x%02x:%02x:%02x:%02x:",mac[6],mac[7],mac[8],mac[9],mac[10],mac[11]);
    printf("\n");
}

void check_type(const u_char* packet,int *num){     //checking if 0x800
    if((packet[12]<<8)+packet[13]==0x800);
    {
        *num = 1;
    }
}

void check_ip(const u_char*ip,int* check){          //checking if value is 6 (TCP)
    if(ip[23]==6)
    *check = 1;
}


void ip_print(const u_char* ip){                                    //printing value of source ip & Destination ip
    printf("+-----------------Sip------------------+ \n");
    printf(" %u.%u.%u.%u \n",ip[26],ip[27],ip[28],ip[29]);
    printf("\n");
    printf("+-----------------Dip------------------+\n");
    printf(" %u.%u.%u.%u \n",ip[30],ip[31],ip[32],ip[33]);
    printf("\n");
}

void print_port(const u_char *packet)
{

    printf("Source Port : %d\n",(packet[34]<<8)+packet[35]);       // printing Source and Destination port
    printf("\n");
    printf("Destination Port : %d\n",(packet[36]<<8)+packet[37]);
    printf("\n");
}

void print_data(const u_char *packet){
    int head_size= 4*((packet[46]&0xf0)>>4);
    for(int i=0;i<=10;i++)
    {
        printf("%02x ",packet[13+20+head_size+i]);
    }
 printf("\n");
}




int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }



  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    mac_print(packet); //print mac address

    int eighty = 0;
    int ip_on = 0;

    check_type(packet,&eighty); //checking if 0x800

    if(eighty ==1)  // if (ipv4 = 0x800)
    {

        check_ip(packet,&ip_on); //check if it's tcp (6)
        if(ip_on == 1)
              {
                ip_print(packet); //print Sip,Dip
                print_data(packet);
              }
    }

    if(eighty==0){
        printf("It's not IPV4! \n");
    }


    printf("%u bytes captured\n", header->caplen);
  }


  pcap_close(handle);
  return 0;
}
