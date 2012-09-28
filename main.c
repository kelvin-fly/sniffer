#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <string.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pcap/pcap.h>
#include <math.h>
#include <sys/time.h>
//#define Mask 0x0000FFFF
//#define FOUR 0x0000FF00
//#define FIVE 0x000F0000

#define FTWO 0x0000FF00
#define FONE 0x000000FF
#define FTH 0x000F0000

int rawSocket();
int setPromisc(char *,int *);
unsigned short checksum(unsigned short *buf16, int nword);

//int rval;                 //the number of receiving bytes,we need a local varvible

int main(int argc,char **argv)
{
    if(argc!=2)
    {
        perror("please echo like this:   ./mypack eth0\n");
        exit(1);
    }
 
    int sock;
    struct sockaddr_ll rcvaddr;
    char buf[6666];
    struct ifreq ifr;
    int len;

    sock=rawSocket();
    setPromisc(argv[1],&sock);
    len=sizeof(struct sockaddr);
    memset(buf,0,sizeof(buf));

	FILE *fi;
	fi=fopen("/tmp/a.cap","ab+");
	if(fi == NULL)
	{
		printf("open /tmp/a.cap failed!!\n");
	}

	//char head[] = "0xD4C3B2A1020004000000000000000000FFFF000001000000";
	//fprintf(fi,"D4C3B2A1020004000000000000000000FFFF000001000000");   //this is ascii,so wrong!!!

	/*******pcap header*******/
	struct pcap_file_header *fh;
	struct pcap_file_header p_f_h;
	p_f_h.magic = 0xA1B2C3D4;
	p_f_h.version_major = 0x0002;
	p_f_h.version_minor = 0x0004;
	p_f_h.thiszone = 0x00000000;
	p_f_h.sigfigs = 0x00000000;
	p_f_h.snaplen = 0x0000FFFF;
	p_f_h.linktype = 0X00000001;
	fh = &p_f_h;
//	memcpy(buf,fh,sizeof(p_f_h));
//	fprintf(fi,"%s",buf);     //buf is start in ethernet!!!  so  wrong!!!
	fwrite(fh,sizeof(p_f_h),1,fi);
	fclose(fi);

    while(1)
    {
	    int rval;      //the unit is byte!!!  so multiple 256
        rval=recvfrom(sock,buf,sizeof(buf),0,(struct sockaddr*)&rcvaddr,&len);
        if(rval>0)
        {
//          printf("Get %d bytes\n",rval);
			FILE *f;
			f=fopen("/tmp/a.cap","ab+");
			if(f==NULL)
			{
				printf("open /tmp/a.cap failed!!!\n");
			}

   			/*************packet header*********/
			#if 0   //this is manual write time code
   	 	    int time[2]={0x500E4204,0x0000D1EF};
   		    int (*tim)[2];
   			tim=&time;
            fwrite(tim,8,1,f);
			#endif

			#if 1
//			struct pcap_pkthdr *pCap;
//			int now_sec;
//			int time_change = 0;
//			int last_sec = 0;

			struct timeval tv;
//			struct timezone tz;   //usually dont need tz
			gettimeofday(&tv,NULL);
			fwrite(&(tv.tv_sec),4,1,f);
			fwrite(&(tv.tv_usec),4,1,f);

//			printf("%x\n",tv.tv_usec);

/*			//may be wrong in data type,cant assignment
			printf("%d\n",tv.tv_sec);
			pCap->ts.tv_sec = tv.tv_sec;
			pCap->ts.tv_usec = tv.tv_usec;
			printf("%d\n",tv.tv_sec);
			printf("%d\n",tv.tv_usec);
			fwrite(pCap,8,1,f);
*/
			#endif

		    int b,c,d;
			int *bp;	
			b = rval*256;           //cause rval is the bytes of recvfrom()
//			printf("%x\n",b);
			/****switch the position*****/
			if(b<0x00010000)
			{
				#if 0
				c = (b>>16)&Mask;
				d = (b<<16)&(~Mask);
				b = c|d;
				#endif
	
				#if 1
				c = (b&FTWO)>>8;
				d = (b&FONE)<<8;
				b = c|d;
				#endif
			}
			else
			{
				#if 0		
				c = (b & FOUR)<<16;
				d = (b & FIVE);
				b = c|d;
				#endif	

				c = (b&FTWO)>>8;
				d = (b&FTH)>>8;
				b = c|d;
			}

//			printf("%x\n",b);    //test switching types of length
			bp = &b;
			fwrite(bp,4,1,f);
			fwrite(bp,4,1,f);

			fwrite(buf,rval,1,f);
			volatile unsigned short *buf16;
			buf16 = (unsigned short *)(buf + sizeof(struct ether_header));
			int ck = checksum(buf16, 10);
			printf("the checksum is:%x\n",ck);
//			fprintf();

//			struct iphdr *ip;
//			ip = (struct iphdr *)(buf + sizeof(struct ether_header));
//			printf("the  is:%d\n",ip->protocol);
//			printf("ttl:%d\n",ip->ttl);
			fclose(f);
			
        }

		else
	   		printf("recvfrom failed!!!\n");	
   	 }
    return 0;
}


int rawSocket()//
{
    int sock;
    //sock=socket(PF_INET,SOCK_RAW,IPPROTO_TCP);//frome IP
    sock=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));//frome Ethernet
    if(sock<0)
    {
        printf("create raw socket failed:%s\n",strerror(errno));
        exit(1);
    }
    
    printf("raw socket :%d created successful!\n",sock);
    return sock;
}


int setPromisc(char *enterface,int *sock)
{
    struct ifreq ifr;
    strcpy(ifr.ifr_name, enterface);
    ifr.ifr_flags=IFF_UP|IFF_PROMISC|IFF_BROADCAST|IFF_RUNNING;
	//ifr.ifr_flags |= IFF_PROMISC;      // this is wrong code
    if(ioctl(*sock,SIOCSIFFLAGS,&ifr)==-1)
    {
        perror("set 'eth' to promisc model failed\n"); //cant write  '%s',enterface  why?
        exit(1);
    }
    printf("set '%s' to promisc successed!\n",enterface);
    return 1;
}

unsigned short checksum(unsigned short *buf16, int nword)
{
unsigned long sum;
struct iphdr *iphdr;
iphdr = (struct iphdr *)buf16;
iphdr->check = 0;
//printf("%x\n",iphdr->check);
//printf("tt%d\n",iphdr->ttl);
//printf("%d\n",iphdr->protocol);
for(sum = 0; nword > 0; nword--)
sum += *buf16++;

sum = (sum>>16) + (sum&0xffff);
sum += (sum>>16);

return htons(~sum);   //this is checksum!!! rember byte-order!!!
}

