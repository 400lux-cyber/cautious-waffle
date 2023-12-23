#pragma once
#include <iostream>
#include <pcap.h>
#include <vector>
#include <string>
#include <thread>
#include <time.h>
#include <mutex>
#pragma comment(lib,"ws2_32.lib")
#pragma pack(1)//��1byte��ʽ����
#pragma warning(disable : 4996)
using namespace std;

class Header {//֡�ײ�
public:
	BYTE DesMAC[6];//Ŀ�ĵ�ַ
	BYTE SrcMAC[6];//Դ��ַ
	WORD FrameType;//֡����
};

class ARPpacket {//ARP���ݰ�
public:
	Header header;//֡�ײ�
	WORD hardType;//Ӳ������
	WORD proType;//Э������
	BYTE hardLen;//Ӳ����ַ����
	BYTE proLen;// Э���ַ����
	WORD Operation;//����
	BYTE SendMAC[6];//ԴMAC
	DWORD SendIP;//ԴIP��ַ
	BYTE RecvMAC[6];//Ŀ��MAC
	DWORD RecvIP;//Ŀ��IP��ַ
};

class iphead {//ipͷ��
public:
	uint8_t version_headlen;//ǰ4λip�汾 ��4λip�ײ����� ��λ��4B
	uint8_t serve;//���ַ���
	uint16_t tot_len;//�ܳ��� ��λ��1B
	uint16_t id;//��ʶ
	uint16_t flags_offset;//ǰ3λ��־λ ��13λƬƫ�� ��λ��8B
	uint8_t ttl;//����ʱ��
	uint8_t protocol;//�ϲ�Э��
	uint16_t checksum;//�ײ�У���
	uint32_t src_ip;//Դip
	uint32_t dst_ip;//Ŀ��ip

	void checksum_cal() {
		this->checksum = 0;
		uint32_t sum = 0;
		uint16_t* p = (uint16_t*)this;
		for (int i = 0; i < 10; i++) {
			sum += *p;
			p++;
		}
		while (sum >> 16) {
			sum = (sum >> 16) + (sum & 0xffff);
		}
		this->checksum = (uint16_t)~sum;
		return;
	}
};

class icmp {//icmp���ݱ�
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint8_t data[36];
};

class packet {//ping���ݰ�
public:
	Header header;
	iphead ipp;
	icmp ic;
};

class item {//·�ɱ���
public:
	uint32_t dst_ip;//Ŀ��ip
	uint32_t mask;//��������
	uint32_t next_ip;//��һ��ip
};

void printIP(uint32_t IP) {
	uint8_t* p = (uint8_t*)&IP;
	for (int i = 0; i < 3; i++) {
		cout << dec << (int)*p << ".";
		p++;
	}
	cout << dec << (int)*p << " ";
}

class table {//·�ɱ�
	vector<item> items{};
public:
	table() {
		char ip[100] = "206.1.3.0";
		item i;
		uint32_t dst_ip = inet_addr(ip);
		i.dst_ip = dst_ip;
		char ma[100] = "255.255.255.0";
		uint32_t mask = inet_addr(ma);
		i.mask = mask;
		char next[100]="206.1.2.2";
		uint32_t next_ip = inet_addr(next);
		i.next_ip = next_ip;
		items.push_back(i);

		char ip1[100] = "206.1.1.0";
		item i1;
		uint32_t dst_ip1 = inet_addr(ip1);
		i1.dst_ip = dst_ip1;
		char ma1[100] = "255.255.255.0";
		uint32_t mask1 = inet_addr(ma1);
		i1.mask = mask1;
		char next1[100] = "206.1.1.2";
		uint32_t next_ip1 = inet_addr(next1);
		i1.next_ip = next_ip1;
		items.push_back(i1);
	}

	void add_item() {
		cout << "������Ŀ��ip��ַ��";
		char ip[100];
		cin >> ip;
		uint32_t dst_ip = inet_addr(ip);
		cout << "�������������룺";
		cin >> ip;
		uint32_t mask = inet_addr(ip);
		cout << "��������һ��ip��ַ��";
		cin >> ip;
		uint32_t next_ip = inet_addr(ip);
		item i;
		i.dst_ip = dst_ip;
		i.mask = mask;
		i.next_ip = next_ip;
		items.push_back(i);
	}

	void delete_item() {
		int index;
		cout << "������ɾ���ı��";
		cin>>index;
		items.erase(items.begin() + index);
	}

	void fix() {
		cout<<"�������޸ĵı��";
		int index;
		cin >> index;
		cout << "������Ŀ��ip��ַ��";
		char ip[100];
		cin >> ip;
		uint32_t dst_ip = inet_addr(ip);
		cout << "�������������룺";
		cin >> ip;
		uint32_t mask = inet_addr(ip);
		cout << "��������һ��ip��ַ��";
		cin >> ip;
		uint32_t next_ip = inet_addr(ip);
		item i;
		i.dst_ip = dst_ip;
		i.mask = mask;
		i.next_ip = next_ip;
		items[index] = i;
	}

	void print() {
		cout << "--------------------------------------------------" << endl;
		cout << "���\tĿ�������ַ\t��������\t��һ����ַ" << endl;
		for (UINT i = 0; i < items.size(); i++) {
			cout << i << "\t";
			printIP(items[i].dst_ip);
			cout << "\t";
			printIP(items[i].mask);
			cout << "\t";
			printIP(items[i].next_ip);
			cout << endl;
		}
		cout << "--------------------------------------------------" << endl;
	}

	uint32_t find_next(uint32_t dst_ip) {
		uint32_t max_mask = 0;
		uint32_t next_ip = 0;
		for (UINT i = 0; i < items.size(); i++) {
			if ((items[i].dst_ip & items[i].mask) == (dst_ip & items[i].mask)) {
				if (items[i].mask > max_mask) {
					max_mask = items[i].mask;
					next_ip = items[i].next_ip;
				}
			}
		}
		return next_ip;
	}
};

//�õ���Ӧ��IP��ַ
void* getaddress(struct sockaddr* sa) {
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);//IPV4��ַ
	}
	return &(((struct sockaddr_in6*)sa)->sin6_addr);//IPV6��ַ
}

//��ӡ�豸��MAC��ַ
void printMAC(uint8_t MAC[]) {
	for (int i = 0; i < 5; i++)printf("%02X-", MAC[i]);
	printf("%02X", MAC[5]);
}

//���롢���ù�������ֻ����ARP��IP��
int compile(pcap_if_t* devi, pcap_t* point) {
	u_int netmask = ((sockaddr_in*)(devi->addresses->netmask))->sin_addr.S_un.S_addr;
	bpf_program filter;
	char packet_filter[] = "ip or arp";
	if (pcap_compile(point, &filter, packet_filter, 1, netmask) < 0) {
		cout << "�޷����������";
		return 0;
	}
	if (pcap_setfilter(point, &filter) < 0) {
		cout << "���������ô���";
		return 0;
	}
}

class imitem {//ip-macӳ�����
public:
	uint32_t ip;
	uint8_t DesMAC[6];
	imitem(uint32_t i, uint8_t d[6]) {
		ip = i;
		for (int i = 0; i < 6; i++) {
			DesMAC[i] = d[i];
		}
	}
};

class imtable {//ip-macӳ���
	vector<imitem> imitems;
public:
	void in(uint32_t ip, uint8_t DesMAC[6]) {
		imitem i(ip, DesMAC);
		imitems.push_back(i);
	}

	uint8_t* search(uint32_t ip) {
		for (auto& item : imitems) {
			if (item.ip == ip) {
				return item.DesMAC;
			}
		}
		return nullptr;
	}

	void print() {
		cout << "IP-MAC Mapping Table:" << endl;
		for (const auto& item : imitems) {
			cout << "IP: ";
			printIP(item.ip); 
			cout << " MAC: ";
			printMAC((uint8_t*)item.DesMAC);
			cout << endl;
		}
	}
};