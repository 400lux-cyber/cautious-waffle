#pragma once
#include <iostream>
#include <pcap.h>
#include <vector>
#include <string>
#include <thread>
#include <time.h>
#include <mutex>
#pragma comment(lib,"ws2_32.lib")
#pragma pack(1)//以1byte方式对齐
#pragma warning(disable : 4996)
using namespace std;

class Header {//帧首部
public:
	BYTE DesMAC[6];//目的地址
	BYTE SrcMAC[6];//源地址
	WORD FrameType;//帧类型
};

class ARPpacket {//ARP数据包
public:
	Header header;//帧首部
	WORD hardType;//硬件类型
	WORD proType;//协议类型
	BYTE hardLen;//硬件地址长度
	BYTE proLen;// 协议地址长度
	WORD Operation;//操作
	BYTE SendMAC[6];//源MAC
	DWORD SendIP;//源IP地址
	BYTE RecvMAC[6];//目的MAC
	DWORD RecvIP;//目的IP地址
};

class iphead {//ip头部
public:
	uint8_t version_headlen;//前4位ip版本 后4位ip首部长度 单位是4B
	uint8_t serve;//区分服务
	uint16_t tot_len;//总长度 单位是1B
	uint16_t id;//标识
	uint16_t flags_offset;//前3位标志位 后13位片偏移 单位是8B
	uint8_t ttl;//生存时间
	uint8_t protocol;//上层协议
	uint16_t checksum;//首部校验和
	uint32_t src_ip;//源ip
	uint32_t dst_ip;//目的ip

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

class icmp {//icmp数据报
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint8_t data[36];
};

class packet {//ping数据包
public:
	Header header;
	iphead ipp;
	icmp ic;
};

class item {//路由表项
public:
	uint32_t dst_ip;//目的ip
	uint32_t mask;//子网掩码
	uint32_t next_ip;//下一跳ip
};

void printIP(uint32_t IP) {
	uint8_t* p = (uint8_t*)&IP;
	for (int i = 0; i < 3; i++) {
		cout << dec << (int)*p << ".";
		p++;
	}
	cout << dec << (int)*p << " ";
}

class table {//路由表
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
		cout << "请输入目的ip地址：";
		char ip[100];
		cin >> ip;
		uint32_t dst_ip = inet_addr(ip);
		cout << "请输入子网掩码：";
		cin >> ip;
		uint32_t mask = inet_addr(ip);
		cout << "请输入下一跳ip地址：";
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
		cout << "请输入删除的表项：";
		cin>>index;
		items.erase(items.begin() + index);
	}

	void fix() {
		cout<<"请输入修改的表项：";
		int index;
		cin >> index;
		cout << "请输入目的ip地址：";
		char ip[100];
		cin >> ip;
		uint32_t dst_ip = inet_addr(ip);
		cout << "请输入子网掩码：";
		cin >> ip;
		uint32_t mask = inet_addr(ip);
		cout << "请输入下一跳ip地址：";
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
		cout << "编号\t目的网络地址\t子网掩码\t下一跳地址" << endl;
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

//得到对应的IP地址
void* getaddress(struct sockaddr* sa) {
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);//IPV4地址
	}
	return &(((struct sockaddr_in6*)sa)->sin6_addr);//IPV6地址
}

//打印设备的MAC地址
void printMAC(uint8_t MAC[]) {
	for (int i = 0; i < 5; i++)printf("%02X-", MAC[i]);
	printf("%02X", MAC[5]);
}

//编译、设置过滤器，只捕获ARP和IP包
int compile(pcap_if_t* devi, pcap_t* point) {
	u_int netmask = ((sockaddr_in*)(devi->addresses->netmask))->sin_addr.S_un.S_addr;
	bpf_program filter;
	char packet_filter[] = "ip or arp";
	if (pcap_compile(point, &filter, packet_filter, 1, netmask) < 0) {
		cout << "无法编译过滤器";
		return 0;
	}
	if (pcap_setfilter(point, &filter) < 0) {
		cout << "过滤器设置错误";
		return 0;
	}
}

class imitem {//ip-mac映射表项
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

class imtable {//ip-mac映射表
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