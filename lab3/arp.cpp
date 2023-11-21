#include <iostream>
#include <pcap.h>
#include<iomanip>

#pragma comment(lib,"ws2_32.lib")
#pragma pack(1)
#pragma warning(disable : 4996)
using namespace std;

//帧首部
struct FrameHeader_t {
    BYTE DesMAC[6];//目的地址
    BYTE SrcMAC[6];//源地址
    WORD FrameType;//帧类型
};

//ARP帧
struct ARPFrame_t {
    FrameHeader_t FrameHeader;//帧首部
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


void printInfo(BYTE MAC[6], DWORD IP)
{
    BYTE* p = (BYTE*)&IP;
    for (int i = 0; i < 3; i++)
    {
        cout << dec << (int)*p << ".";
        p++;
    }
    cout << dec << (int)*p;
    cout << "---";

    for (int i = 0; i < 6; i++)
    {
        if (i < 5)
            printf("%02x:", MAC[i]);
        else
            printf("%02x", MAC[i]);
    }
};



//得到对应的IP地址
void* getaddress(struct sockaddr* sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in*)sa)->sin_addr);//IPV4地址
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);//IPV6地址
}

//打印设备列表中设备信息
pcap_if_t* print_devices(pcap_if_t* d)
{
    pcap_if_t* count; //遍历用的指针
    pcap_addr_t* a; //地址指针
    int i = 0;//设备数量计数
    int j = 0;//捕获的设备
    for (count = d; count; count = count->next)
    {
        cout << ++i << ". " << count->name;
        if (count->description)
            cout << "(" << count->description << ")" << endl;
        else
            cout << "(无描述!)" << endl;
    }
    cout << "choose a device:";
    cin >> j;
    count = d;
    for (int k = 1; k < j; k++) count = count->next;
    cout << count->name << endl;
    for (a = count->addresses; a != NULL; a = a->next) {
        if (a->addr->sa_family == AF_INET) {
            char str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, getaddress((struct sockaddr*)a->addr), str, sizeof(str));
            cout << "IP地址：" << str << endl;
            inet_ntop(AF_INET, getaddress((struct sockaddr*)a->netmask), str, sizeof(str));
            cout << "子网掩码：" << str << endl;

        }
    }
    if (i == 0)
    {
        cout << endl << "未找到设备！" << endl;
        return 0;
    }
    cout << "-----------------------------------------------------------------------------" << endl;
    return count;
}


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];//用于存储错误消息或诊断信息。
    pcap_if_t* devices; //指向设备列表第一个
    if (pcap_findalldevs(&devices, errbuf) == -1) {
        cout << "查找设备失败: " << errbuf << endl;
        return 0;
    }

    pcap_if_t* devi = print_devices(devices);
    char* dev = devi->name;
    cout << "当前网络设备接口卡名字为：" << dev << endl;

    //打开网络接口
    pcap_t* point = pcap_open(dev, 65536, PCAP_OPENFLAG_PROMISCUOUS, 200, NULL, errbuf);
    if (point == NULL) {
        cout << "打开当前网络接口失败" << endl;
        return 0;
    }
    else cout << "成功打开网卡！" << endl;

    //编译、设置过滤器，只捕获ARP包
    u_int netmask = ((sockaddr_in*)(devi->addresses->netmask))->sin_addr.S_un.S_addr;
    bpf_program filter;
    char packet_filter[] = "ether proto \\arp";
    if (pcap_compile(point, &filter, packet_filter, 1, netmask) < 0) {
        cout << "无法编译过滤器";
        return 0;
    }
    if (pcap_setfilter(point, &filter) < 0) {
        cout << "过滤器设置错误";
        return 0;
    }

    DWORD SendIP, RecvIP;

    //组装报文
    ARPFrame_t af;
    ARPFrame_t* pkt = new ARPFrame_t();

    for (int i = 0; i < 6; i++) {
        af.FrameHeader.DesMAC[i] = 0xFF;//255.255.255.255.255.255
        af.FrameHeader.SrcMAC[i] = 0x0;
        af.RecvMAC[i] = 0;
        af.SendMAC[i] = 0x66;
    }
    af.FrameHeader.FrameType = htons(0x0806);//ARP
    af.hardType = htons(0x0001);//以太网
    af.proType = htons(0x0800);//IP
    af.hardLen = 6;
    af.proLen = 4;
    af.Operation = htons(0x0001);//ARP请求
    SendIP = af.SendIP = htonl(0x70707070);//源IP地址设置为虚拟的IP地址112.112.112.112

    //将所选择的网卡的IP设置为请求的IP地址
    for (pcap_addr_t* a = devi->addresses; a != NULL; a = a->next)
    {
        if (a->addr->sa_family == AF_INET)
        {
            RecvIP = af.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
        }
    }

    pcap_sendpacket(point, (u_char*)&af, sizeof(ARPFrame_t));

    struct pcap_pkthdr* pkt_header;//保存了捕获数据包的基本信息
    const u_char* packetData;  //指向捕获到的数据包

    while (1) {//在打开的网络接口卡上捕获网络数据包
        int result = pcap_next_ex(point, &pkt_header, &packetData);
        if (result == 1) {
            pkt = (ARPFrame_t*)packetData;
            if (pkt->RecvIP == SendIP && pkt->SendIP == RecvIP) {

                printInfo(pkt->SendMAC, pkt->SendIP);
                cout << endl;
                break;
            }
            else if (result == -1) {
                cout << "捕获数据包出错" << endl;
                break;
            }
        }
    }

    while (1) {
        //向网络发送数据包
        cout << "----------------------------------------------------------------------------------\n";
        cout << "请求的IP地址:";
        char str[100];
        cin >> str;
        if (!memcmp(str, "exit", 4))break;
        RecvIP = af.RecvIP = inet_addr(str);
        SendIP = af.SendIP = pkt->SendIP;//本机IP
        for (int i = 0; i < 6; i++)
        {
            af.SendMAC[i] = af.FrameHeader.SrcMAC[i] = pkt->SendMAC[i];
        }

        if (pcap_sendpacket(point, (u_char*)&af, sizeof(ARPFrame_t)) != 0)
        {
            cout << "发送失败" << endl;
            return 0;
        }

        bool i = 1;
        while (i) {
            int n = pcap_next_ex(point, &pkt_header, &packetData);
            switch (n) {
            case -1: {
                cout << "捕获时发生错误：" << errbuf << endl;
                i = 0;
                break;
            }
            case 1: {
                pkt = (ARPFrame_t*)packetData;
                if (pkt->RecvIP == SendIP && pkt->SendIP == RecvIP)
                {
                    cout << "IP--MAC：";
                    printInfo(pkt->SendMAC, pkt->SendIP);
                    cout << endl;
                    i = 0;
                    break;
                }

            }
            }
        }
    }
    pcap_close(point);
    pcap_freealldevs(devices);
    return 0;
}


