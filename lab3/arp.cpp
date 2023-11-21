#include <iostream>
#include <pcap.h>
#include<iomanip>

#pragma comment(lib,"ws2_32.lib")
#pragma pack(1)
#pragma warning(disable : 4996)
using namespace std;

//֡�ײ�
struct FrameHeader_t {
    BYTE DesMAC[6];//Ŀ�ĵ�ַ
    BYTE SrcMAC[6];//Դ��ַ
    WORD FrameType;//֡����
};

//ARP֡
struct ARPFrame_t {
    FrameHeader_t FrameHeader;//֡�ײ�
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



//�õ���Ӧ��IP��ַ
void* getaddress(struct sockaddr* sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in*)sa)->sin_addr);//IPV4��ַ
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);//IPV6��ַ
}

//��ӡ�豸�б����豸��Ϣ
pcap_if_t* print_devices(pcap_if_t* d)
{
    pcap_if_t* count; //�����õ�ָ��
    pcap_addr_t* a; //��ַָ��
    int i = 0;//�豸��������
    int j = 0;//������豸
    for (count = d; count; count = count->next)
    {
        cout << ++i << ". " << count->name;
        if (count->description)
            cout << "(" << count->description << ")" << endl;
        else
            cout << "(������!)" << endl;
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
            cout << "IP��ַ��" << str << endl;
            inet_ntop(AF_INET, getaddress((struct sockaddr*)a->netmask), str, sizeof(str));
            cout << "�������룺" << str << endl;

        }
    }
    if (i == 0)
    {
        cout << endl << "δ�ҵ��豸��" << endl;
        return 0;
    }
    cout << "-----------------------------------------------------------------------------" << endl;
    return count;
}


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];//���ڴ洢������Ϣ�������Ϣ��
    pcap_if_t* devices; //ָ���豸�б��һ��
    if (pcap_findalldevs(&devices, errbuf) == -1) {
        cout << "�����豸ʧ��: " << errbuf << endl;
        return 0;
    }

    pcap_if_t* devi = print_devices(devices);
    char* dev = devi->name;
    cout << "��ǰ�����豸�ӿڿ�����Ϊ��" << dev << endl;

    //������ӿ�
    pcap_t* point = pcap_open(dev, 65536, PCAP_OPENFLAG_PROMISCUOUS, 200, NULL, errbuf);
    if (point == NULL) {
        cout << "�򿪵�ǰ����ӿ�ʧ��" << endl;
        return 0;
    }
    else cout << "�ɹ���������" << endl;

    //���롢���ù�������ֻ����ARP��
    u_int netmask = ((sockaddr_in*)(devi->addresses->netmask))->sin_addr.S_un.S_addr;
    bpf_program filter;
    char packet_filter[] = "ether proto \\arp";
    if (pcap_compile(point, &filter, packet_filter, 1, netmask) < 0) {
        cout << "�޷����������";
        return 0;
    }
    if (pcap_setfilter(point, &filter) < 0) {
        cout << "���������ô���";
        return 0;
    }

    DWORD SendIP, RecvIP;

    //��װ����
    ARPFrame_t af;
    ARPFrame_t* pkt = new ARPFrame_t();

    for (int i = 0; i < 6; i++) {
        af.FrameHeader.DesMAC[i] = 0xFF;//255.255.255.255.255.255
        af.FrameHeader.SrcMAC[i] = 0x0;
        af.RecvMAC[i] = 0;
        af.SendMAC[i] = 0x66;
    }
    af.FrameHeader.FrameType = htons(0x0806);//ARP
    af.hardType = htons(0x0001);//��̫��
    af.proType = htons(0x0800);//IP
    af.hardLen = 6;
    af.proLen = 4;
    af.Operation = htons(0x0001);//ARP����
    SendIP = af.SendIP = htonl(0x70707070);//ԴIP��ַ����Ϊ�����IP��ַ112.112.112.112

    //����ѡ���������IP����Ϊ�����IP��ַ
    for (pcap_addr_t* a = devi->addresses; a != NULL; a = a->next)
    {
        if (a->addr->sa_family == AF_INET)
        {
            RecvIP = af.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
        }
    }

    pcap_sendpacket(point, (u_char*)&af, sizeof(ARPFrame_t));

    struct pcap_pkthdr* pkt_header;//�����˲������ݰ��Ļ�����Ϣ
    const u_char* packetData;  //ָ�򲶻񵽵����ݰ�

    while (1) {//�ڴ򿪵�����ӿڿ��ϲ����������ݰ�
        int result = pcap_next_ex(point, &pkt_header, &packetData);
        if (result == 1) {
            pkt = (ARPFrame_t*)packetData;
            if (pkt->RecvIP == SendIP && pkt->SendIP == RecvIP) {

                printInfo(pkt->SendMAC, pkt->SendIP);
                cout << endl;
                break;
            }
            else if (result == -1) {
                cout << "�������ݰ�����" << endl;
                break;
            }
        }
    }

    while (1) {
        //�����緢�����ݰ�
        cout << "----------------------------------------------------------------------------------\n";
        cout << "�����IP��ַ:";
        char str[100];
        cin >> str;
        if (!memcmp(str, "exit", 4))break;
        RecvIP = af.RecvIP = inet_addr(str);
        SendIP = af.SendIP = pkt->SendIP;//����IP
        for (int i = 0; i < 6; i++)
        {
            af.SendMAC[i] = af.FrameHeader.SrcMAC[i] = pkt->SendMAC[i];
        }

        if (pcap_sendpacket(point, (u_char*)&af, sizeof(ARPFrame_t)) != 0)
        {
            cout << "����ʧ��" << endl;
            return 0;
        }

        bool i = 1;
        while (i) {
            int n = pcap_next_ex(point, &pkt_header, &packetData);
            switch (n) {
            case -1: {
                cout << "����ʱ��������" << errbuf << endl;
                i = 0;
                break;
            }
            case 1: {
                pkt = (ARPFrame_t*)packetData;
                if (pkt->RecvIP == SendIP && pkt->SendIP == RecvIP)
                {
                    cout << "IP--MAC��";
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


