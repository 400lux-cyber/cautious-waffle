#include"defs.h"

char errbuf[PCAP_ERRBUF_SIZE];//用于存储错误消息或诊断信息。
pcap_if_t* devices = new pcap_if_t();

table routeTable;
bool on = 1;
vector<uint32_t> myip;//所选网卡的ip地址
pcap_t* point;//选择的网卡
uint32_t i1, i2;
imtable imt;

//选择接口
pcap_if_t* get_divice() {
    if (pcap_findalldevs(&devices, errbuf) == -1) {
        cout << "查找设备失败: " << errbuf << endl;
        return 0;
    }
    pcap_if_t* count; //遍历用的指针
    pcap_addr_t* a; //地址指针
    int i = 0;//设备数量计数
    int j = 0;//捕获的设备
    for (count = devices; count; count = count->next)
    {
        cout << ++i << ". ";// << count->name;
        if (count->description)
            cout <<  count->description << endl;
        else
            cout << "(无描述!)" << endl;
    }
    cout << "choose a device:";
    cin >> j;
    count = devices;
    for (int k = 1; k < j; k++) count = count->next;
    cout << count->name << endl;
    for (a = count->addresses; a != NULL; a = a->next) {
        if (a->addr->sa_family == AF_INET) {
            char str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, getaddress((struct sockaddr*)a->addr), str, sizeof(str));
            cout << "IP地址：" << str <<endl;
            myip.push_back(inet_addr(str));
            inet_ntop(AF_INET, getaddress((struct sockaddr*)a->netmask), str, sizeof(str));
            cout << "子网掩码：" << str << endl;
        }
    }
    if (i == 0){
        cout << endl << "未找到设备！" << endl;
        return 0;
    }
    cout << "----------------------------------------------------------------------------" << endl;
    return count;
}

//获取对应ip的mac地址
uint8_t* get_mac(pcap_if_t* devi,uint32_t ip) {
    if (imt.search(ip) != NULL) {
        cout << "find in ip-mac table!";
        return imt.search(ip);
    }
    ARPpacket af;
    ARPpacket* pkt = new ARPpacket();
    DWORD SendIP{ 0 }, RecvIP{ 0 };
    for (int i = 0; i < 6; i++) {
        af.header.DesMAC[i] = 0xFF;//255.255.255.255.255.255
        af.header.SrcMAC[i] = 0x0;
        af.RecvMAC[i] = 0;
        af.SendMAC[i] = 0x66;
    }
    af.header.FrameType = htons(0x0806);//ARP
    af.hardType = htons(0x0001);//以太网
    af.proType = htons(0x0800);//IP
    af.hardLen = 6;
    af.proLen = 4;
    af.Operation = htons(0x0001);//ARP请求
    SendIP = af.SendIP = htonl(0x70707070);//源IP地址设置为虚拟的IP地址112.112.112.112

    //将所选择的网卡的IP设置为请求的IP地址
    for (pcap_addr_t* a = devi->addresses; a != NULL; a = a->next) {
        if (a->addr->sa_family == AF_INET)
            RecvIP = af.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
    }
    pcap_sendpacket(point, (u_char*)&af, sizeof(ARPpacket));

    struct pcap_pkthdr* pkt_header;//保存了捕获数据包的基本信息
    const u_char* packetData;  //指向捕获到的数据包
    while (1) {//在打开的网络接口卡上捕获网络数据包
        int result = pcap_next_ex(point, &pkt_header, &packetData);
        if (result == 1) {
            pkt = (ARPpacket*)packetData;
            if (pkt->RecvIP == SendIP && pkt->SendIP == RecvIP) {
                break;
            }
            else if (result == -1) {
                cout << "捕获数据包出错" << endl;
                break;
            }
        }
    }
    //向网络发送数据包
    RecvIP = af.RecvIP = ip;
    SendIP = af.SendIP = pkt->SendIP;//本机IP
    for (int i = 0; i < 6; i++)
    {
        af.SendMAC[i] = af.header.SrcMAC[i] = pkt->SendMAC[i];
    }
    pcap_sendpacket(point, (u_char*)&af, sizeof(ARPpacket));
    while (1) {
        int n = pcap_next_ex(point, &pkt_header, &packetData);
        pkt = (ARPpacket*)packetData;
        if (pkt->RecvIP == SendIP && pkt->SendIP == ip) {
            imt.in(ip, pkt->SendMAC);
            return pkt->SendMAC;
        }
    }
}

bool equal_mac(uint8_t* mac) {
    if((int)mac[0] != 240)return 0;
    if ((int)mac[1] != 119)return 0;
    if ((int)mac[2] != 195)return 0;
    if ((int)mac[3] != 22)return 0;
    if ((int)mac[4] != 55)return 0;
    if ((int)mac[5] != 58)return 0;
    return 1;
}

//操作路由表
int choose() {
    cout << "\n1.添加路由表项\n2.删除路由表项\n3.修改路由表项\n4.查看路由表\n5.查询ip-mac映射表\n6.退出\n";
    int choice;
    while (1) {
        cout << "选择您要进行的操作：";
        cin >> choice;
        switch (choice) {
        case 1: {//添加路由表项
            routeTable.add_item(); break; }
        case 2: {//删除路由表项
            routeTable.delete_item(); break; }
        case 3: {//修改路由表项
            routeTable.fix();  break; }
        case 4: {//查看路由表
            routeTable.print(); break; }
        case 5: {//查看ip-mac映射表
            imt.print(); break; }
        case 6: {//退出
            on = 0;
            return 0; }
        }
    }
}

void printpkt(packet* pkt) {
    cout << "\nsrc=";
    printIP(pkt->ipp.src_ip);
    cout << " srcmac=";
    printMAC(pkt->header.SrcMAC);
    cout << " dst=";
    printIP(pkt->ipp.dst_ip);
    cout << " dstmac=";
    printMAC(pkt->header.DesMAC);
    cout << endl;
}

void listen(pcap_if_t* devi) {
    struct pcap_pkthdr* pkt_header;//保存了捕获数据包的基本信息
    const u_char* packetData;  //指向捕获到的数据包
    packet* pkt;
    while (on) {//在打开的网络接口卡上捕获网络数据包
        int result = pcap_next_ex(point, &pkt_header, &packetData);
        if (result == 1) {
            pkt=(packet*)packetData;
            if (pkt->ipp.dst_ip == myip[0]|| pkt->ipp.dst_ip == myip[1]) {
                cout << "本机收到！信息："; printpkt(pkt);
                continue;
            }

            bool eq = equal_mac(pkt->header.DesMAC);
            if (pkt->ipp.ttl <= 0 || pkt->header.FrameType != 8
                || pkt->ipp.protocol != 1 || !eq)
                continue;
            
            uint32_t dst_ip = pkt->ipp.dst_ip;
            uint32_t nextip = routeTable.find_next(dst_ip);
            if (nextip == 0) {
                //cout<<"未找到下一跳地址"<<endl;
            }
            else {
                printpkt(pkt);
                cout << "下一跳ip：";
                printIP(nextip);
                i2 = nextip;
                if (nextip != 0xFFFFFFFF) {
                    uint8_t* next_mac = new uint8_t();
                    next_mac = get_mac(devi,nextip);
                    printMAC(next_mac);
                    for (int i = 0; i < 6; i++) {
                        pkt->header.SrcMAC[i] = pkt->header.DesMAC[i];
                        pkt->header.DesMAC[i] = next_mac[i];
                    }
                    pkt->ipp.ttl--;
                    pkt->ipp.checksum_cal();
                }
                printpkt(pkt);
                int send = pcap_sendpacket(point, (u_char*)pkt, sizeof(packet));
                if (send)cout << "send!\n";
                else { cout << pcap_geterr(point); return; }
            }
        }
    }
}

int main() {
    //获取设备列表，打开网络接口。编译、设置过滤器，只捕获ARP和IP包
    pcap_if_t* devi = get_divice();
    char* dev = devi->name;
    point = pcap_open(dev, 65536, PCAP_OPENFLAG_PROMISCUOUS, 200, NULL, errbuf);
    compile(devi, point);


    char ip[100]="206.1.2.2";
    uint32_t dst_ip = inet_addr(ip);
    get_mac(devi,dst_ip);
    char ip1[100] = "206.1.1.2";
    uint32_t dst_ip1 = inet_addr(ip1);
    get_mac(devi,dst_ip1);
    cout << "\n";

    imt.print();

    thread t([&]() {listen(devi); });//监听线程，路由转发数据包
    t.detach();

    choose();//操作路由表

    pcap_close(point);
    pcap_freealldevs(devices);
    return 0;
}