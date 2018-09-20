#ifdef WIN32
#define _WIN32_WINNT 0x0501
#include <stdio.h>
#endif
#include <boost/thread.hpp>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server
#define T_NAPTR 35
#include <iostream>
using namespace boost::asio;
io_service service;

ip::udp::endpoint ep( ip::address::from_string("10.241.30.170"), 53);
ip::udp::socket sock(service, ip::udp::endpoint(ip::udp::v4(), 0) );
struct DNS_HEADER
{
    unsigned short id; // identification number

    char rd :1; // recursion desired
    char tc :1; // truncated message
    char aa :1; // authoritive answer
    char opcode :4; // purpose of message
    char qr :1; // query/response flag

    char rcode :4; // response code
    char ad :1; // authenticated data
    //char z :1; // its z! reserved

    short q_count; // number of question entries
    short ans_count; // number of answer entries
    short auth_count; // number of authority entries
    short add_count; // number of resource entries
};
struct QUESTION
{
    short qtype;
    short qclass;
};
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
    unsigned short other;
    unsigned short pref;
    unsigned short flagLen;
    unsigned char flag;
    unsigned short servLen;
    unsigned char serv;
    unsigned short regLen;
    unsigned char reg;
};
//Pointers to resource record contents
struct RES_RECORD
{
    char *name;
    struct R_DATA *resource;
    char *rdata;
    RES_RECORD(){
        name=0;
        resource=0;
        rdata=0;
    }
    ~RES_RECORD(){

    }
};
#pragma pack(pop)

//Pointers to resource record contents
void ChangetoDnsNameFormat(char *dns, char *host){
    int lock = 0 , i;
        std::strcat(host,".");
        for(i = 0 ; i < strlen((char*)host) ; i++)
        {
            if(host[i]=='.')
            {
                *dns++= i-lock;
                for(;lock<i;lock++)
                {
                    *dns++=host[lock];
                }
                lock++;
            }
        }
        *dns++='\0';

}

void do_send(char* MSISDN){
    char sendBuf[512];
    char *qname;
    char* host;
    int i;
    int sizeNumber=strlen((char*)MSISDN);
    char str[2*sizeNumber];
    int index=1;
    str[0]=MSISDN[sizeNumber-1];
    i=1;
    while(i!=sizeNumber+1)
    {
        str[index]='.';
        str[index+1]=MSISDN[sizeNumber-i-1];
        index=index+2;
        i++;
    }
    host=(char*)&str;
    strcat(host,"e164.arpa\0");
    struct DNS_HEADER *dns = (struct DNS_HEADER *)&sendBuf;
    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0; //This is a query
    dns->opcode = 0; //This is a standard query
    dns->aa = 0; //Not Authoritative
    dns->tc = 0; //This message is not truncated
    dns->rd = 1; //Recursion Desired
//    dns->z = 0;
    dns->ad = 1;
    dns->rcode = 1;
    dns->q_count = htons(1); //we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;
    qname =(char*)&sendBuf[sizeof(struct DNS_HEADER)];
    ChangetoDnsNameFormat(qname , host);
    struct QUESTION* qinfo =(struct QUESTION*)&sendBuf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)];
    qinfo->qtype = htons(T_NAPTR);
    qinfo->qclass = htons(1);
    i=1;
    sock.send_to(buffer(sendBuf), ep);
}

char* ReadName(char* reader,char* buffer,int* count)
{
    char *name;
    int p=0,jumped=0;//,offset;
    *count = 1;
    name = (char*)malloc(256);
    name[0]='\0';
    //read the names in 3www6google3com format
    while(*reader!=0)
    {
        if(*reader>=192)
            jumped = 1; //we have jumped to another location so counting wont go up!
        else
            name[p++]=*reader;
            reader = reader+1;
        if(jumped==0)
            *count = *count + 1; //if we havent jumped to another location then we can count up
    }
    name[p]='\0'; //string complete
    if(jumped==1)
        *count = *count + 1; //number of steps we actually moved forward in the packet
        return name;
}

int do_recv(){
    char recvBuf[1024];
    ip::udp::endpoint sender_ep;
    int bytes = 0;
    while(bytes==0){
        bytes = sock.receive_from(buffer(recvBuf), sender_ep);
    }
    struct DNS_HEADER* dns = (struct DNS_HEADER*) recvBuf;
    int errCode=0;
    struct RES_RECORD answers;
    int stop;
    char *reader = &recvBuf[sizeof(struct DNS_HEADER)];
    stop=0;
    answers.name=ReadName(reader,recvBuf,&stop);
    reader = reader + stop;
    answers.resource = (struct R_DATA*)(reader);
    reader = reader + sizeof(struct R_DATA);
    answers.rdata = ReadName(reader,recvBuf,&stop);
    reader = reader + stop;
    char* ident=answers.rdata+(strlen((char*)answers.rdata)-3);
    char* mtsIdent="01!";
    if((strcmp((char*)ident,mtsIdent))==0){
         return 1;
    }
    if(ntohs(dns->rcode)!=0){
                int n=ntohs(dns->rcode)/256;
                switch (n){
                case 1:
                    errCode=8;//",8,Query Format Error";
                        break;
                case 2:
                    errCode=8;//",8,Server failed to complete the DNS request";
                        break;
                case 3:
                    errCode=8;//",8,MSISDN does not exist";
                        break;
                case 4:
                    errCode=8;//",8,Function not implemented";
                    break;
                case 5:
                    errCode=8;//",8,The server refused to answer for the query";
                    break;
                default:
                    errCode=9;//",9, MNP check error";
                    break;
                }
    }
    memset(recvBuf,0,512);
    return errCode;
}

int main(int argc, char* argv[]) {
    // connect several clients
    if(argc<2)
        return 2;
    std::string msisdn=argv[1];
    if(msisdn.empty())
        return 1;
    do_send((char*)msisdn.c_str());
    int recv=do_recv();
    std::cout<<recv<<"\n";
    sock.close();
    return recv;
}
