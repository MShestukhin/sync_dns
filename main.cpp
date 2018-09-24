
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
#include <fstream>
#include "includes/libconfig.h++"
#include "includes/occi.h"
#include "includes/ocilib.h"
#include <fstream>
#include <string>
using namespace boost::asio;
using namespace std;
io_service service;
string MNP_host="";
vector<string> split(string str,const char * delimitr)
{
    std::vector<string> v;
    char* chars_array = strtok((char*)str.c_str(), delimitr);
    while(chars_array)
    {
        v.push_back(chars_array);
        chars_array = strtok(NULL, delimitr);
    }
    return v;
}


bool contains(std::string s_cel,std::string s_find){
    if (s_cel.find(s_find) != std::string::npos) {
        return true;
    }
    return false;
};

void init()
{
    ifstream file;
    file.open("./etc/bic-soap.conf");
    //file.open("./bic-ftp.conf");
    string base="base";
    string user="user ";
    string pswd="pswd";
    string mnp_host="MNP_host";
    while(file) {
      std::string str;
      std::getline(file, str);
      if(contains(str,base)){
          str.erase(std::remove(str.begin(),str.end(),' '),str.end());
          base.clear();
          base=split(str,"=").at(1);
      }
      if(contains(str,user)){
          str.erase(std::remove(str.begin(),str.end(),' '),str.end());
          user.clear();
          user=split(str,"=").at(1);
      }
      if(contains(str,pswd)){
          str.erase(std::remove(str.begin(),str.end(),' '),str.end());
          pswd.clear();
          pswd=split(str,"=").at(1);
      }
      if(contains(str,mnp_host)){
          str.erase(std::remove(str.begin(),str.end(),' '),str.end());
          mnp_host.clear();
          mnp_host=split(str,"=").at(1);
          MNP_host=mnp_host;
      }
    }
    OCI_Connection* cn;
    OCI_Statement* st;
    OCI_Resultset*rs;
    if(!OCI_Initialize(NULL, NULL, OCI_ENV_DEFAULT)){
        std::cout<< "EXIT_FAILURE";
    }
    cn = OCI_ConnectionCreate(base.c_str(), user.c_str(), pswd.c_str(), OCI_SESSION_DEFAULT);
    st = OCI_StatementCreate(cn);
    st = OCI_StatementCreate(cn);
    OCI_Prepare(st,"select code, val from SETTINGS where code='mnp_dns_server'");
    OCI_Execute(st);
    rs = OCI_GetResultset(st);
    while(OCI_FetchNext(rs))
    {
        char str[100];
        sprintf(str,OCI_GetString(rs,2));
        if(MNP_host=="")
            MNP_host=str;
    }
    OCI_Cleanup();
    file.close();

}
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
//    char z :1; // its z! reserved

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

void do_send(char* MSISDN,ip::udp::socket& sock){
    char sendBuf[100];
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
//    dns->z = 1;
    dns->ad = 0;
    dns->rcode = 0;
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
    ip::udp::endpoint ep( ip::address::from_string(MNP_host.c_str()), 53);
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

int do_recv(ip::udp::socket& sock){
    char recvBuf[512];
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
    string regex(answers.rdata);
    vector<string> for_find_rn=split(regex,";");
    std::string rn_val;
    for(int i=0;i<for_find_rn.size();i++){
        if(contains(for_find_rn.at(i),"rn=")){
            rn_val=split(for_find_rn.at(i),"=").at(1);
        }
    }
    char* mtsIdent="01";
    if(contains(rn_val,"01")){
         return 1;
    }
    if(ntohs(dns->rcode)!=0){
        int n=ntohs(dns->rcode)/256;
        switch (n){
        case 1:
            errCode=9;//",8,Query Format Error";
                break;
        case 2:
            errCode=9;//",8,Server failed to complete the DNS request";
                break;
        case 3:
            errCode=9;//",8,MSISDN does not exist";
                break;
        case 4:
            errCode=9;//",8,Function not implemented";
            break;
        case 5:
            errCode=9;//",8,The server refused to answer for the query";
            break;
        default:
            errCode=8;//",9, MNP check error";
            break;
        }
    }
    memset(recvBuf,0,512);
    return errCode;
}

int main(int argc, char* argv[]) {
    // connect several clients
    init();
    ip::udp::socket sock(service, ip::udp::endpoint(ip::udp::v4(), 53) );
    if(argc<2)
        return 2;
    do_send((char*)argv[1],sock);
    int recv=do_recv(sock);
    std::cout<<recv<<"\n";
    sock.close();
    return recv;
}
