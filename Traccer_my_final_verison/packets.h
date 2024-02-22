#pragma once


#pragma pack(push, 1)

struct IP //// Structure for IPV4 header
{
	unsigned char headerSize : 4;
	unsigned char version : 4;
	unsigned char dscp : 6; // Type of service
	unsigned char ecn : 2; // �������������� � ��������� (�� �����������)
	unsigned short packetSize; //����� ������
	unsigned short packetId;  // ���������� �������
	unsigned short flags : 3;
	unsigned short fragmentOffset : 13; //�������� ����������
	unsigned char TTL; // ����� �����
	unsigned char protocol; //������������ ��������
	unsigned short checksum; // ����������� �����
	unsigned int ipSrc; // IP �����������
	unsigned int ipDst; //IP ����������
};



struct UDP
{
	unsigned short portSrc; // ���� �����������
	unsigned short portDst; // ���� ����������
	unsigned short length;  // ����� ����������
	unsigned short checksum; // ����������� �����
};

struct ICMP
{
	unsigned char type;          // ICMP packet type
	unsigned char code;          // Type sub code
	unsigned short checksum;
	unsigned int unused;
	//unsigned short id;
	//unsigned short seq;
};

struct IP_Pseudo // ������������ ������ ��� ���������� �����
{
	unsigned int ipSrc;
	unsigned int ipDst;
	unsigned char zero = 0;
	unsigned char protocol;
	unsigned short length;
	unsigned short portSrc;
	unsigned short portDst;
	unsigned short udpLength;
	unsigned short zeros = 0;
};

#pragma pack(pop, 1)