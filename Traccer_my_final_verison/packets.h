#pragma once


#pragma pack(push, 1)

struct IP //// Structure for IPV4 header
{
	unsigned char headerSize : 4;
	unsigned char version : 4;
	unsigned char dscp : 6; // Type of service
	unsigned char ecn : 2; // ѕредупреждение о перегузке (не используетс¤)
	unsigned short packetSize; //Длина пакета
	unsigned short packetId;  // Уникальный иденфит
	unsigned short flags : 3;
	unsigned short fragmentOffset : 13; //возможно правильный
	unsigned char TTL; // Время жизни
	unsigned char protocol; //Используемый протокол
	unsigned short checksum; // Контрольная сумма
	unsigned int ipSrc; // IP отправителя
	unsigned int ipDst; //IP получателя
};



struct UDP
{
	unsigned short portSrc; // Порт отправителя
	unsigned short portDst; // Порт получателя
	unsigned short length;  // Длина датаграммы
	unsigned short checksum; // Контрольная сумма
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

struct IP_Pseudo // Используется просто для контролной суммы
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