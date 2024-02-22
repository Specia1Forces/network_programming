// Traccer_my_final_verison.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//

#pragma comment(lib, "ws2_32.lib")
#include <Winsock2.h>
#include <iostream>

#include <Windows.h>

#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <iostream>
#include <vector>
#include <chrono>



#pragma warning(disable: 4996)

#include "packets.h"
using namespace std;

unsigned short ip_checksum(byte* addr, int count)//Контрольнная сумма ip пакета
{
	register long sum = 0;

	while (count > 1) {
		/*  This is the inner loop */
		sum += *(unsigned short*)addr;
		count -= 2;
		addr += 2;
	}

	if (count > 0)
		sum += *(unsigned char*)addr;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

void udp_pseudo_header_checksum(IP& iphdr, UDP& udphdr, std::vector<byte>& payload)
{
	IP_Pseudo pseudo;

	pseudo.ipSrc = iphdr.ipSrc;
	pseudo.ipDst = iphdr.ipDst;
	pseudo.protocol = iphdr.protocol;

	pseudo.length = pseudo.udpLength = udphdr.length;
	pseudo.portSrc = udphdr.portSrc;
	pseudo.portDst = udphdr.portDst;

	std::vector<byte> buffer(sizeof(IP_Pseudo) + payload.size());

	if (buffer.size() % 2)
	{
		buffer.resize(buffer.size() + 1);
	}

	memcpy(buffer.data(), &pseudo, sizeof(IP_Pseudo));
	memcpy(buffer.data() + sizeof(IP_Pseudo), payload.data(), payload.size());


	udphdr.checksum = ip_checksum(buffer.data(), buffer.size());
}
// Параметры трассировки
int max_hops = 30;

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "Russian");
	if (argc < 2)
	{
		std::cout << "Usage: " << argv[0] << " <target>\n";
		return 0;
	}

	int error;
	WSADATA wsadata;

	error = WSAStartup(MAKEWORD(2, 2), &wsadata);
	if (error)
	{
		std::cout << "WSAStartup failed\n";
		return 1;
	}
	//DNS 
	// Если в аргументах предоставлено DNS имя узла, то узнаем ip адреса
	addrinfo hints = { 0 }, * result;
	hints.ai_family = AF_UNSPEC; //Одним из преимуществ здесь является то, что мы можем сделать наш код независимым от IP, указав AF_UNSPEC. В этом случае функция getaddrinfo() вернет адреса IPv4 и IPv6.
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	error = getaddrinfo(argv[1], "33434", &hints, &result);



	if (error)
	{
		std::cout << "Getaddrinfo failed\n";
		return 1;
	}

	if (result == nullptr)
	{
		std::cout << argv[1] << " could not be detected. Check the address and repeat\n";
		return 0;
	}

	// Берем первый IPv4 адрес целевого узла из найденых
	addrinfo* ptr;
	for (ptr = result; ptr != nullptr; ptr = ptr->ai_next)
	{
		if (ptr->ai_family == AF_INET)
		{
			result = ptr;
			break;
		}
	}
	//DNS 

	// Автоматический поиск IP
	// Получаем индекс сетевого адаптера с которого лучше всего отправлять пакеты
	unsigned long ifIndex;
	GetBestInterfaceEx(result->ai_addr, &ifIndex);

	unsigned long size = sizeof(IP_ADAPTER_INFO);

	// Получаем список сетевых интерфейсов пользователя
	std::vector<IP_ADAPTER_INFO> adapters_info;
	adapters_info.resize(1);
	GetAdaptersInfo(adapters_info.data(), &size);

	adapters_info.resize(size / sizeof(IP_ADAPTER_INFO));
	GetAdaptersInfo(adapters_info.data(), &size);

	IP_ADAPTER_INFO* send_adapter = nullptr;
	for (IP_ADAPTER_INFO& adapter_info : adapters_info)
	{
		if (adapter_info.Index == ifIndex) // Нашли нужный сетевой адаптер с нужным индексом
		{
			send_adapter = &adapter_info;
			break;
		}
	}
	// Автоматический поиск IP

	// Создаем сокеты для ICMP и UDP
	//добавить проверку на создания 
	SOCKET icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if (WSAGetLastError() == 10013) // raw сокеты не доступны
	{
		std::cout << "Permission denied. Need admin rights." << std::endl;
		return 1;
	}

	// Говорим системе что генерируем заголовок IP сами
	//  предоставим наш собственный IP-заголовок и не позволим ядру предоставить его 
	int optval = 1;
	//устанавливаем нужные параметры при работе сокета setsockopt
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char*)&optval, sizeof(optval)) == SOCKET_ERROR) {
		printf("\nCouldn't set IP_HDRINCL");
		return 1;
	}
	// IPPROTO_IP: параметр IP.
	//IP_HDRINCL - Включить заголовок IP в пакет
	/*
	[in] s Дескриптор, идентифицирующий сокет.
	[in] level Уровень, на котором определена опция(например, SOL_SOCKET).
	[in] optname Параметр сокета, для которого необходимо установить значение(например, SO_BROADCAST).Параметр optname должен быть параметром сокета, определенным в пределах указанного уровня, иначе поведение не определено.
	[in] optval 	Указатель на буфер, в котором указано значение для запрошенной опции.
	[in] optlen Размер буфера, на который указывает параметр optval, в байтах.
	*/


	// Время ожидания ответа ICMP
	DWORD read_timeout = 4000; //4000

	if (setsockopt(icmp, SOL_SOCKET, SO_RCVTIMEO, (char*)&read_timeout, sizeof(read_timeout)) == SOCKET_ERROR)
		//Set the options associated with a socket. Options may exist in the multi-layer protocol. In order to operate the socket layer options, the value of the layer should be specified as SOL_SOCKET
		//The socket to be set or get the option, the protocol layer where the option is located, the name of the option that needs to be accessed (the operation of the socket automatically has a timeout), points to the buffer containing the new option value, and the length of the current option
	{
		cout << "\nFailed to set recv timeout\n"
			<< "error code: " << WSAGetLastError() << endl;
		closesocket(icmp);
		WSACleanup();
		return -1;
	}

	//SO_RCVTIMEO - Время ожидания приема

	//Установите параметры, связанные с сокетом. Параметры могут существовать в многоуровневом протоколе.
	//  Чтобы использовать параметры уровня сокета, значение уровня должно быть указано как SOL_SOCKET
	//Сокет, который нужно установить или получить параметр, уровень протокола, на котором находится параметр,
	//имя параметра, к которому необходимо получить доступ (работа сокета автоматически приостанавливается), указывает на буфер, содержащий новое значение параметра, и длину текущего параметра

	// Прикрепляемся к нулевому адресу и порту для приема всех пакетов со всех интерфейсов
	sockaddr_in service; //Адрес, используемый для обработки сетевых сообщений
	service.sin_family = AF_INET; //sin_family;//Кластер протоколов семейства адресов AF_INET (TCP/IP-IPv4)
	service.sin_addr.s_addr = INADDR_ANY; //s_addr 32-bit IPv4 address //sin_addr The in_addr structure представляет an IPv4 Internet address.
	service.sin_port = htons(0);
	error = bind(icmp, (sockaddr*)&service, sizeof(service));//gривязать IP-адрес к сокету, чтобы он мог принимать входящие соединения

	// INADDR_ANY - это адрес, обозначенный как 0.0.0.0,
   // Указывает неопределенный адрес или «любой адрес». "


	//Начать определять маршрутизацию




	srand(GetCurrentTime());
	unsigned short startPacketId = rand();

	byte data[1024];

	std::vector<byte> d;
	for (int i = 0; i < 64; i++)
	{
		d.push_back(i);
	}

	// Заполняем UDP заголовок
	UDP udp;
	udp.portSrc = htons(27015);
	udp.portDst = htons(33434);
	udp.length = htons(8 + d.size());
	udp.checksum = 0;

	// Заполняем IP заголовок
	IP ip;
	ip.version = 4;
	ip.headerSize = 5;
	ip.dscp = 56;
	ip.ecn = 0;
	ip.packetSize = htons(sizeof(IP) + sizeof(UDP) + d.size());
	ip.flags = 0;
	ip.fragmentOffset = 0;
	ip.TTL = 0; //TTL изменяем
	ip.protocol = IPPROTO_UDP;
	ip.checksum = 0;

	unsigned long address;
	if (send_adapter != nullptr)
		inet_pton(AF_INET, send_adapter->IpAddressList.IpAddress.String, &address);
	else
		inet_pton(AF_INET, "127.0.0.1", &address);

	unsigned int addr;
	ip.ipSrc = address;
	if (inet_pton(AF_INET, argv[1], &addr))
		ip.ipDst = addr; // Если в аргументах ip адрес
	else
		ip.ipDst = ((sockaddr_in*)result->ai_addr)->sin_addr.S_un.S_addr; // Если в аргументах DNS имя узла

	udp_pseudo_header_checksum(ip, udp, d); // Расчет контрольной 

	sockaddr_in send_addr;// Конечный адрес, куда отправляем пакет
	send_addr.sin_family = AF_INET;//IP 4
	send_addr.sin_port = udp.portDst; //ПОРТ
	send_addr.sin_addr.S_un.S_addr = ip.ipDst; // Адрес

	std::vector<byte> buffer;
	buffer.resize(sizeof(IP) + sizeof(UDP) + d.size());

	char ipStrBuf[64];

	std::cout << "\nTesting connection with " << argv[1] << " [" << inet_ntop(AF_INET, &ip.ipDst, ipStrBuf, sizeof(ipStrBuf)) << "]:" << std::endl;

	int count_packets = 3;//
	//Начать определять маршрутизацию
	int count_pack_id = 0;
	bool destination = false;
	cout << "Максимальное числом прыжков " << max_hops << endl;
	double average = 0;
	int count_pack = 0;
	for (int i = 0; i < max_hops; i++) {


		//время жизни
		ip.TTL = ip.TTL + 1;
		cout << " " << i + 1 << " ";


		for (int j = 0; j < count_packets;j++) {
			
			
			// id пакета для дальнешего определения ответа среди других пакетов в сети
			ip.packetId = htons(startPacketId + count_pack_id);

			// Расчет контрольной суммы 
			ip.checksum = ip_checksum((byte*)&ip, sizeof(IP));

			// Запаковка заголовков IP, UDP и данных в байтовый буфер
			memcpy(buffer.data(), &ip, sizeof(IP));
			memcpy(buffer.data() + sizeof(IP), &udp, sizeof(UDP));
			if (d.size() > 0)
				memcpy(buffer.data() + sizeof(IP) + sizeof(UDP), d.data(), d.size());

			auto begin = std::chrono::steady_clock::now();
			count_pack_id++;

			// Отправка UDP пакета
			sendto(sock, (char*)(buffer.data()), buffer.size(), 0, (sockaddr*)(&send_addr), sizeof(sockaddr));

			sockaddr_in recv_addr = { 0 };
			recv_addr.sin_family = AF_INET;
			recv_addr.sin_addr.S_un.S_addr = INADDR_ANY;
			recv_addr.sin_port = 0;

			// INADDR_ANY - это адрес, обозначенный как 0.0.0.0,
			// Указывает неопределенный адрес или «любой адрес». "

			int s = sizeof(sockaddr);
			while (true)
			{
				
				// Прием ICMP пакета
				int length = recvfrom(icmp, (char*)data, 1024, 0, (sockaddr*)&recv_addr, &s);

				auto end = std::chrono::steady_clock::now();

				//время отлика
				auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin);




				if (length == -1 || elapsed_ms.count() > 4000) // Время ожидания ответа вышло (length == -1 || elapsed_ms.count() > 4000)
				{
					cout << " * ";
					count_pack++;
					if (j == count_packets - 1) {

						std::cout << "Превышен интервал ожидания для запроса." << std::endl;
					}

					break;
				}

				average = average + elapsed_ms.count();
				

				if (length == sizeof(IP) + sizeof(ICMP) + sizeof(IP) + sizeof(UDP) + d.size() ||
					length == sizeof(IP) + sizeof(ICMP) + sizeof(IP) + sizeof(UDP)) // Если у пакета нужный размер,отсеиваем плохие пакеты
				{
					// Разбираем принятый пакет на:
					IP* iphdr = (IP*)data; // IP заголовок
					ICMP* icmphdr = (ICMP*)(data + sizeof(IP)); // ICMP заголовок
					IP* iphdr_ret = (IP*)(data + sizeof(IP) + sizeof(ICMP)); // IP заголовок недошедшего пакета
					UDP* udp = (UDP*)(data + sizeof(IP) + sizeof(ICMP) + sizeof(IP)); // UDP заголовок недошедшего пакета

					// Если у ICMP пакета тип 11, код 0 , то есть Время жизни дейтаграммы истекло

					if (icmphdr->type == 11 && icmphdr->code == 0 && iphdr_ret->packetId == ip.packetId)
					{
						// Выводим информацию о том что целевой узел доступен, время задержки
						std::cout << " время = " << elapsed_ms.count() << " ms ";

						if (j == count_packets - 1) {

							std::cout << "Среднее время = " << average / (double)(count_packets- count_pack) << " ms ";
							std::cout <<
								"Ответ от " << inet_ntop(AF_INET, &(iphdr->ipSrc), ipStrBuf, sizeof(ipStrBuf)) <<
								std::endl;
						}
						break;
					}


					// Если у ICMP пакета тип 3, код 3 (порт недоступен) и packetId из заголовка недошедшего пакета равен packetId из отправленного
					if (icmphdr->type == 3 && icmphdr->code == 3 && iphdr_ret->packetId == ip.packetId)
					{
						// Выводим информацию о том что целевой узел доступен, время задержки 
						std::cout << " время = " << elapsed_ms.count() << " ms ";

						if (j == count_packets - 1) {
							std::cout << "Среднее время = " << average / (double)(count_packets - count_pack) << " ms ";
							std::cout <<
								"Ответ от " << inet_ntop(AF_INET, &(iphdr->ipSrc), ipStrBuf, sizeof(ipStrBuf)) <<
								std::endl;
						}
						destination = true;
						break;
					}

					// Если у ICMP пакета тип 3, код 1 (узел недоступен) и packetId из заголовка недошедшего пакета равен packetId из отправленного
					if (icmphdr->type == 3 && icmphdr->code == 1 && iphdr_ret->packetId == ip.packetId)
					{
						// Выводим информацию о том что целевой узел недоступен
						std::cout <<
							"Ответ от " << inet_ntop(AF_INET, &(iphdr->ipSrc), ipStrBuf, sizeof(ipStrBuf)) <<
							": Target is unavailable" << std::endl;

						break;
					}



				}


			}

		}
		 average = 0;
		count_pack_id++;
		count_pack = 0;
		if (destination) {
			cout << " Трассировка завершена" << endl;
			return 0;
		}



	}

	return 2;
}


/*
for (int i = 0; i < max_hops; i++) {
		/* Базовые
		typedef struct traceinfo{
		int packetid;
		int ttl; //время жизни
		int proto; // протокол
		int size;
		unsigned long saddr; //размера адреса
		unsigned long daddr; // данные адреса
		} TRACE_INFO;


		*/

		//Каждый цикл создаем новый пакет  , пакетные данные обновляем
		// ip
		// udp
		// udp+mes


		//время отправления пакета
		// RequestTime      = GetTickCount(); //Извлекает количество миллисекундах, прошедших с момента запуска системы
		// 
		// отправляет ip+udp пакет (необходимо заполнить в ручную)
		// written          = sendto(sock,data,pack_size,0,(struct sockaddr *)&dest,sizeof(dest));
		/*
		if (written == SOCKET_ERROR)
		{
			printf("\n Sending packet failed. Check permissions on this system");
			printf("\n Admin rights are required on XP");
			return 1;
		}
		*/
		// 
		//  время принятия пакета
		//  ResponseTime  = GetTickCount();
		//latency = ResponseTime - RequestTime;
		// принимает  ip+icmp пакет в цикле while
		// декодируем,есть три ситуации
		// Время истекло при передаче
		// Порт не доступен
		//  Если пункт назначения недоступен,прекращаем
		// if((unsigned int)(icmpheader->type)==11) //Время жизни дейтаграммы истекло
	//	printf("  (TTL Expired)\n");
	//else if((unsigned int)(icmpheader->type)==0)  //Эхо-ответ
	//	printf("  (ICMP Echo Reply)\n");
//	else if((unsigned int)(icmpheader->type)==3)  //Адресат недоступен
//		DESTINATION_UNREACHABLE = 1;
		// 
		// 
		//время приема пакета

		/* КАК ПРОИСХОДИТ ДЕКОДИРОВАНИЕ ДАННЫХ
		* чекнуть у миши, не очень у других
		*

		*/




