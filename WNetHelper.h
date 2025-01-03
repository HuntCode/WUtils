#ifndef WUTILS_NETHELPER_H
#define WUTILS_NETHELPER_H

#include <string>
#include <vector>
#include <winsock2.h>
#include <iphlpapi.h>

#ifdef  __cplusplus
#define EXTERN_C extern "C"
#else
#define EXTERN_C
#endif // __cplusplus

#ifdef WBASE_EXPORTS
#define WNETHELPER_API __declspec(dllexport)
#else
#define WNETHELPER_API __declspec(dllimport)
#endif // WBASE_EXPORTS

#define G_WNetHelper WNetHelper::getInstance()

class WNetHelper
{
public:
	~WNetHelper();
	static WNetHelper& getInstance();

	const char* GetCode(int length = 6, bool refresh = false);
    const char* GetCodeEx();
	const char* GetIP();

	std::string IPToCode(int length, const char* ip, bool refresh = false);
    std::string IPToCodeEx(const char* ip);

	const char* CodeToIP(const char* code);

    const char* CurrentLocalCode();

    bool BonjourServiceIsRunning();

    bool IsFirewallRuleEnabled();

    bool IsValidIP(const char* ip);

    bool IsLocalIP(const char* ip); //主要针对多网卡情况

private:
    WNetHelper();

	void QueryAdapterList();
	void CleanAdapterList();
	std::vector<IP_ADAPTER_ADDRESSES>& GetAdapterList();
	IP_ADAPTER_ADDRESSES GetFirstConnectedAdapter();
	//获取一个有效的IP地址，如果存在多个网卡，取其中一个，且不保证固定

	std::string IPSegmentAddress(int segments);

	std::string GetIpStr(const struct sockaddr* sa);
	std::string GetCurrentIPAddress();
	std::string GetCurrentDefaultGateway(IP_ADAPTER_ADDRESSES adapter);
	std::string m_curCode;
	std::string m_curIP;

	std::vector<IP_ADAPTER_ADDRESSES> m_adapters;
	std::vector<uint8_t> m_adapterAddresses;

    std::string m_ruleName; // firewall rule name, same as LetsView
    std::string m_fullProgramPath; // full path to the executable, same as C:\\Path\\to\\LetsView.exe
};

#endif  // WUTILS_NETHELPER_H