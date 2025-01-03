#include "WNetHelper.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sstream>
#include <iostream>
#include <random>
#include <algorithm>
#ifndef WIN32
#include <netinet/in.h>
#endif // !WIN32

#include <ws2tcpip.h>
#include <iomanip>
#include <stdint.h>
#include <netfw.h>
#include <atlbase.h>
#include <regex>
#include <thread>

//#include "WLog.h"
#include "WStringUtils.hpp"
//#include "WDeviceSearchHelper.h"

std::string getProgramName() 
{
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameW(nullptr, buffer, MAX_PATH);
    std::wstring fullPath(buffer);

    size_t lastSlash = fullPath.find_last_of(L"\\/");
    std::wstring filename = fullPath.substr(lastSlash + 1);

    size_t lastDot = filename.find_last_of(L'.');
    std::wstring programName = filename.substr(0, lastDot);

    // 宽字符转窄字符
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, programName.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string result(size_needed - 1, 0); // -1 是因为最后的 null terminator 不需要
    WideCharToMultiByte(CP_UTF8, 0, programName.c_str(), -1, &result[0], size_needed, nullptr, nullptr);

    return result;
}

std::string getFullProgramPath() 
{
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameW(nullptr, buffer, MAX_PATH);
    std::wstring fullPath(buffer);

    // 宽字符转窄字符
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, fullPath.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string result(size_needed - 1, 0); // -1 是因为最后的 null terminator 不需要
    WideCharToMultiByte(CP_UTF8, 0, fullPath.c_str(), -1, &result[0], size_needed, nullptr, nullptr);

    return result;
}

//10进制转换成高进制，10进制值用参数传入，返回值是高进制字符串
std::string decToHex(long long dec)
{
	std::string hex = "";
	long long temp = dec;
	while (temp != 0)
	{
		long long remainder = temp % 36;
		if (remainder < 10)
		{
			hex = std::to_string(remainder) + hex;
		}
		else
		{
            char curChar = 'A' + remainder - 10;
            std::string curStr;
            curStr.append(1, curChar);

            hex = curStr + hex;
		}
		temp /= 36;
	}
	return hex;
}

//高进制转换成10进制，高进制值用字符串参数传入，返回值是10进制值
long long hexToDec(std::string hex)
{
	long long dec = 0;
	int len = hex.length();
	for (int i = 0; i < len; i++)
	{
		long long temp = 0;
        if (hex[i] >= '0' && hex[i] <= '9') {
            temp = hex[i] - '0';
        }
        else if(hex[i] == 'A') {
			temp = 10;
		}
		else {
			temp = 10 + hex[i] - 'A';
		}

		dec += temp * pow(36, len - i - 1);
	}
	return dec;
}

WNetHelper::WNetHelper() {
    QueryAdapterList();
    m_curIP = GetCurrentIPAddress();
    m_curCode = IPToCodeEx(m_curIP.c_str());

	//WLogInfo("curIP: %s curCode: %s", m_curIP.c_str(), m_curCode.c_str());

    m_ruleName = getProgramName();
    m_fullProgramPath = getFullProgramPath();
}

WNetHelper::~WNetHelper() {
    // 存在MT编译时，跨模块释放问题，先注释掉
    // 因为是单例，生命周期到程序退出，可以等系统自动回收
    //CleanAdapterList();
}

WNetHelper& WNetHelper::getInstance() {
	static WNetHelper wNetHelper;
	return wNetHelper;
}

const char* WNetHelper::GetCode(int length, bool refresh) {
    m_curCode = IPToCode(length, GetCurrentIPAddress().c_str(), refresh);

    //WLogInfo("refresh %d, castcode: %s", refresh, m_curCode.c_str());

    return m_curCode.c_str();
}

const char* WNetHelper::GetCodeEx() {
    m_curCode = IPToCodeEx(GetCurrentIPAddress().c_str());

    //WLogInfo("%s castcode: %s", __FUNCTION__, m_curCode.c_str());

    return m_curCode.c_str();
}

const char* WNetHelper::GetIP() {
    return m_curIP.c_str();
}

std::string WNetHelper::IPToCode(int length, const char* ip, bool refresh) {
    if (ip == nullptr || ip[0] == '\0')
    {
        m_curCode = "";
        return m_curCode.c_str();
    }

    auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    std::default_random_engine e(seed);

    std::string m_curCode_temp;
    if (length == 6) {
        int ramdom = refresh ? 1 + e() % 160 : 1;
        int s1, s2, s3, s4;
        sscanf(ip, "%d.%d.%d.%d", &s1, &s2, &s3, &s4);
        std::stringstream stream;
        stream << std::setw(6) << std::setfill('0') << std::hex << (ramdom * 100000) + (s3 << 8) + s4;
        m_curCode_temp = stream.str();
    }
    else if (length == 8) {
        int ramdom = refresh ? 1 + e() % 42 : 1;
        //WLogInfo("ramdom: %d", ramdom);
        int s1, s2, s3, s4;
        sscanf(ip, "%d.%d.%d.%d", &s1, &s2, &s3, &s4);
        std::stringstream stream;
        stream << std::setw(8) << std::setfill('0') << std::hex << (ramdom * 100000000) + (s2 << 16) + (s3 << 8) + s4;
        //WXLogInfo("s2 << 16: %d", (s2 << 16));
        //WXLogInfo("s3 << 8: %d", (s3 << 8));
        //WXLogInfo("s4: %d", (s4));
        m_curCode_temp = stream.str();
    }

    //转换大写
    transform(m_curCode_temp.begin(), m_curCode_temp.end(), m_curCode_temp.begin(), ::toupper);

    return m_curCode_temp;
}

std::string WNetHelper::IPToCodeEx(const char* ip) {
    if (ip == nullptr || ip[0] == '\0')
    {
        m_curCode = "";
        return m_curCode.c_str();
    }
    std::string strIP = ip;
    std::string prefix = strIP.substr(0, 7);
    std::string m_curCode_temp;
    if (prefix == "192.168") {
        int highBit = 1;
        int s1, s2, s3, s4;
        sscanf(ip, "%d.%d.%d.%d", &s1, &s2, &s3, &s4);
        std::stringstream stream;
        stream << std::setw(6) << std::setfill('0') << std::hex << (highBit * 100000) + (s3 << 8) + s4;
        m_curCode_temp = stream.str();
    }
    else
    {
        int s1, s2, s3, s4;
        sscanf(ip, "%d.%d.%d.%d", &s1, &s2, &s3, &s4);
        std::stringstream stream;
        stream << std::setw(8) << std::setfill('0') << std::hex << (s1 << 24) + (s2 << 16) + (s3 << 8) + s4;
        m_curCode_temp = "1" + stream.str();
    }

    //转换大写
    transform(m_curCode_temp.begin(), m_curCode_temp.end(), m_curCode_temp.begin(), ::toupper);

    return m_curCode_temp;
}

const char* WNetHelper::CodeToIP(const char* code) {
    if (code == nullptr || code[0] == '\0')
    {
        return "";
    }

    //WLogInfo("castcode: %s", code);

    static std::string s_ip;
    unsigned int x;
    std::stringstream ss;
    std::stringstream ip;
    ss << std::hex << code;
    ss >> x;

    if (x == 0)
    {
        s_ip = "";
        return s_ip.c_str();
    }

    if (strlen(code) == 6) {
        std::string prefix = "192.168";// IPSegmentAddress(2);
        //WLogInfo("prefix: %s", prefix.c_str());

        x = x % 100000;
        int s3 = (x & 0x00ff00) >> 8;
        int s4 = x & 0x0000ff;
        //WLogInfo("SegmentAddress: %d.%d", s3, s4);

        ip << prefix << "." << s3 << "." << s4;
        s_ip = ip.str();
    }
    else if (strlen(code) == 8) {
        std::string prefix = IPSegmentAddress(1);
        //WLogInfo("prefix: %s", prefix.c_str());

        x = x % 100000000;
		int s2 = (x & 0xff0000) >> 16;
		int s3 = (x & 0x00ff00) >> 8;
		int s4 = x & 0x0000ff;
        //WLogInfo("SegmentAddress: %d.%d.%d", s2, s3, s4);

		ip << prefix << "." << s2 << "." << s3 << "." << s4;
		s_ip = ip.str();
    }
    else if (strlen(code) == 9) {
        std::string strCode = code;
        unsigned int x;
        std::stringstream ss;
        ss << std::hex << strCode.substr(1);
        ss >> x;

        int s1 = (x & 0xff000000) >> 24;
        int s2 = (x & 0x00ff0000) >> 16;
        int s3 = (x & 0x0000ff00) >> 8;
        int s4 = x & 0x000000ff;
        //WLogInfo("SegmentAddress: %d.%d.%d.%d", s1, s2, s3, s4);

        ip << s1 << "." << s2 << "." << s3 << "." << s4;
        s_ip = ip.str();
    }
    else {
        s_ip = "";
    }
    //WLogInfo("CastHostIP: %s", s_ip.c_str());

    return s_ip.c_str();
}

const char* WNetHelper::CurrentLocalCode() {
    return m_curCode.c_str();
}

bool WNetHelper::BonjourServiceIsRunning() {
    SC_HANDLE hService;
    SC_HANDLE hSCManager;
    SERVICE_STATUS ssStatus;
    const char* hsService;
    hsService = "Bonjour Service";

    if ((hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT)) == NULL)
    {
        //WLogInfo("OpenSCManager failed (%d)", GetLastError());
        CloseServiceHandle(hSCManager);
        return false;
    }

    if ((hService = OpenServiceA(hSCManager, hsService, SERVICE_QUERY_STATUS)) == NULL)
    {
        //WLogInfo("%s, OpenService failed (%d)\n", __FUNCTION__, GetLastError());
        if (GetLastError() == 5)
        {
            printf("please check your user privilege, your should use administrator privilege start it\n");
            //WLogInfo("please check your user privilege, your should use administrator privilege start it");
        }
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return false;
    }
    else
    {
        if (QueryServiceStatus(hService, &ssStatus))
        {
            if (ssStatus.dwCurrentState != SERVICE_RUNNING)//RUNNINGSERVICE_STOPPED 
            {
                if (StartService(hService, 0, NULL) == 0)
                {
                    //WLogInfo("bonjour service is not running, please check it");
                    CloseServiceHandle(hService);
                    CloseServiceHandle(hSCManager);
                    return false;
                }
            }
        }
    }
    //WLogInfo("bonjour service is running");
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return true;
}

bool WNetHelper::IsFirewallRuleEnabled() {
    HRESULT hr;

    CComPtr<INetFwPolicy2> fwPolicy2;
    hr = fwPolicy2.CoCreateInstance(__uuidof(NetFwPolicy2));
    if (FAILED(hr)) {
        //WLogError("Failed to create firewall policy object.");
        return false;
    }

    CComPtr<INetFwRules> fwRules;
    hr = fwPolicy2->get_Rules(&fwRules);
    if (FAILED(hr)) {
        //WLogError("Failed to get firewall rules collection.");
        return false;
    }

    CComPtr<IUnknown> fwRuleEnumerator;
    hr = fwRules->get__NewEnum(&fwRuleEnumerator);
    if (FAILED(hr)) {
        //WLogError("Failed to get rule enumerator.");
        return false;
    }

    CComPtr<IEnumVARIANT> pEnum;
    hr = fwRuleEnumerator->QueryInterface(IID_IEnumVARIANT, (void**)&pEnum);
    if (FAILED(hr)) {
        //WLogError("Failed to query interface for rule enumerator.");
        return false;
    }

    CComVariant item;

    bool inboundRuleOK = false;
    //bool outboundRuleOK = false;

    //WLogInfo("m_ruleName: %s, m_fullProgramPath: %s", m_ruleName.c_str(), m_fullProgramPath.c_str());
    // Query all rules
    while (S_OK == pEnum->Next(1, &item, nullptr)) {
        CComPtr<INetFwRule> fwRule;
        hr = item.punkVal->QueryInterface(IID_INetFwRule, (void**)&fwRule);
        if (SUCCEEDED(hr)) {
            // Get rule name
            BSTR ruleNameBstr;
            BSTR appNameBstr;
            fwRule->get_Name(&ruleNameBstr);
            fwRule->get_ApplicationName(&appNameBstr);

            if (ruleNameBstr != nullptr && appNameBstr != nullptr) {
                // Find rule by name and program path
                int size_needed = WideCharToMultiByte(CP_UTF8, 0, ruleNameBstr, -1, nullptr, 0, nullptr, nullptr);
                std::string strRuleName(size_needed - 1, 0); // -1 是因为最后的 null terminator 不需要
                WideCharToMultiByte(CP_UTF8, 0, ruleNameBstr, -1, &strRuleName[0], size_needed, nullptr, nullptr);

                size_needed = WideCharToMultiByte(CP_UTF8, 0, appNameBstr, -1, nullptr, 0, nullptr, nullptr);
                std::string strAppName(size_needed - 1, 0); // -1 是因为最后的 null terminator 不需要
                WideCharToMultiByte(CP_UTF8, 0, appNameBstr, -1, &strAppName[0], size_needed, nullptr, nullptr);
                //strRuleName strAppName UTF编码
                //WLogInfo("strRuleName: %s, strAppName: %s", strRuleName.c_str(), strAppName.c_str());
                
                if (WStringUtils::CompareNoCase(strRuleName, m_ruleName) == 0 &&
                    WStringUtils::CompareNoCase(strAppName, m_fullProgramPath) == 0) {
                    long profiles = 0;
                    hr = fwRule->get_Profiles(&profiles);
                    if (SUCCEEDED(hr)) {
                        // Check profiles
                        if ((profiles & NET_FW_PROFILE2_PUBLIC) && (profiles & NET_FW_PROFILE2_PRIVATE)) {
                            NET_FW_ACTION action;
                            hr = fwRule->get_Action(&action);
                            if (SUCCEEDED(hr) && action == NET_FW_ACTION_ALLOW) {
                                VARIANT_BOOL enabled;
                                hr = fwRule->get_Enabled(&enabled);
                                if (SUCCEEDED(hr) && enabled == VARIANT_TRUE) {
                                    // Get rule direction
                                    NET_FW_RULE_DIRECTION_ direction;
                                    hr = fwRule->get_Direction(&direction);
                                    if (SUCCEEDED(hr)) {
                                        if (direction == NET_FW_RULE_DIR_IN) {
                                            //WLogInfo("Inbound firewall rule is configured correctly");
                                            inboundRuleOK = true;
                                        }
                                        else if (direction == NET_FW_RULE_DIR_OUT) {
                                            //WLogInfo("Outbound firewall rule is configured correctly");
                                            //outboundRuleOK = true;
                                        }
                                    }
                                }
                                else
                                {
                                    //WLogInfo("Firewall rule is disabled");
                                }
                            }
                            else {
							    //WLogInfo("Firewall rule is blocked");
                            }
                        }
                        else {
                            if (!(profiles & NET_FW_PROFILE2_PUBLIC)) {
                                //WLogInfo("Public profile is not enabled for firewall rule");
                            }

                            if(!(profiles & NET_FW_PROFILE2_PRIVATE)) {
								//WLogInfo("Private profile is not enabled for firewall rule");
							}
                        }


                    }
                }
            }
            item.Clear();
        }
    }

    if (inboundRuleOK/* && outboundRuleOK*/) {
        //WLogInfo("Firewall rule is configured correctly");
        return true;
    }

    //WLogInfo("Firewall rule is not configured correctly");

    return false;
}

bool WNetHelper::IsValidIP(const char* ip) {
    std::regex pattern("^((\\d{1,2}|1\\d{2}|2[0-4]\\d|25[0-5])\\.){3}(\\d{1,2}|1\\d{2}|2[0-4]\\d|25[0-5])$");

    return std::regex_match(ip, pattern);
}

bool WNetHelper::IsLocalIP(const char* ip) {
    for (IP_ADAPTER_ADDRESSES adapter : GetAdapterList())
    {
        if (adapter.OperStatus == IF_OPER_STATUS::IfOperStatusUp)
        {
            std::string strIP = GetIpStr(adapter.FirstUnicastAddress->Address.lpSockaddr);
            if (strcmp(ip, strIP.c_str()) == 0)
            {
				return true;
			}
        }
    }

    return false;
}

void WNetHelper::QueryAdapterList() {
    CleanAdapterList();

    const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;
    ULONG ulOutBufLen;

    if (GetAdaptersAddresses(AF_INET, flags, nullptr, nullptr, &ulOutBufLen) != ERROR_BUFFER_OVERFLOW)
        return;

    m_adapterAddresses.resize(ulOutBufLen);
    auto adapterAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(m_adapterAddresses.data());

    if (GetAdaptersAddresses(AF_INET, flags, nullptr, adapterAddresses, &ulOutBufLen) == NO_ERROR)
    {
        for (PIP_ADAPTER_ADDRESSES adapter = adapterAddresses; adapter; adapter = adapter->Next)
        {
            if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK || adapter->OperStatus != IF_OPER_STATUS::IfOperStatusUp)
                continue;
            m_adapters.push_back(*adapter);
        }

        // 用于确定适配器的优先级
        auto adapterPriority = [](const IP_ADAPTER_ADDRESSES& adapter) {
            std::string adapterName(WStringUtils::FromWString(adapter.Description));
            if (adapterName.find("ZeroTier") != std::wstring::npos|| adapterName.find("WireGuard") != std::wstring::npos)
                return 2;
            else if (adapter.IfType == IF_TYPE_IEEE80211)  // WiFi 适配器
                return 1;
            else
                return 0;
        };

        // 根据优先级对适配器进行排序
        std::sort(m_adapters.begin(), m_adapters.end(), [&adapterPriority](const IP_ADAPTER_ADDRESSES& a, const IP_ADAPTER_ADDRESSES& b) {
            return adapterPriority(a) > adapterPriority(b);
            });
    }
    else
        std::cout << "GetAdaptersAddresses() failed ..." << std::endl;
}

void WNetHelper::CleanAdapterList() {
    std::vector<IP_ADAPTER_ADDRESSES>::iterator it = m_adapters.begin();
    while (it != m_adapters.end())
    {
        it = m_adapters.erase(it);
    }
}

std::vector<IP_ADAPTER_ADDRESSES>& WNetHelper::GetAdapterList() {
    //std::unique_lock<CCriticalSection> lock(m_critSection);
    //if (m_netrefreshTimer.GetElapsedSeconds() >= 5.0f)
    //    queryInterfaceList();

    //刷新适配器，此时很可能切换了网络
    QueryAdapterList();

    return m_adapters;
}

IP_ADAPTER_ADDRESSES WNetHelper::GetFirstConnectedAdapter() {
    for (IP_ADAPTER_ADDRESSES adapter : GetAdapterList())
    {
      if (adapter.OperStatus == IF_OPER_STATUS::IfOperStatusUp && 
          !GetCurrentDefaultGateway(adapter).empty()) {       
            return adapter;
        }
    }

    return  IP_ADAPTER_ADDRESSES(); // Return the first found connected adapter if no wireless adapter is found
}

std::string WNetHelper::IPSegmentAddress(int segments) {
    if (segments < 1 || segments > 4)
        return "";

    size_t index;
    std::string ipSegmentAddress = m_curIP;

    for (int i = 0; i < (4 - segments); ++i)
    {
        index = ipSegmentAddress.find_last_of('.');
        ipSegmentAddress = ipSegmentAddress.substr(0, index).c_str();
    }

    return ipSegmentAddress;
}

std::string WNetHelper::GetIpStr(const struct sockaddr* sa) {
    std::string result;
    if (!sa)
        return result;

    char buffer[INET6_ADDRSTRLEN] = {};
    switch (sa->sa_family)
    {
    case AF_INET:
        inet_ntop(AF_INET, &reinterpret_cast<const struct sockaddr_in*>(sa)->sin_addr, buffer, INET_ADDRSTRLEN);
        break;
    case AF_INET6:
        inet_ntop(AF_INET6, &reinterpret_cast<const struct sockaddr_in6*>(sa)->sin6_addr, buffer, INET6_ADDRSTRLEN);
        break;
    default:
        return result;
    }

    result = buffer;
    return result;
}

std::string WNetHelper::GetCurrentIPAddress() {
    IP_ADAPTER_ADDRESSES adapter = GetFirstConnectedAdapter();
    if (!adapter.FirstUnicastAddress)
        return "";

    std::string curIP = GetIpStr(adapter.FirstUnicastAddress->Address.lpSockaddr);
    if (m_curIP != curIP) {
        if (!m_curIP.empty()) {
            auto tcpServerThread = new std::thread([=]() {
                //WLogInfo("Restart  DeviceSearch server");

                //G_WXDeviceSearchHelper.Stop();
                //G_WXDeviceSearchHelper.Start();

                });
            tcpServerThread->detach();
        }

        //WLogInfo("IP change to: %s", curIP.c_str());
        m_curIP = curIP;  
    }

    return m_curIP;
}

std::string WNetHelper::GetCurrentDefaultGateway(IP_ADAPTER_ADDRESSES adapter) {
    if (!adapter.FirstGatewayAddress)
        return "";

    // Check for certain substrings in the adapter's description
    std::string description = WStringUtils::FromWString(adapter.Description);
    if (
        description.find("VMware") != std::string::npos ||
        description.find("VirtualBox") != std::string::npos ||
        description.find("Hyper-V") != std::string::npos)
    {
        return "";
    }

    //WLogInfo("Adapter name: %s, Friendly name: %s", adapter.AdapterName, WXStringUtils::FromWString(adapter.FriendlyName).c_str());

    return GetIpStr(adapter.FirstGatewayAddress->Address.lpSockaddr);
}