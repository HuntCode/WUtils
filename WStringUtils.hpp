#ifndef WUTILS_STRING_UTILS_H
#define WUTILS_STRING_UTILS_H

#if defined(_WIN32) || defined (_WIN64)
#include <Windows.h>
#endif

#include <string>
#include <vector>
#include <algorithm>
#include <assert.h>
#include <iterator>
//#include <codecvt>
#include <locale>

#include <memory>
#include <chrono>
#include <format>
#ifndef FMT_HEADER_ONLY
#define FMT_HEADER_ONLY
#endif

#define FORMAT_BLOCK_SIZE 512 // # of bytes for initial allocation for printf


 // workaround for broken [[deprecated]] in coverity
#if defined(__COVERITY__)
#undef FMT_DEPRECATED
#define FMT_DEPRECATED
#endif
//#include <fmt/format.h>
//#if FMT_VERSION >= 40000
//#include <fmt/printf.h>
//#endif
#include <format>
//#include <WXBase.h>
#include <cassert>


template<typename T, std::enable_if_t<!std::is_enum<T>::value, int> = 0>
constexpr auto&& EnumToInt(T&& arg) noexcept
{
	return arg;
}
template<typename T, std::enable_if_t<std::is_enum<T>::value, int> = 0>
constexpr auto EnumToInt(T&& arg) noexcept
{
	return static_cast<int>(arg);
}

class WStringUtils
{
public:
	
#if defined(_WIN32) || defined (_WIN64)
	static std::string FromWString(const wchar_t* str, int length)
	{
		int result = WideCharToMultiByte(CP_UTF8, 0, str, length, nullptr, 0, nullptr, nullptr);
		if (result == 0)
			return std::string();

		auto newStr = std::make_unique<char[]>(result);
		result = WideCharToMultiByte(CP_UTF8, 0, str, (int)length, newStr.get(), result, nullptr, nullptr);
		if (result == 0)
			return std::string();

		return std::string(newStr.get(), result);
	}

	static std::string FromWString(const std::wstring& str)
	{
		return FromWString(str.c_str(), (int)str.length());
	}

	static std::wstring ToWString(const char* str, int length)
	{
		int result = MultiByteToWideChar(CP_UTF8, 0, str, length, nullptr, 0);
		if (result == 0)
			return std::wstring();

		auto newStr = std::make_unique<wchar_t[]>(result);
		result = MultiByteToWideChar(CP_UTF8, 0, str, length, newStr.get(), result);

		if (result == 0)
			return std::wstring();

		return std::wstring(newStr.get(), result);
	}

	static std::wstring ToWString(const std::string& str)
	{
		return ToWString(str.c_str(), (int)str.length());
	}
#endif

	/**
	 * 时长(单位：秒)跟时间字符串转换，时间字符串的格式HH::MM::SS
	 */


	/**
	 * 当前时间戳字符串，从1970-01-01 00:00:00计，例如“1646064000”的字符串
	 */
	

	/**
	 * 秒数转换时间戳字符串
	 *
	 * 从1970-01-01 00:00:00计，例如1646064000，返回2022-03-01 00:00:00
	 */
	
	static int CompareNoCase(const std::string& str1, const std::string& str2, size_t n = 0)
	{
		return CompareNoCase(str1.c_str(), str2.c_str(), n);
	}

	static int CompareNoCase(const char* s1, const char* s2, size_t n = 0)
	{
		char c2; // we need only one char outside the loop
		size_t index = 0;
		do
		{
			const char c1 = *s1++; // const local variable should help compiler to optimize
			c2 = *s2++;
			index++;
			if (c1 != c2 && ::tolower(c1) != ::tolower(c2)) // This includes the possibility that one of the characters is the null-terminator, which implies a string mismatch.
				return ::tolower(c1) - ::tolower(c2);
		} while (c2 != '\0' &&
			index != n); // At this point, we know c1 == c2, so there's no need to test them both.
		return 0;
	}
	
	static std::string DecToHex(char num, int radix)
	{
		char hexVals[16] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };

		int temp = 0;
		std::string csTmp;
		int num_char;
		num_char = (int)num;

		// ISO-8859-1 
		// IF THE IF LOOP IS COMMENTED, THE CODE WILL FAIL TO GENERATE A 
		// PROPER URL ENCODE FOR THE CHARACTERS WHOSE RANGE IN 127-255(DECIMAL)
		if (num_char < 0)
			num_char = 256 + num_char;

		while (num_char >= radix)
		{
			temp = num_char % radix;
			num_char = (int)floor((num_char / radix) * 1.0);
			csTmp = hexVals[temp];
		}

		csTmp += hexVals[num_char];

		if (csTmp.length() < 2)
		{
			csTmp += '0';
		}

		std::string strdecToHex = csTmp;
		// Reverse the String
		std::reverse(strdecToHex.begin(), strdecToHex.end());

		return strdecToHex;
	}


	// hack to check only first byte of UTF-8 character
	// without this hack "TrimX" functions failed on Win32 and OS X with UTF-8 strings
	static int isspace_c(char c)
	{
		return (c & 0x80) == 0 && ::isspace(c);
	}


	static int Replace(std::string& str, char oldChar, char newChar)
	{
		int replacedChars = 0;
		for (std::string::iterator it = str.begin(); it != str.end(); ++it)
		{
			if (*it == oldChar)
			{
				*it = newChar;
				replacedChars++;
			}
		}

		return replacedChars;
	}

	static std::wstring ANSIToUnicode(const std::string& str)
	{
		//得到str的字节数
		int len = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, nullptr, 0);
		wchar_t* wstr = new wchar_t[sizeof(wchar_t) * len];
		MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, wstr, len);
		std::wstring destr = wstr;
		delete[] wstr;
		return destr;
	}

	static std::string ANSIToUTF8(const std::string& str)
	{
		std::wstring wstr = ANSIToUnicode(str);
		std::string destr = UnicodeToUTF8(wstr);
		return destr;
	}

	static std::string UnicodeToANSI(const std::wstring& wstr)
	{
		// 得到wstr的字节数
		int len = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
		char* str = new char[sizeof(char) * len];
		WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, str, len, nullptr, nullptr);
		std::string destr = str;
		delete[] str;
		return destr;
	}

	static std::string UnicodeToUTF8(const std::wstring& wstr)
	{
		// 得到wstr的字节数
		int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
		char* str = new char[sizeof(char) * len];
		WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, str, len, nullptr, nullptr);
		std::string destr = str;
		delete[] str;
		return destr;
	}

	std::string UTF8ToANSI(const std::string& str)
	{
		std::wstring wstr = UTF8ToUnicode(str);
		std::string destr = UnicodeToANSI(wstr);
		return destr;
	}

	std::wstring UTF8ToUnicode(const std::string& str)
	{
		//得到str的字节数
		int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
		wchar_t* wstr = new wchar_t[sizeof(wchar_t) * len];
		MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, wstr, len);
		std::wstring destr = wstr;
		delete[] wstr;
		return destr;
	}


private:


};

#endif // WUTILS_STRING_UTILS_H
