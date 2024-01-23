#pragma once
//https://github.com/CasualCoder91/PatternScannerBMH/blob/master/SpeedTest/ScanData.h
#include <string>
#define DLLEXPORT __declspec(dllexport)

class ScanData
{
private:
	static const size_t hexTable[];

public:
	unsigned char* data; //byte array
	size_t size = 0;

	DLLEXPORT ScanData(const std::string input);
	DLLEXPORT ScanData(size_t size);
	DLLEXPORT ~ScanData();

	DLLEXPORT void print();

};