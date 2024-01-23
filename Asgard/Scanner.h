#include "ScanData.h"
#include <list>

class Scanner {
public:
	 static DLLEXPORT uintptr_t  scan(const ScanData& signature, const ScanData& data);
	 static DLLEXPORT std::list<uintptr_t>  fullscan(const ScanData& signature, const ScanData& data);
private:
	
};
