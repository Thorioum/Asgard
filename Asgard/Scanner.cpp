#include "Scanner.h"
#include "Memory.h"

uintptr_t Scanner::scan(const ScanData& signature, const ScanData& data)
{
	for (size_t currentIndex = 0; currentIndex < data.size - signature.size; currentIndex++) {
		for (size_t sigIndex = 0; sigIndex < signature.size; sigIndex++) {
			if (data.data[currentIndex + sigIndex] != signature.data[sigIndex] && signature.data[sigIndex] != '?') {
				break;
			}
			else if (sigIndex == signature.size - 1) {
				return currentIndex;
			}
		}
	}
	return 0;
}
std::list<uintptr_t>Scanner::fullscan(const ScanData& signature, const ScanData& data)
{
	std::list<uintptr_t> list;

	for (size_t currentIndex = 0; currentIndex < data.size - signature.size; currentIndex++) {
		for (size_t sigIndex = 0; sigIndex < signature.size; sigIndex++) {
			if (data.data[currentIndex + sigIndex] != signature.data[sigIndex] && signature.data[sigIndex] != '?') {
				break;
			}
			else if (sigIndex == signature.size - 1) {
				list.push_back(currentIndex);
			}
		}
	}
	return list;
}