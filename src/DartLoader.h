#pragma once
#include "ElfHelper.h"

class DartLoader final
{
public:

	static Dart_Isolate Load(LibAppInfo& libInfo);
	static void Unload();

private:
	DartLoader() = delete;
};

