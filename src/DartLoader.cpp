#include "DartSdk.h"
#include "DartLoader.h"
#include <stdexcept>
#include <cstdlib>


static void init_vm_flags()
{
	const char* options[] = {
		"--precompilation",
	};
	char* error = Dart_SetVMFlags(sizeof(options) / sizeof(*options), options);
	if (error)
		throw std::runtime_error(error);
}

#ifdef BLUTTER_DART_SINGLE_SNAPSHOT
static void init_dart()
{
	char* error = NULL;

	Dart_InitializeParams init_params;
	memset(&init_params, 0, sizeof(init_params));
	init_params.version = DART_INITIALIZE_PARAMS_CURRENT_VERSION;
	init_params.start_kernel_isolate = false;
	error = Dart_Initialize(&init_params);
	if (error) {
		throw std::runtime_error(error);
	}
}
#else
static void init_dart(const uint8_t* vm_snapshot_data, const uint8_t* vm_snapshot_instructions)
{
	char* error = NULL;

	Dart_InitializeParams init_params;
	memset(&init_params, 0, sizeof(init_params));
	init_params.version = DART_INITIALIZE_PARAMS_CURRENT_VERSION;
	init_params.vm_snapshot_data = vm_snapshot_data;
	init_params.vm_snapshot_instructions = vm_snapshot_instructions;
	init_params.start_kernel_isolate = false;
	error = Dart_Initialize(&init_params);
	if (error) {
		throw std::runtime_error(error);
	}
}

static Dart_Isolate load_isolate(const uint8_t* isolate_snapshot_data, const uint8_t* isolate_snapshot_instructions)
{
	char* error = NULL;

	Dart_IsolateFlags flags;
	Dart_IsolateFlagsInitialize(&flags);
	flags.is_system_isolate = false;
#ifdef BLUTTER_DART_SINGLE_SNAPSHOT
	flags.null_safety = true;
#else
	auto pos = strstr((const char*)isolate_snapshot_data + 0x30, "null-safety");
	if (pos == NULL) {
		flags.null_safety = true;
	}
	else {
		flags.null_safety = pos[-1] == ' ';
	}
#endif

	auto isolate = Dart_CreateIsolateGroup(nullptr, nullptr, isolate_snapshot_data,
		isolate_snapshot_instructions, &flags,
		nullptr, nullptr, &error);
	if (isolate == NULL) {
		throw std::runtime_error(error);
	}

	return isolate;
}

Dart_Isolate DartLoader::Load(LibAppInfo& libInfo)
{
	init_vm_flags();

#ifdef BLUTTER_DART_SINGLE_SNAPSHOT
	init_dart();
#else
	init_dart(libInfo.vm_snapshot_data, libInfo.vm_snapshot_instructions);
#endif

	auto isolate = load_isolate(libInfo.isolate_snapshot_data, libInfo.isolate_snapshot_instructions);

	return isolate;
}

template<typename T>
inline void ignore_result(const T& ) {}

void DartLoader::Unload()
{
	if (Dart_CurrentIsolate() != nullptr) {
		Dart_ShutdownIsolate();
	}
	ignore_result(Dart_Cleanup());
}

