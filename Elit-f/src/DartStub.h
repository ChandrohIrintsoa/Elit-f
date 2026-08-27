#pragma once
#include <string>
#include "DartFnBase.h"
#include <vm/stub_code_list.h>

class DartAbstractType;

class DartStub : public DartFnBase
{
public:
	enum Kind : int32_t {
#ifdef ELITF_DART_SINGLE_SNAPSHOT
#define DO(name) name ## Stub,
		VM_STUB_CODE_LIST(DO)
#undef DO
#else
#define DO(member, name) name ## Stub,
		OBJECT_STORE_STUB_CODE_LIST(DO)
#undef DO
		BuildNonGenericMethodExtractorStub,
		BuildGenericMethodExtractorStub,
#define DO(name) name ## VMStub,
		VM_STUB_CODE_LIST(DO)
#undef DO
#endif
		SharedStub,
		AllocateUserObjectStub,
		TypeCheckStub,
		UnknownStub,
	};

	DartStub(const dart::CodePtr ptr, Kind kind, uint64_t addr, int64_t size, std::string name) :
		DartFnBase(addr, size, std::move(name)), ptr(ptr), kind(kind) {}
	DartStub() = delete;
	DartStub(const DartStub&) = default;
	DartStub(DartStub&&) = delete;
	DartStub& operator=(const DartStub&) = delete;
	virtual ~DartStub() {}

	virtual std::string FullName() const { return name + "Stub"; }
	virtual bool IsStub() const { return true; }

	DartStub* Split(uint64_t another_ep_addr) {
		auto updateSize = another_ep_addr - ep_addr;
		auto newStub = new DartStub(ptr, kind, another_ep_addr, size - updateSize, name);
		size = updateSize;
		return newStub;
	}

	const dart::CodePtr ptr;
	const Kind kind;
};

class DartAllocateStub : public DartStub {
public:
	DartAllocateStub(const dart::CodePtr ptr, uint64_t addr, int64_t size, uint32_t cid, std::string name) :
		DartStub(ptr, AllocateUserObjectStub, addr, size, std::move(name)), cid(cid) {}
	DartAllocateStub() = delete;
	DartAllocateStub(const DartAllocateStub&) = delete;
	DartAllocateStub(DartAllocateStub&&) = delete;
	DartAllocateStub& operator=(const DartAllocateStub&) = delete;

	virtual std::string FullName() const { return "Allocate" + name + "Stub"; }
	virtual uint32_t ReturnType() const { return cid; }

private:
	const uint32_t cid;
};

class DartTypeStub : public DartStub {
public:
	DartTypeStub(const dart::CodePtr ptr, const uint64_t addr, int64_t size, const DartAbstractType& abType, std::string name) :
		DartStub(ptr, TypeCheckStub, addr, size, std::move(name)), abType(abType) {}
	DartTypeStub() = delete;
	DartTypeStub(const DartTypeStub&) = delete;
	DartTypeStub(DartTypeStub&&) = delete;
	DartTypeStub& operator=(const DartTypeStub&) = delete;

	virtual std::string FullName() const { return "IsType_" + name + "_Stub"; }

	const DartAbstractType& abType;
};

class DartNativeFn : public DartFnBase
{
public:
	DartNativeFn(uint64_t addr, int64_t size, std::string name) :
		DartFnBase(addr, size, std::move(name)) {}
	DartNativeFn() = delete;
	DartNativeFn(const DartNativeFn&) = delete;
	DartNativeFn(DartNativeFn&&) = delete;
	DartNativeFn& operator=(const DartNativeFn&) = delete;
};
