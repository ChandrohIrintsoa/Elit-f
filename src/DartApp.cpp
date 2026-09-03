#include "DartSdk.h"
#include "DartApp.h"
#include "ElfHelper.h"
#include "DartLoader.h"
PRAGMA_WARNING(push, 0)
#include <vm/stub_code.h>
#include <vm/heap/safepoint.h>
PRAGMA_WARNING(pop)
#include <format>
#include <iostream>

DartApp::DartApp(const char* path) : ppool(NULL), nativeLib(0xdeadead), throwStubAddr(0)
{
	auto libInfo = ElfHelper::MapLibAppSo(path);
	lib_base = libInfo.lib;
	vm_snapshot_data = libInfo.vm_snapshot_data;
	vm_snapshot_instructions = libInfo.vm_snapshot_instructions;
	isolate_snapshot_data = libInfo.isolate_snapshot_data;
	isolate_snapshot_instructions = libInfo.isolate_snapshot_instructions;

	isolate = reinterpret_cast<dart::Isolate*>(DartLoader::Load(libInfo));

	heap_base_ = dart::Thread::Current()->heap_base();
	inScope = false;

	DartFnBase::SetLibBase(base());

	dartIntCid = 0;
	dartDoubleCid = 0;
	dartStringCid = 0;
	dartBoolCid = 0;
	dartRecordCid = 0;
	dartListCid = 0;
	dartSetCid = 0;
	dartMapCid = 0;
	dartRunesCid = 0;
	dartFutureCid = 0;
}

DartApp::~DartApp()
{
	ExitScope();
	DartLoader::Unload();

	for (auto lib : libs) {
		delete lib;
	}

	for (auto& stub : stubs) {
		delete stub.second;
	}
}

void DartApp::EnterScope()
{
	if (!inScope) {
		inScope = true;
		Dart_EnterScope();
		isolate->safepoint_handler()->ExitSafepointUsingLock(dart::Thread::Current());

		ppool = reinterpret_cast<dart::ObjectPool*>(dart::VMHandles::AllocateHandle(dart::Thread::Current()->zone()));
		*ppool = isolate->group()->object_store()->global_object_pool();
	}
}

void DartApp::ExitScope()
{
	if (inScope) {
		inScope = false;
		Dart_ExitScope();
		ppool = NULL;
	}
}

DartClass* DartApp::GetClass(intptr_t cid)
{
	if ((size_t)cid > classes.size()) {
		return topClasses.at(dart::ClassTable::IndexFromTopLevelCid(cid));
	}
	return classes.at(cid);
}

DartFnBase* DartApp::GetFunction(uint64_t addr)
{
	auto fn = functions.find(addr);
	if (fn != functions.end()) {
		return fn->second;
	}

	auto stub = stubs.find(addr);
	if (stub != stubs.end()) {
		return stub->second;
	}
	for (auto& [ep_addr, stub] : stubs) {
		if (stub->Address() < addr && addr < stub->AddressEnd()) {
			auto newStub = stub->Split(addr);
			stubs[addr] = newStub;
			return newStub;
		}
	}
	return nullptr;
}

DartLibrary* DartApp::addLibraryClass(const dart::Library& library, const dart::Class& cls)
{
	const auto topCid = library.toplevel_class().untag()->id();
	const auto idx = dart::ClassTable::IndexFromTopLevelCid(topCid);
	auto dartCls = topClasses[idx];
	DartLibrary* dartLib;
	if (dartCls == NULL) {
		dartLib = addLibrary(library);
	}
	else {
		dartLib = const_cast<DartLibrary*>(&dartCls->lib);
	}

	if (!cls.IsTopLevel()) {
		auto dartCls = dartLib->AddClass(cls);

		classes[dartCls->id] = dartCls;
		for (const auto dartFn : dartCls->functions) {
			functions[dartFn->Address()] = dartFn;
		}
	}
	return dartLib;
}

DartLibrary* DartApp::addLibrary(const dart::Library& library)
{
	auto lib = new DartLibrary(library);
	libs.push_back(lib);

	for (const auto dartCls : lib->classes) {
		if (dartCls == lib->topClass)
			topClasses[dart::ClassTable::IndexFromTopLevelCid(dartCls->id)] = dartCls;
		else
			classes[dartCls->id] = dartCls;
		for (const auto dartFn : dartCls->functions) {
			functions[dartFn->Address()] = dartFn;
		}
	}

	return lib;
}

void DartApp::LoadInfo()
{
	auto ig = dart::Isolate::Current()->group();

	loadFromClassTable(ig);

	auto store = ig->object_store();

	loadStubs(store);

	findFunctionInHeap();

	loadFromObjectPool();

	finalizeFunctionsInfo();


}

void DartApp::loadFromClassTable(dart::IsolateGroup* ig)
{
	auto table = ig->class_table();
	const auto num_cids = table->NumCids();
	const auto num_top_cids = table->NumTopLevelCids();
	classes.resize(num_cids);
	topClasses.resize(num_top_cids);
	libs.reserve(num_top_cids);

	auto& library = dart::Library::Handle();
	auto& cls = dart::Class::Handle();


	for (intptr_t i = 0; i < num_top_cids; i++) {
		const auto topCid = dart::ClassTable::CidFromTopLevelIndex(i);
		auto clsPtr = table->At(topCid);
		if (clsPtr == nullptr)
			continue;

		cls = clsPtr;
		library = cls.library();
		addLibrary(library);
	}

	for (intptr_t i = 0; i < num_cids; i++) {
		auto clsPtr = table->At(i);
		if (clsPtr == nullptr) {
			ASSERT(!classes[i]);
			continue;
		}

		if (classes[i] == nullptr) {
			cls = clsPtr;
			library = cls.library();
			if (library.IsNull()) {
				auto dartCls = nativeLib.AddClass(cls);
				classes[i] = dartCls;
			}
			else {
				addLibraryClass(library, cls);
			}
		}

#ifdef HAS_SHARED_CLASS_TABLE
		classes[i]->unboxed_fields_bitmap = ig->shared_class_table()->GetUnboxedFieldsMapAt(i);
#else
		classes[i]->unboxed_fields_bitmap = table->GetUnboxedFieldsMapAt(i);
#endif
	}

	for (auto dartCls : classes) {
		if (dartCls == NULL)
			continue;

		if (dartCls->superCls)
			dartCls->superCls = classes[(intptr_t)dartCls->superCls];

		if (dartCls->name == "int") dartIntCid = dartCls->id;
		else if (dartCls->name == "double") dartDoubleCid = dartCls->id;
		else if (dartCls->name == "String") dartStringCid = dartCls->id;
		else if (dartCls->name == "bool") dartBoolCid = dartCls->id;
		else if (dartCls->name == "Record") dartRecordCid = dartCls->id;
		else if (dartCls->name == "List") dartListCid = dartCls->id;
		else if (dartCls->name == "Set") dartSetCid = dartCls->id;
		else if (dartCls->name == "Map") dartMapCid = dartCls->id;
		else if (dartCls->name == "Runes") dartRunesCid = dartCls->id;
		else if (dartCls->name == "Future") dartFutureCid = dartCls->id;
	}

	typeDb = std::unique_ptr<DartTypeDb>(new DartTypeDb(classes));

	auto zone = dart::Thread::Current()->zone();
	auto& interfaces = dart::Array::Handle(zone);
	auto& type = dart::Type::Handle(zone);
	for (auto dartCls : classes) {
		if (dartCls == nullptr || dartCls->superCls == nullptr)
			continue;

		cls = dartCls->ptr;
		auto dartType = typeDb->FindOrAdd(cls.DeclarationType());
		dartCls->declarationType = dartType;
		ASSERT(dartType->AsType()->Class().Id() == dartCls->Id());
		if (dartCls->num_type_parameters > 0) {
			dartCls->typeVectorName = dartType->Arguments().SubvectorName(0, dartCls->num_type_parameters);
		}
		if (dartCls->superCls->num_type_parameters > 0) {
			dartCls->parentTypeVectorName = dartType->Arguments().SubvectorName(0, dartCls->superCls->num_type_parameters);
		}

		interfaces = cls.interfaces();
		auto interfaces_len = interfaces.Length();
		if (dartCls->is_transformed_mixin) {
			type ^= interfaces.At(--interfaces_len);
			dartCls->mixin = classes[type.type_class_id()];
			ASSERT(dartCls->mixin);
		}
		for (auto i = 0; i < interfaces_len; i++) {
			type ^= interfaces.At(i);
			dartCls->interfaces.push_back(classes[type.type_class_id()]);
		}
	}
}

void DartApp::loadStubs(dart::ObjectStore* store)
{
#ifdef BLUTTER_DART_SINGLE_SNAPSHOT
	(void)store;
	uint64_t ep_addr;
	DartStub* stub;

	throwStubAddr = dart::StubCode::Throw().EntryPoint();

#define DO(name) { \
		const auto& code = dart::StubCode::name(); \
		ep_addr = code.EntryPoint() - base(); \
		if (!stubs.contains(ep_addr)) { \
			stub = new DartStub(code.ptr(), DartStub::name ## Stub, ep_addr, code.Size(), #name); \
			stubs[ep_addr] = stub; \
			auto it = functions.find(ep_addr); \
			if (it != functions.end()) { \
				auto dartFn = it->second; \
				std::erase(dartFn->Class().functions, dartFn); \
				functions.erase(it); \
			} \
		} \
	}
	VM_STUB_CODE_LIST(DO);
#undef DO
#else
	dart::CodePtr ptr;
	auto& code = dart::Code::Handle();
	uint64_t ep_addr;
	DartStub* stub;

#define DO(member, name) \
	ptr = store->member(); \
	code = ptr; \
	ep_addr = code.EntryPoint() - base(); \
	stub = new DartStub(ptr, DartStub::name ## Stub, ep_addr, code.Size(), #name); \
	ASSERT(!stubs.contains(ep_addr)); \
	stubs[ep_addr] = stub;
	OBJECT_STORE_STUB_CODE_LIST(DO);
#ifndef NO_METHOD_EXTRACTOR_STUB
	DO(build_nongeneric_method_extractor_code, BuildNonGenericMethodExtractor);
	DO(build_generic_method_extractor_code, BuildGenericMethodExtractor);
#endif
#undef DO

	code = store->throw_stub();
	throwStubAddr = code.EntryPoint();

	ASSERT(dart::StubCode::HasBeenInitialized());
#define DO(name) {\
		const auto& code = dart::StubCode::name(); \
		ep_addr = code.EntryPoint() - base(); \
		if (stubs.contains(ep_addr)) { \
			ASSERT(stubs[ep_addr]->Name() == #name); \
		} \
		else { \
			stub = new DartStub(code.ptr(), DartStub::name ## VMStub, ep_addr, code.Size(), #name); \
			stubs[ep_addr] = stub; \
			auto it = functions.find(ep_addr); \
			if (it != functions.end()) { \
				auto dartFn = it->second; \
				std::erase(dartFn->Class().functions, dartFn); \
				functions.erase(it); \
			} \
		} \
	}
	VM_STUB_CODE_LIST(DO);
#undef DO
#endif
}

DartFunction* DartApp::addFunctionNoCheck(const dart::Function& func)
{
	const auto cls_ptr = func.Owner();
	const auto cid = cls_ptr.untag()->id();
	DartClass* cls;
	if (dart::ClassTable::IsTopLevelCid(cid)) {
		const auto idx = dart::ClassTable::IndexFromTopLevelCid(cid);
		cls = topClasses[idx];
		if (cls == NULL) {
			const auto& clsHandle = dart::Class::Handle(cls_ptr);
			const auto& library = dart::Library::Handle(clsHandle.library());
			cls = addLibrary(library)->topClass;
		}
	}
	else {
		cls = classes[cid];
		if (cls == NULL) {
			auto msg = std::format("found invalid class id: {}", cid);
			throw std::runtime_error(msg);
		}
	}
	return cls->AddFunction(func.ptr());
}

void DartApp::addFunction(uintptr_t ep_addr, const dart::Function& func)
{
	if (!functions.contains(ep_addr)) {
		auto dartFn = addFunctionNoCheck(func);
		functions[dartFn->Address()] = dartFn;
	}
}

class HeapCodeVisitor : public dart::ObjectVisitor {
public:
	explicit HeapCodeVisitor(std::vector<dart::CodePtr>& codePtrs) : codePtrs(codePtrs) {}
	virtual ~HeapCodeVisitor() {}

	virtual void VisitObject(dart::ObjectPtr obj) {
		if (obj->IsCode())
			codePtrs.push_back(dart::Code::RawCast(obj));
	}

private:
	std::vector<dart::CodePtr>& codePtrs;
};

void DartApp::findFunctionInHeap()
{
	std::vector<dart::CodePtr> codePtrs;
	dart::HeapIterationScope heap_iteration_scope(dart::Thread::Current());
	HeapCodeVisitor visitor(codePtrs);
	heap_iteration_scope.IterateOldObjects(&visitor);

	auto zone = dart::Thread::Current()->zone();
	auto& code = dart::Code::Handle(zone);
	auto& obj = dart::Object::Handle(zone);

	for (dart::CodePtr code_ptr : codePtrs) {
		code = code_ptr;
		const auto entry_point = code.EntryPoint();
		const auto ep_offset = entry_point - base();

		auto owner = code.owner();
		if ((intptr_t)owner == (intptr_t)dart::Object::null()) {
			ASSERT(code.IsStubCode());
			if (!stubs.contains(ep_offset)) {
				auto stub_size = code.Size();
				DartStub* candidateStub = nullptr;
				std::vector<DartStub*> candidateStubs;
				for (auto const& [stubEp, stub] : stubs) {
					if (stub->kind < DartStub::SharedStub && stub->Size() == (int64_t)stub_size) {
						if (memcmp((void*)stub->MemAddress(), (void*)entry_point, stub_size) == 0) {
							candidateStub = stub;
							break;
						}
						candidateStubs.push_back(stub);
					}
				}
				if (candidateStub == nullptr) {
					RELEASE_ASSERT(!candidateStubs.empty());
					if (candidateStubs.size() == 1) {
						candidateStub = candidateStubs[0];
					}
					else {
						uint32_t maxMatch = 0;
						for (auto stub : candidateStubs) {
							auto tmpCode = (uint8_t*)stub->MemAddress();
							uint32_t cnt = 0;
							for (size_t i = 0; i < stub_size; i++) {
								if (((uint8_t*)entry_point)[i] == tmpCode[i])
									cnt++;
							}
							if (cnt > maxMatch) {
								candidateStub = stub;
								maxMatch = cnt;
							}
						}
					}
				}
				ASSERT(candidateStub);
				stubs[ep_offset] = new DartStub(code_ptr, candidateStub->kind, ep_offset, stub_size, candidateStub->Name());
			}
			continue;
		}

		obj = owner;
		if (obj.IsClass()) {
			if (stubs.contains(ep_offset)) {
				throw std::runtime_error("not allocate stub for user class");
			}
			const auto cid = (uint32_t)dart::Class::Cast(obj).id();
			auto astub = new DartAllocateStub(code_ptr, ep_offset, code.Size(), cid, classes[cid]->name);
			stubs[ep_offset] = astub;
		}
		else if (obj.IsAbstractType()) {
			if (!obj.IsType()) {
#ifdef HAS_RECORD_TYPE
				if (!obj.IsRecordType()) {
					std::cerr << std::format("TestType is not for Type or RecordType, but for {}\n", classes[obj.GetClassId()]->Name());
				}
#else
				std::cerr << std::format("TestType is not for Type, but for {}\n", classes[obj.GetClassId()]->Name());
#endif
			}
			if (stubs.contains(ep_offset))
				throw std::runtime_error("duplitcate stub entry point");
			auto dartType = typeDb->FindOrAdd(dart::AbstractType::Cast(obj).ptr());
			auto tstub = new DartTypeStub(code_ptr, ep_offset, code.Size(), *dartType, dartType->ToString());
			stubs[ep_offset] = tstub;
		}
		else if (obj.IsFunction()) {
			ASSERT(code.is_optimized());
			addFunction(ep_offset, dart::Function::Cast(obj));
		}
		else if (obj.IsSmi()) {
			auto ownerClassId = code.OwnerClassId();
			ASSERT(ownerClassId == dart::kFunctionCid);
			if (!functions.contains(ep_offset)) {
				if (!nativeLib.topClass) {
					nativeLib.topClass = new DartClass(nativeLib);
				}
				auto dartFn = nativeLib.topClass->AddFunction(code);
				functions[dartFn->Address()] = dartFn;
			}
		}
		else {
			auto msg = std::format("[!] unknown code at: {:#x}, {}\n", ep_offset, obj.ToCString());
			std::cout << msg;
			std::cout << "  !!! Unhandle case. Please report with your APK\n";
		}
	}
}

void DartApp::finalizeFunctionsInfo()
{
	auto& parentFn = dart::Function::Handle();
	std::unordered_map<uint64_t, DartFunction*> pending_functions;
	for (auto& [_, dartFn] : functions) {
		if (dartFn->parent) {
			parentFn = dart::FunctionPtr((intptr_t)dartFn->parent);
			const auto ep_addr = parentFn.entry_point() - base();
			if (stubs.contains(ep_addr)) {
				dartFn->parent = nullptr;
			}
			else if (functions.contains(ep_addr)) {
				dartFn->parent = functions[ep_addr];
			}
			else if (pending_functions.contains(ep_addr)) {
				dartFn->parent = pending_functions[ep_addr];
			}
			else {
				auto newDartFn = addFunctionNoCheck(parentFn);
				pending_functions[ep_addr] = newDartFn;
				dartFn->parent = newDartFn;
			}
		}

	}

	std::unordered_map<uint64_t, DartFunction*> new_functions;
	while (!pending_functions.empty()) {
		for (auto& [dartFn_ep, dartFn] : pending_functions) {
			if (dartFn->parent) {
				parentFn = dart::FunctionPtr((intptr_t)dartFn->parent);
				const auto ep_addr = parentFn.entry_point() - base();
				if (stubs.contains(ep_addr)) {
					dartFn->parent = nullptr;
				}
				else if (functions.contains(ep_addr)) {
					dartFn->parent = functions[ep_addr];
				}
				else if (pending_functions.contains(ep_addr)) {
					dartFn->parent = pending_functions[ep_addr];
				}
				else if (new_functions.contains(ep_addr)) {
					dartFn->parent = new_functions[ep_addr];
				}
				else {
					auto newDartFn = addFunctionNoCheck(parentFn);
					new_functions[ep_addr] = newDartFn;
					dartFn->parent = newDartFn;
				}
			}
			functions[dartFn_ep] = dartFn;
		}
		pending_functions.clear();
		pending_functions = std::move(new_functions);
		new_functions.clear();
	}

	for (auto& [_, dartFn] : functions) {
		if (dartFn->parent == dartFn) {
			dartFn->parent = nullptr;
		}
	}

	auto& func = dart::Function::Handle();
	for (auto& [_, dartFn] : functions) {
		func = dartFn->ptr;
		const auto sigPtr = func.signature();
		if (!sigPtr.IsHeapObject())
			continue;
		const auto& sig = dart::FunctionType::Handle(sigPtr);
		if (!sig.IsNull()) {
			dartFn->Signature().returnType = TypeDb()->FindOrAdd(sig.result_type());

			const auto& type_params = dart::TypeParameters::Handle(sig.type_parameters());
			if (!type_params.IsNull()) {
			}

			const intptr_t num_params = sig.NumParameters();
			const intptr_t num_fixed_params = sig.num_fixed_parameters();
			const intptr_t num_opt_pos_params = sig.NumOptionalPositionalParameters();
			const intptr_t num_opt_named_params = sig.NumOptionalNamedParameters();
			const intptr_t num_opt_params = num_opt_pos_params + num_opt_named_params;

			auto& dname = dart::String::Handle();
			for (intptr_t i = 0; i < num_params; i++) {
				auto dtype = TypeDb()->FindOrAdd(sig.ParameterTypeAt(i));
				auto isRequired = false;
				std::string name;

				if (num_opt_named_params > 0 && i >= num_fixed_params) {
					if (sig.IsRequiredAt(i))
						isRequired = true;
					dname = sig.ParameterNameAt(i);
					name = dname.ToCString();
				}

				dartFn->Signature().params.push_back(FnParam{ dtype, std::move(name), isRequired });
			}
		}
	}
}

void DartApp::walkObject(dart::Object& obj)
{
	auto cid = obj.GetClassId();
	if (cid < dart::kNumPredefinedCids) {
		if (obj.IsArray()) {
			const auto& arr = dart::Array::Cast(obj);
			const auto arr_len = arr.Length();
			if (arr_len > 0) {
				auto arrPtr = dart::Array::DataOf(arr.ptr());
				for (intptr_t i = 0; i < arr_len; i++) {
					if (arrPtr->IsHeapObject()) {
						obj = arrPtr->Decompress(heap_base());
						walkObject(obj);
					}
					arrPtr++;
				}
			}
		}
		else if (cid == dart::kConstMapCid || cid == dart::kMapCid) {
			auto& map = dart::Map::Cast(obj);
			dart::Map::Iterator iter(map);
			auto& obj2 = dart::Object::Handle();
			while (iter.MoveNext()) {
				obj2 = iter.CurrentKey();
				walkObject(obj2);
				obj2 = iter.CurrentValue();
				walkObject(obj2);
			}
		}
		else if (cid == dart::kConstSetCid || cid == dart::kSetCid) {
			auto& set = dart::Set::Cast(obj);
			dart::Set::Iterator iter(set);
			auto& obj2 = dart::Object::Handle();
			while (iter.MoveNext()) {
				obj2 = iter.CurrentKey();
				walkObject(obj2);
			}
		}
		else if (obj.IsTypeArguments()) {
			typeDb->FindOrAdd(dart::TypeArguments::RawCast(obj.ptr()));
		}
		else if (obj.IsType()) {
			typeDb->FindOrAdd(dart::Type::RawCast(obj.ptr()));
		}
		else if (obj.IsTypeParameter()) {
			typeDb->FindOrAdd(dart::TypeParameter::RawCast(obj.ptr()));
		}
		else if (obj.IsFunctionType()) {
			typeDb->FindOrAdd(dart::FunctionType::RawCast(obj.ptr()));
		}
		else if (obj.IsFunction()) {
			const auto& func = dart::Function::Cast(obj);
			const auto ep_addr = func.entry_point() - base();
			addFunction(ep_addr, func);
		}
		else if (obj.IsClosure()) {
			const auto& closure = dart::Closure::Cast(obj);
			const auto ep_addr = closure.entry_point() - base();
			const auto& func = dart::Function::Handle(closure.function());
			addFunction(ep_addr, func);
		}
		return;
	}

	ASSERT(obj.IsInstance());

	auto dartCls = classes[cid];
	ASSERT(dartCls);
	typeDb->FindOrAdd(*dartCls, dart::Instance::Cast(obj));

	const auto bitmap = dartCls->unboxed_fields_bitmap;
	auto offset = dart::Instance::NextFieldOffset();
	const auto ptr = dart::UntaggedObject::ToAddr(obj.ptr());
	while (offset < dartCls->size) {
		if (bitmap.Get(offset / dart::kCompressedWordSize)) {
			if (dart::kCompressedWordSize == 4) {
				RELEASE_ASSERT(bitmap.Get((offset + dart::kCompressedWordSize) / dart::kCompressedWordSize));
			}
			auto p = reinterpret_cast<uint64_t*>(ptr + offset);
			if (*p <= 0x1000000000000000 || *p >= 0xffffffffffff0000) {
				dartCls->AddField(offset, typeDb->Get(dart::kMintCid));
			}
			else {
				dartCls->AddField(offset, typeDb->Get(dart::kDoubleCid));
			}
			offset += dart::kCompressedWordSize * 2;
		}
		else {
			auto p = reinterpret_cast<dart::CompressedObjectPtr*>(ptr + offset);
			if (!p->IsHeapObject()) {
				dartCls->AddField(offset, typeDb->Get(dart::kMintCid));
			}
			else {
				const auto objPtr2 = p->Decompress(heap_base());
				if (objPtr2.GetClassId() != dart::kNullCid) {
					if (offset == dartCls->TypeArgumentsOffset()) {
						ASSERT(objPtr2.GetClassId() == dart::kTypeArgumentsCid);
						typeDb->FindOrAdd(dart::TypeArguments::RawCast(objPtr2));
					}
					else {
						const auto fieldCid = objPtr2.GetClassId();
						const auto fieldCls = classes[fieldCid];
						if (fieldCls) {
							obj = objPtr2;
							dartCls->AddField(offset, typeDb->FindOrAdd(*fieldCls, dart::Instance::Cast(obj)));
							walkObject(obj);
						}
						else {
						}
					}
				}
			}
			offset += dart::kCompressedWordSize;
		}
	}

}

void DartApp::loadFromObjectPool()
{
	const auto& pool = GetObjectPool();
	intptr_t num = pool.Length();

	auto& obj = dart::Object::Handle();

	for (intptr_t i = 0; i < num; i++) {
		const auto objType = pool.TypeAt(i);
		if (objType == dart::ObjectPool::EntryType::kTaggedObject) {
			obj = pool.ObjectAt(i);
			if (obj.IsField()) {
				const auto& field = dart::Field::Cast(obj);
				auto dartCls = GetClass(field.Owner().untag()->id());
				auto dartField = dartCls->AddField(field.ptr());
				if (dartField->IsStatic()) {
					ASSERT(!staticFields.contains(dartField->Offset()));
					staticFields[dartField->Offset()] = dartField;
				}
			}
			walkObject(obj);
		}
		else if (objType == dart::ObjectPool::EntryType::kImmediate) {
		}
		else if (objType == dart::ObjectPool::EntryType::kNativeFunction) {
		}
		else {
			throw std::runtime_error("Unknown Object Pool entry type");
		}
	}
}

