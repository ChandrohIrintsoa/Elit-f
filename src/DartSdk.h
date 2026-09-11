#pragma once
#include <string>
#include <format>
#include <vector>
#include <algorithm>
#include <unordered_map>
#include <iostream>

#if defined(_MSC_VER)
#define PRAGMA_WARNING(...) __pragma(warning(__VA_ARGS__))
#else
#define PRAGMA_WARNING(...)
#endif

PRAGMA_WARNING(push, 0)
#include <include/dart_api.h>
#include <vm/dart_entry.h>
#include <vm/dart.h>
#include <vm/object.h>
#include <vm/object_store.h>
#include <vm/native_symbol.h>
#include <vm/zone_text_buffer.h>
#include <vm/tagged_pointer.h>
#include <vm/compiler/runtime_api.h>
#include <vm/compiler/runtime_offsets_extracted.h>
PRAGMA_WARNING(pop)

#ifdef OLD_MAP_SET_NAME
namespace dart {
using Map = LinkedHashMap;
using Set = LinkedHashSet;
#ifdef OLD_MAP_NO_IMMUTABLE
using ConstMap = LinkedHashMap;
using ConstSet = LinkedHashSet;
#else
using ConstMap = ImmutableLinkedHashMap;
using ConstSet = ImmutableLinkedHashSet;
#endif

enum ClassIdX : intptr_t {
	kMapCid = kLinkedHashMapCid,
	kSetCid = kLinkedHashSetCid,
#ifdef OLD_MAP_NO_IMMUTABLE
	kConstMapCid = kLinkedHashMapCid,
	kConstSetCid = kLinkedHashSetCid,
#else
	kConstMapCid = kImmutableLinkedHashMapCid,
	kConstSetCid = kImmutableLinkedHashSetCid,
#endif
};
}
#endif

#ifdef NO_LAST_INTERNAL_ONLY_CID
namespace dart {
constexpr intptr_t kLastInternalOnlyCid = kUnwindErrorCid;
}
#endif

#if defined SEMIDBG && !defined DEBUG
#undef ASSERT
#define ASSERT(cond) RELEASE_ASSERT(cond)
#endif

#ifdef CACHED_FUNCTION_ENTRY_POINTS_LIST
#define HAS_INIT_ASYNC 1
#endif

#ifdef NO_INIT_LATE_STATIC_FIELD
#define InitLateStaticFieldStub InitStaticFieldStub
#define InitLateFinalStaticFieldStub InitStaticFieldStub
#endif

#ifdef UNIFORM_INTEGER_ACCESS
#define MintValue(obj) obj.Value()
constexpr intptr_t kUntaggedObjectClassIdTagPos = dart::UntaggedObject::ClassIdTag::shift();
#define DartGetRecordType(record) record.GetRecordType(dart::TypeVisibility::kUserVisibleType)
#else
#define MintValue(obj) obj.value()
constexpr intptr_t kUntaggedObjectClassIdTagPos = dart::UntaggedObject::kClassIdTagPos;
#define DartGetRecordType(record) record.GetRecordType()
#endif
