#pragma once
#include "DartClass.h"
#include "DartStub.h"
#include "Util.h"
#include "Disassembler.h"

struct VarStorage {
	enum Kind : int32_t {
		Expression = 0,
		Register,
		Local,
		Argument,
		Static,
		Pool,
		Thread,
		InInstruction,
		Immediate,
		SmallImm,
		Call,
		Field,
		Uninit,
	};
	VarStorage(A64::Register reg) : kind{ Register }, reg{ reg } {}
	VarStorage(Kind kind) : kind{ kind }, offset{ 0 } {}
	VarStorage(Kind kind, int val) : kind{ kind }, offset{ val } {}

	static VarStorage NewExpression() { return VarStorage(Expression); }
	static VarStorage NewRegister(A64::Register reg) { return VarStorage(reg); }
	static VarStorage NewLocal(int offset) { return VarStorage(Local, offset); }
	static VarStorage NewArgument(int idx) { return VarStorage(Argument, idx); }
	static VarStorage NewStatic(int offset) { return VarStorage(Static, offset); }
	static VarStorage NewPool(int offset) { return VarStorage(Pool, offset); }
	static VarStorage NewThread(int offset) { return VarStorage(Thread, offset); }
	static VarStorage NewImmediate() { return VarStorage(Immediate); }
	static VarStorage NewSmallImm(int val) { return VarStorage(SmallImm, val); }
	static VarStorage NewCall() { return VarStorage(Call); }
	static VarStorage NewUninit() { return VarStorage(Uninit); }

	bool operator==(A64::Register reg) const { return kind == Register && reg == this->reg; }
	bool IsImmediate() const { return kind == Immediate; }
	bool IsPredefinedValue() const { return kind == Immediate || kind == Pool; }

	std::string Name();

	Kind kind;
	union {
		A64::Register reg;
		int offset;
		int idx;
	};
};

using ValueType = int32_t;

struct VarInteger;
struct VarParam;
struct VarValue {
	enum CustomTypeId : int32_t {
		Expression = -1000,
		TaggedCid,
		NativeInt,
		NativeDouble,
		Parameter,
		ArgsDesc,
		CurrNumNameParam,
	};

	VarValue(ValueType typeId, bool hasValue = false) : typeId(typeId), hasValue(hasValue) {}
	virtual ~VarValue() {}
	virtual std::string ToString() { return "unknown"; }
	bool HasValue() const { return hasValue; }
	virtual ValueType TypeId() { return typeId; }
	ValueType RawTypeId() const { return typeId; }

	void SetIntType(ValueType tid);
	void SetSmiIfInt();
	VarInteger* AsInteger() {
		ASSERT(RawTypeId() == dart::kIntegerCid);
		return reinterpret_cast<VarInteger*>(this);
	}
	VarParam* AsParam() {
		ASSERT(typeId == Parameter);
		return reinterpret_cast<VarParam*>(this);
	}

	ValueType typeId;
	bool hasValue;
};

struct VarNull : public VarValue {
	explicit VarNull() : VarValue(dart::kNullCid, true) {}
	virtual std::string ToString() { return "Null"; }
};

struct VarBoolean : public VarValue {
	explicit VarBoolean(bool val) : VarValue(dart::kBoolCid, true), val(val) {}
	explicit VarBoolean() : VarValue(dart::kBoolCid, false), val(false) {}
	virtual std::string ToString() { return val ? "true" : "false"; }

	bool val;
};

struct VarInteger : public VarValue {
	explicit VarInteger(int64_t val, ValueType intTypeId = dart::kIntegerCid) : VarValue(dart::kIntegerCid, true), intTypeId(intTypeId), val(val) {}
	explicit VarInteger(ValueType intTypeId = dart::kIntegerCid) : VarValue(dart::kIntegerCid, false), intTypeId(intTypeId), val(0) {}
	virtual std::string ToString() { return std::to_string(Value()); }
	int64_t Value() const { return (intTypeId == dart::kSmiCid) ? val >> dart::kSmiTagSize : val; }

	ValueType intTypeId;
	int64_t val;
};

struct VarDouble : public VarValue {
	explicit VarDouble(double val, ValueType doubleTypeId = dart::kDoubleCid) : VarValue(dart::kDoubleCid, true), doubleTypeId(doubleTypeId), val(val) {}
	explicit VarDouble(ValueType doubleTypeId = dart::kDoubleCid) : VarValue(dart::kDoubleCid, false), doubleTypeId(doubleTypeId), val(0.0) {}
	virtual std::string ToString() { return std::to_string(val); }

	ValueType doubleTypeId;
	double val;
};

struct VarString : public VarValue {
	explicit VarString(std::string str) : VarValue(dart::kStringCid, true), str(std::move(str)) {}
	explicit VarString() : VarValue(dart::kStringCid, false) {}
	virtual std::string ToString() { return Util::UnescapeWithQuote(str.c_str()); }

	std::string str;
};

struct VarFunctionCode : public VarValue {
	explicit VarFunctionCode(DartFnBase& fn) : VarValue(dart::kFunctionCid, true), fn(fn) {}
	virtual std::string ToString() { return fn.FullName(); }

	DartFnBase& fn;
};

struct VarField : public VarValue {
	explicit VarField(DartField& field) : VarValue(dart::kFieldCid, true), field(field) {}
	virtual std::string ToString() { return field.Name(); }

	DartField& field;
};

struct VarExpression : public VarValue {
	explicit VarExpression(std::string txt) : VarValue(Expression, false), txt(std::move(txt)), cid(dart::kIllegalCid) {}
	explicit VarExpression(std::string txt, ValueType cid) : VarValue(Expression, false), txt(std::move(txt)), cid(cid) {}
	virtual std::string ToString() { return txt; }
	void SetText(std::string txt) { this->txt = std::move(txt); }
	virtual ValueType TypeId() { return cid; }
	void SetType(ValueType cid) { this->cid = cid; }

	std::string txt;
	ValueType cid;
};

struct VarArray : public VarValue {
	explicit VarArray(dart::ArrayPtr ptr) : VarValue(dart::kArrayCid, true), ptr(ptr), eleType(nullptr), length(-1) {}
	explicit VarArray(DartAbstractType* eleType, int length = -1) : VarValue(dart::kArrayCid, false), ptr(dart::Object::null()), eleType(eleType), length(length) {}
	explicit VarArray() : VarValue(dart::kArrayCid, false), ptr(dart::Object::null()), eleType(nullptr), length(-1) {}
	virtual std::string ToString();
	int64_t DataOffset() {
		return dart::Array::data_offset();
	}
	int ElementSize() {
		return dart::kCompressedWordSize;
	}
	bool IsElementTypeInt() {
		return eleType && eleType->AsType()->Class().Name() == "int";
	}

	dart::ArrayPtr ptr;
	DartAbstractType* eleType;
	int length;
};

struct VarGrowableArray : public VarValue {
	explicit VarGrowableArray(DartAbstractType* eleType) : VarValue(dart::kGrowableObjectArrayCid, false), eleType(eleType) {}
	explicit VarGrowableArray() : VarValue(dart::kGrowableObjectArrayCid, false), eleType(nullptr) {}
	virtual std::string ToString() { return "GrowableArray"; }

	int ElementSize() {
		return dart::kCompressedWordSize;
	}
	bool IsElementTypeInt() {
		return eleType && eleType->AsType()->Class().Name() == "int";
	}

	int64_t LengthOffset() {
		return dart::GrowableObjectArray::length_offset();
	}

	int64_t DataOffset() {
		return dart::GrowableObjectArray::data_offset();
	}

	DartAbstractType* eleType;
};

struct VarUnlinkedCall : public VarValue {
	explicit VarUnlinkedCall(DartStub& stub) : VarValue(dart::kUnlinkedCallCid, true), stub(stub) {}
	virtual std::string ToString() { return std::format("UnlinkedCall_{:#x}", stub.Address()); }

	DartStub& stub;
};

struct VarInstance : public VarValue {
	explicit VarInstance(DartClass* cls) : VarValue(dart::kInstanceCid, true), cls(cls) {}
	explicit VarInstance() : VarValue(dart::kInstanceCid, false), cls(nullptr) {}
	virtual ValueType TypeId() { return cls->Id(); }
	virtual std::string ToString() { return std::format("Instance_{}", cls->Name()); }

	DartClass* cls;
};

struct VarType : public VarValue {
	explicit VarType(const DartType& type) : VarValue(dart::kTypeCid, true), type(type) {}
	virtual std::string ToString() { return type.ToString(); }

	const DartType& type;
};

#ifdef HAS_RECORD_TYPE
struct VarRecordType : public VarValue {
	explicit VarRecordType(const DartRecordType& recordType) : VarValue(dart::kRecordTypeCid, true), recordType(recordType) {}
	virtual std::string ToString() { return recordType.ToString(); }

	const DartRecordType& recordType;
};
#endif

struct VarTypeParameter : public VarValue {
	explicit VarTypeParameter(const DartTypeParameter& typeParam) : VarValue(dart::kTypeParameterCid, true), typeParam(typeParam) {}
	virtual std::string ToString() { return typeParam.ToString(); }

	const DartTypeParameter& typeParam;
};

struct VarFunctionType : public VarValue {
	explicit VarFunctionType(const DartFunctionType& fnType) : VarValue(dart::kFunctionTypeCid, true), fnType(fnType) {}
	virtual std::string ToString() { return fnType.ToString(); }

	const DartFunctionType& fnType;
};

struct VarTypeArgument : public VarValue {
	explicit VarTypeArgument(const DartTypeArguments& typeArgs) : VarValue(dart::kTypeArgumentsCid, true), typeArgs(typeArgs) {}
	virtual std::string ToString() { return typeArgs.ToString(); }

	const DartTypeArguments& typeArgs;
};

struct VarSentinel : public VarValue {
	explicit VarSentinel() : VarValue(dart::kSentinelCid, false) {}
	virtual std::string ToString() { return "Sentinel"; }
};

struct VarSubtypeTestCache : public VarValue {
	explicit VarSubtypeTestCache() : VarValue(dart::kSubtypeTestCacheCid, false) {}
	virtual std::string ToString() { return "SubtypeTestCache"; }
};

struct VarCid : public VarValue {
	explicit VarCid(int cid, bool isSmi) : VarValue(dart::kClassCid, cid != 0), isSmi(isSmi), cid(cid) {}
	explicit VarCid() : VarValue(dart::kClassCid, false), isSmi(false), cid(0) {}
	virtual std::string ToString() { return isSmi ? std::format("TaggedCid_{}", cid >> dart::kSmiTagSize) : std::format("cid_{}", cid); }

	bool isSmi;
	int cid;
};

struct VarParam : public VarValue {
	explicit VarParam(int idx) : VarValue(Parameter, false), idx(idx) {}
	int idx;
};

struct VarItem {
	explicit VarItem() : storage(VarStorage::Uninit) {}
	explicit VarItem(VarStorage storage) : storage(storage) {}
	explicit VarItem(VarStorage storage, std::unique_ptr<VarValue> val) : storage(storage), val(std::move(val)) {}
	explicit VarItem(VarStorage storage, VarValue* val) : storage(storage), val(std::unique_ptr<VarValue>(val)) {}
	explicit VarItem(A64::Register reg, std::unique_ptr<VarValue> val) : storage(VarStorage(reg)), val(std::move(val)) {}
	explicit VarItem(A64::Register reg, VarValue* val) : storage(VarStorage(reg)), val(std::unique_ptr<VarValue>(val)) {}

	VarStorage Storage() const { return storage; }
	std::string StorageName() { return storage.Name(); }

	template <typename T, typename = std::enable_if<std::is_base_of<VarValue, T>::value>>
	T* Get() const { return reinterpret_cast<T*>(val.get()); }
	VarValue* Value() const { return val.get(); }
	std::unique_ptr<VarValue> TakeValue() { return std::move(val); }
	std::string ValueString() const { return val ? val->ToString() : "BUG_NO_ASSIGN_VALUE"; }
	ValueType ValueTypeId() const { return val->RawTypeId(); }
	VarItem* MoveTo(VarStorage storage) { return new VarItem(storage, std::move(val)); }
	VarItem* MoveTo(A64::Register reg) { return new VarItem(VarStorage::NewRegister(reg), std::move(val)); }

	std::string Name();
	std::string CallArgName();

	VarStorage storage;
	std::unique_ptr<VarValue> val;
};
