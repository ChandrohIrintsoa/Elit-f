#pragma once

class DartClass;
class DartType;
#ifdef HAS_RECORD_TYPE
class DartRecordType;
#endif
#ifdef HAS_TYPE_REF
class DartTypeRef;
#endif
class DartTypeParameter;
class DartFunctionType;
class DartTypeDb;

class DartAbstractType {
public:
	enum Kind : uint8_t {
		TypeParam = 1,
		Type,
#ifdef HAS_RECORD_TYPE
		RecordType,
#endif
#ifdef HAS_TYPE_REF
		TypeRef,
#endif
		FunctionType,
	};

	explicit DartAbstractType(Kind kind, bool nullable) : kind(kind), nullable(nullable) {}
	DartAbstractType() = delete;

	bool IsNullable() const { return nullable; }

	virtual std::string ToString() const = 0;

	bool IsType() const { return kind == Kind::Type; }
	bool IsTypeParameter() const { return kind == Kind::TypeParam; }

	DartType* AsType() {
		ASSERT(kind == Type);
		return reinterpret_cast<DartType*>(this);
	}
#ifdef HAS_RECORD_TYPE
	DartRecordType* AsRecordType() {
		ASSERT(kind == RecordType);
		return reinterpret_cast<DartRecordType*>(this);
	}
#endif
#ifdef HAS_TYPE_REF
	DartTypeRef* AsTypeRef() {
		ASSERT(kind == TypeRef);
		return reinterpret_cast<DartTypeRef*>(this);
	}
#endif
	DartTypeParameter* AsTypeParameter() {
		ASSERT(kind == TypeParam);
		return reinterpret_cast<DartTypeParameter*>(this);
	}
	DartFunctionType* AsFunctionType() {
		ASSERT(kind == FunctionType);
		return reinterpret_cast<DartFunctionType*>(this);
	}

protected:
	Kind kind;
	bool nullable;
};

class DartTypeArguments {
public:
	explicit DartTypeArguments(std::vector<DartAbstractType*> args) : args(std::move(args)) {}
	explicit DartTypeArguments() {}

	std::string SubvectorName(int from_index, int len) const;
	std::string ToString() const { return args.empty() ? std::string() : SubvectorName(0, (int)args.size()); }
	size_t Length() const { return args.size(); }

	static const DartTypeArguments Null;

protected:
	std::vector<DartAbstractType*> args;

	friend class DartTypeDb;
};

class DartType : public DartAbstractType
{
public:
	DartType() = delete;
	const DartTypeArguments& Arguments() const { return *args; }
	const DartClass& Class() const { return cls; }

	virtual std::string ToString() const;
	std::string ToString(bool showTypeArgs) const;

protected:
	explicit DartType(bool nullable, DartClass& cls, const DartTypeArguments* args) : DartAbstractType(Kind::Type, nullable), cls(cls), args(args) {}

	DartClass& cls;
	const DartTypeArguments* args;

	friend class DartTypeDb;
	friend class DartApp;
};

#ifdef HAS_RECORD_TYPE
class DartRecordType : public DartAbstractType
{
public:
	DartRecordType() = delete;

	virtual std::string ToString() const;

protected:
	explicit DartRecordType(bool nullable, std::vector<std::string> fieldNames) : DartAbstractType(Kind::RecordType, nullable), fieldNames(std::move(fieldNames)) {}

	std::vector<DartAbstractType*> fieldTypes;
	std::vector<std::string> fieldNames;

	friend class DartTypeDb;
};
#endif

#ifdef HAS_TYPE_REF
class DartTypeRef : public DartAbstractType
{
public:
	DartTypeRef() = delete;

	virtual std::string ToString() const;

protected:
	explicit DartTypeRef(DartType& type) : DartAbstractType(Kind::TypeRef, false), type(type) {}

	DartType& type;

	friend class DartTypeDb;
};
#endif

class DartTypeParameter : public DartAbstractType {
public:
	DartTypeParameter() = delete;

	virtual std::string ToString() const;

protected:
	explicit DartTypeParameter(bool nullable, uint16_t base, uint16_t index, bool isClassTypeParam)
		: DartAbstractType(Kind::TypeParam, nullable), base(base), index(index), isClassTypeParam(isClassTypeParam), bound(nullptr) {}

	uint16_t base;
	uint16_t index;
	bool isClassTypeParam;
	DartAbstractType* bound;

	friend class DartTypeDb;
};

class DartFunctionType : public DartAbstractType {
public:
	DartFunctionType() = delete;

	virtual std::string ToString() const;

	struct Parameter {
		Parameter(std::string name, DartAbstractType* type) : name(std::move(name)), type(type) {}

		std::string name;
		DartAbstractType* type;
	};
	struct OptionalParameter : public Parameter {
		OptionalParameter(std::string name, DartAbstractType* type, void* defaultValue) : Parameter(std::move(name), type), defaultValue(defaultValue) {}

		void* defaultValue;
	};

protected:
	explicit DartFunctionType(bool nullable, bool hasImplicitParam, bool hasNamedParam, std::vector<DartTypeParameter*> typeParams)
		: DartAbstractType(Kind::FunctionType, nullable), hasImplicitParam(hasImplicitParam), hasNamedParam(hasNamedParam), resultType(nullptr), typeParams(std::move(typeParams)) {}

	bool hasImplicitParam;
	bool hasNamedParam;

	std::vector<DartTypeParameter*> typeParams;
	DartAbstractType *resultType;

	std::vector<Parameter> params;
	std::vector<OptionalParameter> optionalParams;

	friend class DartTypeDb;
};

class DartTypeDb {
public:

	DartType* Get(uint32_t cid);

	DartType* FindOrAdd(dart::TypePtr typePtr);
#ifdef HAS_RECORD_TYPE
	DartRecordType* FindOrAdd(dart::RecordTypePtr recordTypePtr);
#endif
	DartTypeParameter* FindOrAdd(dart::TypeParameterPtr typeParamPtr);
	DartFunctionType* FindOrAdd(dart::FunctionTypePtr fnTypePtr);
	DartAbstractType* FindOrAdd(dart::AbstractTypePtr abTypePtr);

	const DartTypeArguments* FindOrAdd(dart::TypeArgumentsPtr typeArgsPtr);

	DartType* FindOrAdd(DartClass& dartCls, const dart::TypeArgumentsPtr typeArgsPtr);
	DartType* FindOrAdd(DartClass& dartCls, const dart::Instance& inst);
	DartType* FindOrAdd(uint32_t cid, const DartTypeArguments* typeArgs);

protected:
	DartTypeDb(std::vector<DartClass*>& classes) : classes(classes) { typesByCid.resize(classes.size()); }

	std::unordered_map<intptr_t, DartAbstractType*> typesMap;
	std::vector<std::vector<DartType*>> typesByCid;

	std::unordered_map<intptr_t, DartTypeArguments*> typeArgsMap;

	std::vector<DartClass*>& classes;

	friend class DartApp;
};
