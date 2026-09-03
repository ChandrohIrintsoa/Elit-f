#include "DartSdk.h"
#include "DartClass.h"
#include "DartLibrary.h"
#include "DartFunction.h"
#include "HtArrayIterator.h"
#include <numeric>

DartClass::DartClass(const DartLibrary& lib_, const dart::Class& cls) :
	lib(lib_), unboxed_fields_bitmap(0), superCls(nullptr), ptr(cls.ptr()), declarationType(nullptr), type(CLASS),
	num_type_arguments(0), num_type_parameters(0), mixin(nullptr), is_const_constructor(false), is_transformed_mixin(false)
{
	auto zone = dart::Thread::Current()->zone();

	ASSERT(cls.is_type_finalized());

	id = (uint32_t)cls.id();
	if (!cls.IsTopLevel()) {
		name = cls.ScrubbedNameCString();
	}

	size = (int32_t)cls.host_next_field_offset();
	type_argument_offset = (int32_t)cls.host_type_arguments_field_offset();


	if (id == dart::kGrowableObjectArrayCid) {
	}

	if (!cls.is_loaded() || id <= dart::kLastInternalOnlyCid) {
		return;
	}

	if (!dart::ClassTable::IsTopLevelCid(id)) {
		auto supClsPtr = cls.SuperClass();

		auto superCid = supClsPtr.untag()->id();
		if (superCid > 0 && (intptr_t)supClsPtr == (intptr_t)dart::Object::null())
			superCid = 0;
		if (superCid)
			superCls = (DartClass*)(intptr_t)superCid;

		if (cls.is_const())
			is_const_constructor = true;
		is_transformed_mixin = cls.is_transformed_mixin_application();

		if (cls.is_abstract())
			type = ABSTRACT;
		else if (cls.is_enum_class())
			type = ENUM;

		num_type_parameters = (uint32_t)cls.NumTypeParameters();
		num_type_arguments = (uint32_t)cls.NumTypeArguments();
	}

	{
		const auto& fields = dart::Array::Handle(zone, cls.fields());
		intptr_t num = fields.Length();
		for (intptr_t i = 0; i < num; i++) {
			auto fieldPtr = fields.At(i);
			AddField(fieldPtr);
		}
	}

	{
		const auto& funcs = dart::Array::Handle(zone, cls.functions());
		intptr_t num_funcs = funcs.Length();
		for (intptr_t i = 0; i < num_funcs; i++) {
			auto funcPtr = funcs.At(i);
			AddFunction(funcPtr);
		}
	}

}

DartClass::DartClass(const DartLibrary& lib)
	: lib(lib), unboxed_fields_bitmap(0), id(0), superCls(nullptr), ptr(dart::Class::null()), declarationType(nullptr),
	name(""), type(CLASS), num_type_arguments(0), num_type_parameters(0), mixin(nullptr),
	type_argument_offset(0), size(0), is_const_constructor(false), is_transformed_mixin(false)
{
}

DartClass::~DartClass()
{
	for (auto field : fields) {
		delete field;
	}
	for (auto func : functions) {
		delete func;
	}
}

DartFunction* DartClass::AddFunction(const dart::ObjectPtr funcPtr)
{
	auto dartFn = new DartFunction(*this, dart::Function::RawCast(funcPtr));
	functions.push_back(dartFn);
	return dartFn;
}

DartFunction* DartClass::AddFunction(const dart::Code& code)
{
	auto dartFn = new DartFunction(*this, code);
	functions.push_back(dartFn);
	return dartFn;
}

DartField* DartClass::AddField(const dart::ObjectPtr fieldPtr)
{
	auto dartField = new DartField(*this, dart::Field::RawCast(fieldPtr));
	fields.push_back(dartField);
	return dartField;
}

DartField* DartClass::AddField(intptr_t offset, DartAbstractType* type, bool nativeNumber)
{
	auto dartField = FindField(offset);
	if (dartField == nullptr) {
		dartField = new DartField(*this, (uint32_t)offset, type);
		fields.push_back(dartField);
	}
	else {
		auto ctype = dartField->Type();
		if (ctype != type) {
		}
	}
	return dartField;
}

DartField* DartClass::FindField(intptr_t offset)
{
	auto it = std::find_if(fields.begin(), fields.end(), [offset](const DartField* field) { return field->Offset() == offset; });
	if (it == fields.end())
		return nullptr;
	return *it;
}

std::string DartClass::FullNameWithPackage() const
{
	return "[" + lib.url + "] " + name + typeVectorName;
}

void DartClass::PrintHead(std::ostream& of)
{
	if (superCls == NULL)
		of << std::format("\n// class id: {}, size: {:#x}\n", id, size);
	else
		of << std::format("\n// class id: {}, size: {:#x}, field offset: {:#x}\n", id, size, superCls->size);
	if (dart::ClassTable::IsTopLevelCid(id)) {
		of << "class :: {\n";
		return;
	}
	if (superCls == NULL) {
		of << std::format("class {};\n", name.c_str());
		return;
	}

	if (is_const_constructor || is_transformed_mixin) {
		of << "//   ";
		if (is_const_constructor)
			of << "const constructor, ";
		if (is_transformed_mixin)
			of << "transformed mixin,";
		of << "\n";
	}

	std::string cls_prefix;
	if (type == DartClass::CLASS)
		cls_prefix = "class";
	else if (type == DartClass::ABSTRACT)
		cls_prefix = "abstract class";
	else if (type == DartClass::ENUM)
		cls_prefix = "enum";
	else
		cls_prefix = "maybe_class";

	of << cls_prefix << " ";

	of << name << typeVectorName;

	of << " extends " << superCls->name << parentTypeVectorName;;

	if (!interfaces.empty() || mixin) {
		of << "\n    ";
		if (!interfaces.empty()) {
			of << "implements ";
			of << std::accumulate(interfaces.begin() + 1, interfaces.end(), interfaces[0]->FullName(),
				[](std::string x, DartClass* y) {
					return x + ", " + y->FullName();
				}
			);
		}
		if (mixin) {
			of << " with " << mixin->FullName();
		}
	}

	of << " {\n";
}

void DartClass::PrintFoot(std::ostream& of)
{
	of << "}\n";
}

