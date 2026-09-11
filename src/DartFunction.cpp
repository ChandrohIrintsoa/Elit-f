#include "DartSdk.h"
#include "DartFunction.h"
#include "DartClass.h"
#include "DartLibrary.h"
#include "DartApp.h"
#include "VarValue.h"
#include "CodeAnalyzer.h"
#include <numeric>
#include <array>
#include <include/dart_api.h>
#include <vm/object.h>

intptr_t DartFnBase::lib_base;

#ifdef BLUTTER_DART_SINGLE_SNAPSHOT
static int64_t findDiscardedCodeSize(dart::uword entry_point)
{
	auto& tables = dart::GrowableObjectArray::Handle(dart::Thread::Current()->zone(),
		dart::IsolateGroup::Current()->object_store()->instructions_tables());
	auto& table = dart::InstructionsTable::Handle();
	for (intptr_t t = 0; t < tables.Length(); t++) {
		table ^= tables.At(t);
		if (!table.ContainsPc(entry_point))
			continue;
		const auto len = static_cast<intptr_t>(table.rodata()->length);
		intptr_t lo = 0;
		intptr_t hi = len - 1;
		while (lo <= hi) {
			const auto mid = (hi - lo + 1) / 2 + lo;
			if (entry_point < table.EntryPointAt(mid)) {
				hi = mid - 1;
			}
			else if ((mid != hi) && (entry_point >= table.EntryPointAt(mid + 1))) {
				lo = mid + 1;
			}
			else {
				if (mid == len - 1)
					break;
				return static_cast<int64_t>(table.EntryPointAt(mid + 1)) - static_cast<int64_t>(table.EntryPointAt(mid));
			}
		}
		break;
	}
	return 0;
}
#endif

DartFunction::DartFunction(DartClass& cls, const dart::FunctionPtr ptr) : DartFnBase(), cls(cls), parent(nullptr), ptr(ptr), kind(NORMAL)
{
        auto* zone = dart::Thread::Current()->zone();

        const auto& func = dart::Function::Handle(zone, ptr);

        name = func.UserVisibleNameCString();

        is_native = func.is_native();
        is_closure = func.IsClosureFunction();
        is_ffi = func.kind() == dart::UntaggedFunction::kFfiTrampoline;
        if (!is_ffi) {
                is_static = func.is_static();
                is_const = func.is_const();
                is_abstract = func.is_abstract();
                is_async = func.IsAsyncFunction();
                func.IsGetterFunction();

                switch (func.kind()) {
                case dart::UntaggedFunction::kConstructor:
                        kind = CONSTRUCTOR;
                        break;
                case dart::UntaggedFunction::kSetterFunction:
                case dart::UntaggedFunction::kImplicitSetter:
                        kind = SETTER;
                        break;
                case dart::UntaggedFunction::kGetterFunction:
                case dart::UntaggedFunction::kImplicitGetter:
                case dart::UntaggedFunction::kImplicitStaticGetter:
                        kind = GETTER;
                        break;
                default:
                        kind = NORMAL;
                }
        }
        else {
                is_static = false;
                is_const = false;
                is_abstract = false;
                is_async = false;
        }

	const auto ep = func.entry_point() - lib_base;
	const auto& code = dart::Code::Handle(zone, func.CurrentCode());
#ifdef BLUTTER_DART_SINGLE_SNAPSHOT
	if (dart::Code::IsUnknownDartCode(code.ptr())) {
		ep_addr = ep;
		payload_addr = ep;
		morphic_addr = ep;
		size = findDiscardedCodeSize(func.entry_point());
	}
	else
#endif
	{
		payload_addr = code.PayloadStart();
		if (payload_addr > 0)
			payload_addr -= lib_base;
		morphic_addr = code.MonomorphicEntryPoint();
		if (morphic_addr > 0)
			morphic_addr -= lib_base;
		size = code.Size();
		ep_addr = code.EntryPoint() - lib_base;
		if (ep != ep_addr) {
			ep_addr = ep;
		}
	}


        if (is_closure) {
                is_static = func.is_static();
                auto parentPtr = func.parent_function();
                if ((intptr_t)parentPtr != (intptr_t)dart::Function::null()) {
                        parent = (DartFunction*)(intptr_t)parentPtr;
                }
                else {
                }
        }

}

DartFunction::DartFunction(DartClass& cls, const dart::Code& code)
        : DartFnBase(), cls(cls), parent(nullptr), ptr(dart::Function::null()), kind(NORMAL),
        is_native(true), is_closure(false), is_ffi(false), is_static(false), is_const(false), is_abstract(false), is_async(false)
{
        payload_addr = code.PayloadStart();
        if (payload_addr > 0)
                payload_addr -= lib_base;
        morphic_addr = code.MonomorphicEntryPoint();
        if (morphic_addr > 0)
                morphic_addr -= lib_base;
        size = code.Size();
        ep_addr = code.EntryPoint() - lib_base;
        name = "__unknown_function__";
}

std::string DartFunction::FullName() const
{
        auto& lib = cls.Library();
        return "[" + lib.url + "] " + cls.Name() + "::" + name;
}

DartFunction* DartFunction::GetOutermostFunction() const
{
        if (!parent)
                return nullptr;

        DartFunction* topFn = parent;
        while (topFn->parent) {
                ASSERT(topFn->IsClosure());
                topFn = topFn->parent;
        }
        return topFn;
}

void DartFunction::SetAnalyzedData(std::unique_ptr<AnalyzedFnData> data)
{
        ASSERT(!analyzedData);

        analyzedData = std::move(data);
}

static const auto BinaryOpNames = std::to_array<std::string>({ "+", "-", "*", "/", "~/", "%", "&", "|" });
static bool isBinaryOpName(const std::string& name)
{
        return std::find(BinaryOpNames.begin(), BinaryOpNames.end(), name) != BinaryOpNames.end();
}

std::string DartFunction::ToCallStatement(const std::vector<std::shared_ptr<VarItem>>& args) const
{
        std::string callArgs = "";
        std::string callFn = "";
        if (IsStatic() || kind == CONSTRUCTOR) {
                if (!args.empty()) {
                        callArgs = std::accumulate(args.begin() + 1, args.end(), args[0]->CallArgName(),
                                [](std::string x, const std::shared_ptr<VarItem> y) {
                                        return x + ", " + y->CallArgName();
                                }
                        );
                }
                callFn = Name();
        }
        else {
                ASSERT(!args.empty());
                if (isBinaryOpName(name)) {
                        ASSERT(args.size() == 2);
                        return args[0]->CallArgName() + " " + name + " " + args[1]->CallArgName();
                }
                else {
                        if (args.size() > 1) {
                                callArgs = std::accumulate(args.begin() + 2, args.end(), args[1]->CallArgName(),
                                        [](std::string x, const std::shared_ptr<VarItem>& y) {
                                                return x + ", " + y->CallArgName();
                                        }
                                );
                        }
                        callFn = args[0]->CallArgName() + "." + Name();
                }
        }
        return std::format("{}({})", callFn.c_str(), callArgs.c_str());
}

void DartFunction::PrintHead(std::ostream& of) const
{
        auto zone = dart::Thread::Current()->zone();
        auto& func = dart::Function::Handle(zone, ptr);

        const auto& sig = dart::FunctionType::Handle(zone, func.signature());

        of << "  ";
        if (is_closure)
                of << "[closure] ";

        if (is_ffi) {
                of << "[ffi] ";
        }
        else {
                if (is_const)
                        of << "const ";
                else if (is_abstract)
                        of << "abstract ";

                switch (kind) {
                case CONSTRUCTOR:
                        if (is_static)
                                of << "factory ";
                        break;
                case SETTER:
                        of << "set ";
                        break;
                case GETTER:
                        if (sig.IsNull())
                                of << "get ";
                        break;
                default:
                        if (is_static)
                                of << "static ";
                        break;
                }
        }

        if (sig.IsNull()) {
                of << "_ " << name << "(/* No info */)";
        }
        else {
                dart::ZoneTextBuffer buffer(zone);
                const auto& result_type = dart::AbstractType::Handle(sig.result_type());
                result_type.PrintName(dart::Object::kScrubbedName, &buffer);
                of << buffer.buffer() << " " << name;
                const auto& type_params = dart::TypeParameters::Handle(zone, sig.type_parameters());
                if (!type_params.IsNull()) {
                        buffer.Clear();
                        type_params.Print(dart::Thread::Current(), zone, false, 0, dart::Object::kScrubbedName, &buffer);
                        of << "<" << buffer.buffer() << ">";
                }
                buffer.Clear();
                sig.PrintParameters(dart::Thread::Current(), zone, dart::Object::kScrubbedName, &buffer);
                of << "(" << buffer.buffer() << ")";
        }

        if (is_async) {
                of << " async";
        }
        of << " {\n";

        of << std::format("    // ** addr: {:#x}, size: {:#x}\n", ep_addr, size);
}

void DartFunction::PrintFoot(std::ostream& of) const
{
        of << "  }\n";
}

