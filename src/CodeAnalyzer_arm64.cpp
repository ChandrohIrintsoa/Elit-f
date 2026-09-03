#include "CodeAnalyzer.h"
#include "DartApp.h"
#include "VarValue.h"
#include "DartThreadInfo.h"
#include <source_location>
#include <unordered_set>

#ifndef NO_CODE_ANALYSIS

class InsnMarker
{
public:
	explicit InsnMarker(AsmIterator& insn) : insn(insn), mark(insn.Current()) {}
	~InsnMarker() {
		if (mark)
			insn.SetCurrent(mark);
	}

	int64_t Take() {
		auto res = mark->address;
		mark = nullptr;
		return res;
	}

	cs_insn* Insn() {
		return mark;
	}

private:
	AsmIterator& insn;
	cs_insn* mark;
};

class InsnException
{
public:
	explicit InsnException(const char* cond, AsmIterator& insn, const std::source_location& location = std::source_location::current())
		: cond{ cond }, insn{ insn.Current() }, location{ location } {}

	std::string cond;
	cs_insn* insn;
	std::source_location location;
};

#define INSN_ASSERT(cond) \
  do {                    \
	if (!(cond)) throw InsnException(#cond, insn); \
  } while (false)

static VarValue* getPoolObject(DartApp& app, intptr_t offset, A64::Register dstReg)
{
	intptr_t idx = dart::ObjectPool::IndexFromOffset(offset);
	auto& pool = app.GetObjectPool();
	auto objType = pool.TypeAt(idx);
	if (objType == dart::ObjectPool::EntryType::kTaggedObject) {
		auto ptr = pool.ObjectAt(idx);
		if (!ptr.IsHeapObject()) {
			return new VarInteger(dart::RawSmiValue(dart::Smi::RawCast(ptr)), dart::kSmiCid);
		}

		if (ptr.IsRawNull())
			return new VarNull();

		auto& obj = dart::Object::Handle(ptr);
		if (obj.IsString())
			return new VarString(dart::String::Cast(obj).ToCString());

		if (obj.IsTypedData()) {
			return new VarExpression(std::format("{}", obj.ToCString()), (int32_t)obj.GetClassId());
		}

		switch (obj.GetClassId()) {
		case dart::kSmiCid:
			return new VarInteger(dart::Smi::Cast(obj).Value(), dart::kSmiCid);
		case dart::kMintCid:
			return new VarInteger(MintValue(dart::Mint::Cast(obj)), dart::kMintCid);
		case dart::kDoubleCid:
			return new VarDouble(dart::Double::Cast(obj).value());
		case dart::kBoolCid:
			return new VarBoolean(dart::Bool::Cast(obj).value());
		case dart::kNullCid:
			return new VarNull();
		case dart::kCodeCid: {
			const auto& code = dart::Code::Cast(obj);
			auto stub = app.GetFunction(code.EntryPoint() - app.base());
			ASSERT(stub);
			return new VarFunctionCode(*stub);
		}
		case dart::kFieldCid: {
			const auto& field = dart::Field::Cast(obj);
			auto dartCls = app.GetClass(field.Owner().untag()->id());
			auto dartField = dartCls->FindField(field.TargetOffset());
			ASSERT(dartField);
			return new VarField(*dartField);
		}
		case dart::kArrayCid:
		case dart::kImmutableArrayCid:
			return new VarArray(dart::Array::Cast(obj).ptr());
		case dart::kFunctionCid:
		case dart::kClosureCid:
		case dart::kConstMapCid:
		case dart::kConstSetCid:
			return new VarExpression(std::format("{}", obj.ToCString()), (int32_t)obj.GetClassId());
#ifdef HAS_RECORD_TYPE
		case dart::kRecordCid: {
			return new VarExpression(std::format("{}", obj.ToCString()), (int32_t)obj.GetClassId());
		}
#endif
		case dart::kTypeParametersCid:
			throw std::runtime_error("Type parameter in Object Pool");
		case dart::kTypeCid:
			return new VarType(*app.TypeDb()->FindOrAdd(dart::Type::Cast(obj).ptr()));
#ifdef HAS_RECORD_TYPE
		case dart::kRecordTypeCid:
			return new VarRecordType(*app.TypeDb()->FindOrAdd(dart::RecordType::Cast(obj).ptr()));
#endif
		case dart::kTypeParameterCid:
			return new VarTypeParameter(*app.TypeDb()->FindOrAdd(dart::TypeParameter::Cast(obj).ptr()));
		case dart::kFunctionTypeCid:
			return new VarFunctionType(*app.TypeDb()->FindOrAdd(dart::FunctionType::Cast(obj).ptr()));
		case dart::kTypeArgumentsCid: {
			return new VarTypeArgument(*app.TypeDb()->FindOrAdd(dart::TypeArguments::Cast(obj).ptr()));
		}
		case dart::kSentinelCid:
			return new VarSentinel();
		case dart::kUnlinkedCallCid: {
			intptr_t idx = dart::ObjectPool::IndexFromOffset(offset + 8);
			ASSERT(pool.TypeAt(idx) == dart::ObjectPool::EntryType::kImmediate);
			auto imm = pool.RawValueAt(idx);
			auto dartFn = app.GetFunction(imm - app.base());
			return new VarUnlinkedCall(*dartFn->AsStub());
		}
		case dart::kSubtypeTestCacheCid:
			return new VarSubtypeTestCache();
		case dart::kInt32x4Cid:
		case dart::kFloat32x4Cid:
		case dart::kFloat64x2Cid:
			return new VarExpression(std::format("{}", obj.ToCString()), (int32_t)obj.GetClassId());
		case dart::kLibraryPrefixCid:
		case dart::kInstanceCid:
			return new VarInstance(app.GetClass(dart::kInstanceCid));
		}

		if (obj.IsInstance()) {
			auto dartCls = app.GetClass(obj.GetClassId());
			if (dartCls->Id() < dart::kNumPredefinedCids) {
				std::cerr << std::format("Unhandle predefined class {} ({})\n", dartCls->Name(), dartCls->Id());
			}
			return new VarInstance(dartCls);
		}

		throw std::runtime_error("unhandle object class in getPoolObject");
	}
	else if (objType == dart::ObjectPool::EntryType::kImmediate) {
		auto imm = pool.RawValueAt(idx);
		if (dstReg.IsDecimal())
			return new VarDouble(*((double*)&imm), VarType::NativeDouble);
		return new VarInteger(imm, VarValue::NativeInt);
	}
	else if (objType == dart::ObjectPool::EntryType::kNativeFunction) {
		throw std::runtime_error("getting native function pool object from Dart code");
	}
	else {
		throw std::runtime_error(std::format("unknown pool object type: {}", (int)objType).c_str());
	}
}

static inline void handleDecompressPointer(AsmIterator& insn, arm64_reg reg) {
	INSN_ASSERT(insn.id() == ARM64_INS_ADD);
	INSN_ASSERT(insn.ops(0).reg == insn.ops(1).reg && insn.ops(0).reg == reg);
	INSN_ASSERT(insn.ops(2).reg == CSREG_DART_HEAP && insn.ops(2).shift.value == 32);
	++insn;
}

static inline void handleExtraDecompressPointer(AsmIterator& insn, arm64_reg reg) {
	if (insn.id() != ARM64_INS_ADD) return;
	if (!(insn.ops(0).reg == insn.ops(1).reg && insn.ops(0).reg == reg)) return;
	if (!(insn.ops(2).reg == CSREG_DART_HEAP && insn.ops(2).shift.value == 32)) return;
	++insn;
}

static bool tryConsumeLeaveFrameRestore(AsmIterator& insn)
{
	if (insn.id() == ARM64_INS_LDP) {
		if (insn.op_count() < 3 || insn.op_count() > 4)
			return false;
		if (insn.ops(0).reg != CSREG_DART_FP || insn.ops(1).reg != ARM64_REG_LR)
			return false;
		if (insn.ops(2).mem.base != CSREG_DART_SP)
			return false;
		if (insn.op_count() == 4 && (insn.ops(3).type != ARM64_OP_IMM || insn.ops(3).imm != 0x10))
			return false;
		++insn;
		return true;
	}

	if (insn.id() == ARM64_INS_MOV && insn.ops(1).type == ARM64_OP_REG &&
		(insn.ops(1).reg == CSREG_DART_FP || insn.ops(1).reg == ARM64_REG_X29))
	{
		const auto tmpReg = insn.ops(0).reg;
		if (tmpReg == CSREG_DART_FP)
			return false;
		++insn;
		if (!(insn.id() == ARM64_INS_LDR && insn.writeback()))
			return false;
		if (insn.ops(0).reg != CSREG_DART_FP)
			return false;
		if (insn.op_count() < 3 || insn.ops(1).mem.base != tmpReg)
			return false;
		if (insn.ops(2).type != ARM64_OP_IMM || insn.ops(2).imm != 8)
			return false;
		++insn;
		return true;
	}

	return false;
}

struct ILResult {
	cs_insn* lastIns{ nullptr };
	std::unique_ptr<ILInstr> il;
	uint64_t NextAddress() const { return lastIns->address + lastIns->size; }
	template <typename T, typename = std::enable_if<std::is_base_of<ILInstr, T>::value>>
	T* get() { return reinterpret_cast<T*>(il.get()); }
};
struct StoreLocalResult {
	arm64_reg srcReg{ ARM64_REG_INVALID };
	int fpOffset{ 0 };
};

class FunctionAnalyzer
{
public:
	FunctionAnalyzer(AnalyzedFnData* fnInfo, DartFunction* dartFn, AsmInstructions& asm_insns, DartApp& app)
		: fnInfo{ fnInfo }, dartFn{ dartFn }, asm_insns{ asm_insns }, app{ app } {}

	void asm2il();

	void handlePrologue(AsmIterator& insItr, uint64_t endPrologueAddr);
	std::tuple<A64::Register, A64::Register> unboxParam(AsmIterator& insn, A64::Register expectedSrcReg = A64::Register{});
	void handleFixedParameters(AsmIterator& insn, arm64_reg paramCntReg, int paramCnt = 0);
	void handleOptionalPositionalParameters(AsmIterator& insn, arm64_reg optionalParamCntReg);
	void handleOptionalNamedParameters(AsmIterator& insn, arm64_reg paramCntReg);
	void handleArgumentsDescriptorTypeArguments(AsmIterator& insn);
	void handleParameterRegisters(AsmIterator& insn);

	StoreLocalResult handleStoreLocal(AsmIterator& insn, arm64_reg expected_src_reg = ARM64_REG_INVALID);

	std::unique_ptr<SetupParametersInstr> processPrologueParametersInstr(AsmIterator& insn, uint64_t endPrologueAddr);

	std::unique_ptr<EnterFrameInstr> processEnterFrameInstr(AsmIterator& insn);
	std::unique_ptr<LeaveFrameInstr> processLeaveFrameInstr(AsmIterator& insn);
	std::unique_ptr<AllocateStackInstr> processAllocateStackInstr(AsmIterator& insn);
	std::unique_ptr<CheckStackOverflowInstr> processCheckStackOverflowInstr(AsmIterator& insn);
	std::unique_ptr<CallLeafRuntimeInstr> processCallLeafRuntime(AsmIterator& insn);
	std::unique_ptr<ILInstr> processObjectPoolInstr(AsmIterator& insn);
	std::unique_ptr<LoadValueInstr> processLoadValueNoObjectPoolInstr(AsmIterator& insn);
	std::unique_ptr<LoadValueInstr> processLoadValueInstr(AsmIterator& insn);
	std::unique_ptr<ClosureCallInstr> processClosureCallInstr(AsmIterator& insn);
	std::unique_ptr<MoveRegInstr> processMoveRegInstr(AsmIterator& insn);
	std::unique_ptr<DecompressPointerInstr> processDecompressPointerInstr(AsmIterator& insn);
	std::unique_ptr<SaveRegisterInstr> processSaveRegisterInstr(AsmIterator& insn);
	std::unique_ptr<RestoreRegisterInstr> processLoadSavedRegisterInstr(AsmIterator& insn);
	std::unique_ptr<InitAsyncInstr> processInitAsyncInstr(AsmIterator& insn);
	std::unique_ptr<CallInstr> processCallInstr(AsmIterator& insn);
	std::unique_ptr<GdtCallInstr> processGdtCallInstr(AsmIterator& insn);
	std::unique_ptr<ReturnInstr> processReturnInstr(AsmIterator& insn);
	std::unique_ptr<TestTypeInstr> processInstanceofNoTypeArgumentInstr(AsmIterator& insn);
	std::unique_ptr<BranchIfSmiInstr> processBranchIfSmiInstr(AsmIterator& insn);
	std::unique_ptr<LoadClassIdInstr> processLoadClassIdInstr(AsmIterator& insn);
	std::unique_ptr<BoxInt64Instr> processBoxInt64Instr(AsmIterator& insn);
	std::unique_ptr<LoadInt32Instr> processLoadInt32FromBoxOrSmiInstrFromSrcReg(AsmIterator& insn, A64::Register expectedSrcReg = A64::Register{});
	std::unique_ptr<LoadInt32Instr> processLoadInt32FromBoxOrSmiInstr(AsmIterator& insn);
	std::unique_ptr<LoadTaggedClassIdMayBeSmiInstr> processLoadTaggedClassIdMayBeSmiInstr(AsmIterator& insn);
	std::unique_ptr<ILInstr> processLoadFieldTableInstr(AsmIterator& insn);
	std::unique_ptr<AllocateObjectInstr> processTryAllocateObject(AsmIterator& insn);
	std::unique_ptr<WriteBarrierInstr> processWriteBarrierInstr(AsmIterator& insn);
	std::unique_ptr<ILInstr> processLoadStore(AsmIterator& insn);

	struct ObjectPoolInstr {
		A64::Register dstReg;
		VarItem item{};
		bool isWrite;
		bool IsSet() const { return dstReg.IsSet(); }
	};

private:
	void setAsmTextDataPool(uint64_t addr, uint64_t offset) {
		auto& asm_text = fnInfo->asmTexts.AtAddr(addr);
		asm_text.dataType = AsmText::PoolOffset;
		asm_text.poolOffset = offset;
	}
	void setAsmTextDataBoolean(uint64_t addr, bool b) {
		auto& asm_text = fnInfo->asmTexts.AtAddr(addr);
		asm_text.dataType = AsmText::Boolean;
		asm_text.boolVal = b;
	}
	void setAsmTextDataCall(uint64_t addr, uint64_t callAddress) {
		auto& asm_text = fnInfo->asmTexts.AtAddr(addr);
		asm_text.dataType = AsmText::Call;
		asm_text.callAddress = callAddress;
	}

	ObjectPoolInstr getObjectPoolInstruction(AsmIterator& insn);
	void printInsnException(InsnException& e);

	AnalyzedFnData* fnInfo;
	DartFunction* dartFn;
	AsmInstructions& asm_insns;
	DartApp& app;
};

typedef std::unique_ptr<ILInstr>(FunctionAnalyzer::* AsmMatcherFn)(AsmIterator& insn);
static const AsmMatcherFn matcherFns[] = {
	(AsmMatcherFn) &FunctionAnalyzer::processEnterFrameInstr,
	(AsmMatcherFn) &FunctionAnalyzer::processLeaveFrameInstr,
	(AsmMatcherFn) &FunctionAnalyzer::processAllocateStackInstr,
	(AsmMatcherFn) &FunctionAnalyzer::processCheckStackOverflowInstr,
	(AsmMatcherFn) &FunctionAnalyzer::processCallLeafRuntime,
	(AsmMatcherFn) &FunctionAnalyzer::processObjectPoolInstr,
	(AsmMatcherFn) &FunctionAnalyzer::processLoadValueNoObjectPoolInstr,
	(AsmMatcherFn) &FunctionAnalyzer::processDecompressPointerInstr,
	(AsmMatcherFn) &FunctionAnalyzer::processClosureCallInstr,
	(AsmMatcherFn) &FunctionAnalyzer::processSaveRegisterInstr,
	(AsmMatcherFn) &FunctionAnalyzer::processLoadSavedRegisterInstr,
	(AsmMatcherFn) &FunctionAnalyzer::processInitAsyncInstr,
	(AsmMatcherFn) &FunctionAnalyzer::processCallInstr,
	(AsmMatcherFn) &FunctionAnalyzer::processGdtCallInstr,
	(AsmMatcherFn) &FunctionAnalyzer::processReturnInstr,
	(AsmMatcherFn) &FunctionAnalyzer::processInstanceofNoTypeArgumentInstr,
	(AsmMatcherFn) &FunctionAnalyzer::processBranchIfSmiInstr,
	(AsmMatcherFn) &FunctionAnalyzer::processLoadClassIdInstr,
	(AsmMatcherFn) &FunctionAnalyzer::processBoxInt64Instr,
	(AsmMatcherFn) &FunctionAnalyzer::processLoadInt32FromBoxOrSmiInstr,
	(AsmMatcherFn) &FunctionAnalyzer::processLoadTaggedClassIdMayBeSmiInstr,
	&FunctionAnalyzer::processLoadFieldTableInstr,
	(AsmMatcherFn) &FunctionAnalyzer::processTryAllocateObject,
	(AsmMatcherFn) &FunctionAnalyzer::processWriteBarrierInstr,
	&FunctionAnalyzer::processLoadStore,
};

FunctionAnalyzer::ObjectPoolInstr FunctionAnalyzer::getObjectPoolInstruction(AsmIterator& insn)
{
	int64_t offset = 0;
	bool isWrite = false;
	A64::Register dstReg;
	InsnMarker marker(insn);
	if (insn.id() == ARM64_INS_LDR) {
		if (insn.ops(1).mem.base == CSREG_DART_PP && insn.ops(1).mem.index == ARM64_REG_INVALID) {
			offset = insn.ops(1).mem.disp;
			dstReg = A64::Register{ insn.ops(0).reg };
			++insn;
		}
	}
	else if (insn.id() == ARM64_INS_ADD) {
		if (insn.ops(1).reg == CSREG_DART_NULL) {
			ASSERT(insn.ops(2).type == ARM64_OP_IMM);
			const auto offset = insn.ops(2).imm;
			bool val;
			if (offset == dart::kTrueOffsetFromNull) {
				val = true;
			}
			else if (offset == dart::kFalseOffsetFromNull) {
				val = false;
			}
			else {
				FATAL("add from NULL_REG");
			}
			auto b = new VarBoolean(val);
			setAsmTextDataBoolean(marker.Take(), val);
			dstReg = A64::Register{ insn.ops(0).reg };
			++insn;
			return ObjectPoolInstr{ dstReg, VarItem{ VarStorage::NewImmediate(), b } };
		}

		if (insn.ops(1).reg == CSREG_DART_PP && insn.ops(2).type == ARM64_OP_IMM && insn.ops(2).shift.type == ARM64_SFT_LSL && insn.ops(2).shift.value == 12) {
			auto base = insn.ops(2).imm << 12;
			auto offset_reg = insn.ops(0).reg;
			++insn;

			if (insn.id() == ARM64_INS_LDR) {
				INSN_ASSERT(insn.ops(1).mem.base == offset_reg);
				offset = base + insn.ops(1).mem.disp;
			}
			else if (insn.id() == ARM64_INS_LDP) {
				INSN_ASSERT(insn.ops(2).mem.base == offset_reg);
				offset = base + insn.ops(2).mem.disp;
			}
			else if (insn.id() == ARM64_INS_ADD) {
				INSN_ASSERT(insn.ops(2).type == ARM64_OP_IMM);
				offset = base + insn.ops(2).imm;
			}
			else if (insn.id() == ARM64_INS_STR) {
				INSN_ASSERT(insn.ops(1).mem.base == offset_reg);
				offset = base + insn.ops(1).mem.disp;
				isWrite = true;
			}
			else {
				INSN_ASSERT(false);
			}
			dstReg = A64::Register{ insn.ops(0).reg };
			++insn;
		}
	}
	else if (insn.id() == ARM64_INS_MOV) {
		const auto offset_reg = insn.ops(0).reg;
		offset = insn.ops(1).imm;
		++insn;

		if (insn.id() == ARM64_INS_MOVK && insn.ops(0).reg == offset_reg &&
			insn.ops(1).type == ARM64_OP_IMM && insn.ops(1).shift.type == ARM64_SFT_LSL && insn.ops(1).shift.value == 16)
		{
			offset |= insn.ops(1).imm << 16;
			++insn;

			if (insn.id() == ARM64_INS_LDR && insn.ops(1).mem.base == CSREG_DART_PP && insn.ops(1).mem.index == offset_reg) {
				dstReg = A64::Register{ insn.ops(0).reg };
				++insn;
			}
			if (insn.id() == ARM64_INS_STR && insn.ops(1).mem.base == CSREG_DART_PP && insn.ops(1).mem.index == offset_reg) {
				dstReg = A64::Register{ insn.ops(0).reg };
				++insn;
				isWrite = true;
			}
		}
	}
	else if (insn.id() == ARM64_INS_STR) {
		if (insn.ops(1).mem.base == CSREG_DART_PP && insn.ops(1).mem.index == ARM64_REG_INVALID) {
			offset = insn.ops(1).mem.disp;
			dstReg = A64::Register{ insn.ops(0).reg };
			++insn;
			isWrite = true;
		}
	}

	if (!dstReg.IsSet()) {
		return ObjectPoolInstr{};
	}

	setAsmTextDataPool(marker.Take(), offset);
	auto val = getPoolObject(app, offset, dstReg);
	return ObjectPoolInstr{ dstReg, VarItem{VarStorage::NewPool((int)offset), val}, isWrite };
}

void FunctionAnalyzer::printInsnException(InsnException& e)
{
	std::cerr << "Analysis error at line " << e.location.line()
		<< " `" << e.location.function_name() << "`: " << e.cond << '\n';
	const uint64_t fn_addr = fnInfo->dartFn.Address();

	auto ins = e.insn;
	for (int i = 0; ins->address > fn_addr && i < 4; i++) {
		--ins;
	}
	while (ins != e.insn) {
		std::cerr << std::format("    {:#x}: {} {}\n", ins->address, &ins->mnemonic[0], &ins->op_str[0]);
		++ins;
	}
	std::cerr << std::format("  * {:#x}: {} {}\n", ins->address, &ins->mnemonic[0], &ins->op_str[0]);
	if (ins->address + ins->size < fnInfo->dartFn.AddressEnd()) {
		++ins;
		std::cerr << std::format("    {:#x}: {} {}\n", ins->address, &ins->mnemonic[0], &ins->op_str[0]);
	}
}

std::unique_ptr<EnterFrameInstr> FunctionAnalyzer::processEnterFrameInstr(AsmIterator& insn)
{
	if (insn.id() == ARM64_INS_STP && insn.ops(0).reg == CSREG_DART_FP && insn.ops(1).reg == ARM64_REG_LR && insn.ops(2).mem.base == CSREG_DART_SP) {
		INSN_ASSERT(insn.writeback());
		const auto ins0_addr = insn.address();
		++insn;

		INSN_ASSERT(insn.id() == ARM64_INS_MOV);
		INSN_ASSERT(insn.ops(0).reg == CSREG_DART_FP);
		INSN_ASSERT(insn.ops(1).reg == CSREG_DART_SP);
		++insn;

		fnInfo->useFramePointer = true;
		return std::make_unique<EnterFrameInstr>(insn.Wrap(ins0_addr));
	}
	return nullptr;
}

std::unique_ptr<LeaveFrameInstr> FunctionAnalyzer::processLeaveFrameInstr(AsmIterator& insn)
{
	if (insn.id() == ARM64_INS_MOV && insn.ops(0).reg == CSREG_DART_SP && insn.ops(1).reg == CSREG_DART_FP) {
		INSN_ASSERT(fnInfo->useFramePointer);
		const auto ins0_addr = insn.address();
		++insn;
		if (!tryConsumeLeaveFrameRestore(insn))
			return nullptr;

		return std::make_unique<LeaveFrameInstr>(insn.Wrap(ins0_addr));
	}
	return nullptr;
}

std::unique_ptr<AllocateStackInstr> FunctionAnalyzer::processAllocateStackInstr(AsmIterator& insn)
{
	if (insn.id() == ARM64_INS_SUB && insn.ops(0).reg == CSREG_DART_SP && insn.ops(1).reg == CSREG_DART_SP && insn.ops(2).type == ARM64_OP_IMM) {
		const auto stackSize = (uint32_t)insn.ops(2).imm;
		fnInfo->stackSize = stackSize;
		const auto ins0_addr = insn.address();
		++insn;
		return std::make_unique<AllocateStackInstr>(insn.Wrap(ins0_addr), stackSize);
	}
	return nullptr;
}

std::unique_ptr<CheckStackOverflowInstr> FunctionAnalyzer::processCheckStackOverflowInstr(AsmIterator& insn)
{
	if (insn.id() == ARM64_INS_LDR && insn.ops(1).mem.base == CSREG_DART_THR && insn.ops(1).mem.disp == AOT_Thread_stack_limit_offset) {
		INSN_ASSERT(insn.ops(0).reg == CSREG_DART_TMP);
		const auto ins0_addr = insn.address();
		++insn;

INSN_ASSERT(insn.id() == ARM64_INS_CMP);
INSN_ASSERT(insn.ops(0).reg == CSREG_DART_SP);
INSN_ASSERT(insn.ops(1).reg == CSREG_DART_TMP);
++insn;

INSN_ASSERT(insn.id() == ARM64_INS_B);
INSN_ASSERT(insn.ops(0).type == ARM64_OP_IMM);
uint64_t target = (uint64_t)insn.ops(0).imm;
const auto cc = insn.cc();
++insn;

if (cc == ARM64_CC_HI) {
	INSN_ASSERT(insn.IsBranch());
	INSN_ASSERT(insn.NextAddress() == target);
	target = (uint64_t)insn.ops(0).imm;
	++insn;
}
else {
	INSN_ASSERT(cc == ARM64_CC_LS);
}

if (target != 0) {
	INSN_ASSERT(target < dartFn->AddressEnd() && target >= insn.address());
	if (fnInfo->firstCheckStackOverflowAddr == 0)
		fnInfo->firstCheckStackOverflowAddr = ins0_addr;
	return std::make_unique<CheckStackOverflowInstr>(insn.Wrap(ins0_addr), target);
}
	}

	return nullptr;
}

std::unique_ptr<CallLeafRuntimeInstr> FunctionAnalyzer::processCallLeafRuntime(AsmIterator& insn)
{
	if (insn.id() == ARM64_INS_AND && insn.ops(0).reg == CSREG_DART_SP && insn.ops(1).reg == CSREG_DART_SP && insn.ops(2).imm == 0xfffffffffffffff0) {
		if (fnInfo->LastIL()->Kind() == ILInstr::EnterFrame) {
			InsnMarker marker(insn);
			++insn;
			if (insn.id() == ARM64_INS_MOV && insn.ops(0).reg == ARM64_REG_SP && insn.ops(1).reg == CSREG_DART_SP) {
				++insn;

				INSN_ASSERT(insn.id() == ARM64_INS_LDR);
				INSN_ASSERT(insn.ops(0).reg == CSREG_DART_TMP);
				INSN_ASSERT(insn.ops(1).mem.base == CSREG_DART_THR);
				const auto thr_offset = insn.ops(1).mem.disp;
				++insn;

				INSN_ASSERT(insn.id() == ARM64_INS_STR);
				INSN_ASSERT(insn.ops(0).reg == CSREG_DART_TMP);
				INSN_ASSERT(insn.ops(1).mem.base == CSREG_DART_THR && insn.ops(1).mem.disp == AOT_Thread_vm_tag_offset);
				++insn;

				INSN_ASSERT(insn.id() == ARM64_INS_BLR);
				INSN_ASSERT(insn.ops(0).reg == CSREG_DART_TMP);
				++insn;

				INSN_ASSERT(insn.IsMovz());
				INSN_ASSERT(insn.ops(0).reg == CSREG_DART_TMP);
				INSN_ASSERT(insn.ops(1).imm == dart::VMTag::kDartTagId);
				++insn;

				INSN_ASSERT(insn.id() == ARM64_INS_STR);
				INSN_ASSERT(insn.ops(0).reg == CSREG_DART_TMP);
				INSN_ASSERT(insn.ops(1).mem.base == CSREG_DART_THR && insn.ops(1).mem.disp == AOT_Thread_vm_tag_offset);
				++insn;

				INSN_ASSERT(insn.id() == ARM64_INS_LDR);
				INSN_ASSERT(insn.ops(0).reg == CSREG_DART_TMP);
				INSN_ASSERT(insn.ops(1).mem.base == CSREG_DART_THR && insn.ops(1).mem.disp == AOT_Thread_saved_stack_limit_offset);
				++insn;

				INSN_ASSERT(insn.id() == ARM64_INS_SUB);
				INSN_ASSERT(insn.ops(0).reg == ARM64_REG_SP);
				INSN_ASSERT(insn.ops(1).reg == CSREG_DART_TMP);
				INSN_ASSERT(insn.ops(2).imm == 1 && insn.ops(2).shift.type == ARM64_SFT_LSL && insn.ops(2).shift.value == 12);
				++insn;

				auto il = processLeaveFrameInstr(insn);
				INSN_ASSERT(il);

				INSN_ASSERT(GetThreadLeafFunction(thr_offset));

				fnInfo->RemoveLastIL();

				return std::make_unique<CallLeafRuntimeInstr>(insn.Wrap(marker.Take()), thr_offset);
			}
		}
	}
	else if ((insn.id() == ARM64_INS_MOV && insn.ops(1).reg == CSREG_DART_THR) ||
		(insn.id() == ARM64_INS_LDR && GetThreadLeafFunction(insn.ops(1).mem.disp) && insn.ops(1).mem.base != CSREG_DART_PP && insn.ops(1).mem.disp > dart::Thread::AllocateHandle_entry_point_offset()))
	{
		InsnMarker marker(insn);

		if (insn.id() == ARM64_INS_MOV) {
			const auto tmp_reg = insn.ops(0).reg;
			++insn;

			if (!(insn.id() == ARM64_INS_LDR && insn.ops(1).mem.base == tmp_reg)) {
				return nullptr;
			}
		}

		const auto thr_offset = insn.ops(1).mem.disp;
		const A64::Register tmp_target_reg = insn.ops(0).reg;
		++insn;

		INSN_ASSERT(GetThreadLeafFunction(thr_offset));

		std::vector<std::unique_ptr<MoveRegInstr>> movILs;
		while (true) {
			auto il = processMoveRegInstr(insn);
			if (!il) {
				if ((insn.id() == ARM64_INS_LDR || insn.id() == ARM64_INS_LDUR) && insn.ops(1).mem.base == CSREG_DART_FP) {
					++insn;
					continue;
				}
				else {
					INSN_ASSERT(il);
				}
			}
			if (il->srcReg == A64::Register::FP) {
				INSN_ASSERT(il->dstReg == A64::Register::TMP2);
				break;
			}
			else if (il->srcReg == tmp_target_reg) {
				INSN_ASSERT(il->dstReg == A64::Register::R9);
			}
			else {
				movILs.push_back(std::move(il));
			}
		}
		const auto call_target_reg = ARM64_REG_X9;

		INSN_ASSERT(insn.id() == ARM64_INS_STR && insn.writeback());
		INSN_ASSERT(insn.ops(0).reg == CSREG_DART_FP);
		INSN_ASSERT(insn.ops(1).mem.base == CSREG_DART_SP && insn.ops(1).mem.disp == -8);
		++insn;

		INSN_ASSERT(insn.id() == ARM64_INS_MOV);
		INSN_ASSERT(insn.ops(0).reg == CSREG_DART_FP);
		INSN_ASSERT(insn.ops(1).reg == CSREG_DART_SP);
		++insn;

		INSN_ASSERT(insn.id() == ARM64_INS_AND);
		INSN_ASSERT(insn.ops(0).reg == CSREG_DART_SP);
		INSN_ASSERT(insn.ops(1).reg == CSREG_DART_SP);
		INSN_ASSERT(insn.ops(2).imm == 0xfffffffffffffff0);
		++insn;

		INSN_ASSERT(insn.id() == ARM64_INS_MOV);
		INSN_ASSERT(insn.ops(1).reg == ARM64_REG_SP);
		const auto saved_csp_reg = insn.ops(0).reg;
		++insn;

		INSN_ASSERT(insn.id() == ARM64_INS_MOV);
		INSN_ASSERT(insn.ops(0).reg == ARM64_REG_SP);
		INSN_ASSERT(insn.ops(1).reg == CSREG_DART_SP);
		++insn;

		bool save_to_vm_tag = false;
		if (insn.id() == ARM64_INS_STR) {
			INSN_ASSERT(insn.ops(0).reg == call_target_reg);
			INSN_ASSERT(insn.ops(1).mem.base == CSREG_DART_THR && insn.ops(1).mem.disp == AOT_Thread_vm_tag_offset);
			++insn;
			save_to_vm_tag = true;
		}

		INSN_ASSERT(insn.id() == ARM64_INS_BLR);
		INSN_ASSERT(insn.ops(0).reg == call_target_reg);
		++insn;

		if (save_to_vm_tag) {
			INSN_ASSERT(insn.IsMovz());
			INSN_ASSERT(insn.ops(0).reg == CSREG_DART_TMP);
			INSN_ASSERT(insn.ops(1).imm == dart::VMTag::kDartTagId);
			++insn;

			INSN_ASSERT(insn.id() == ARM64_INS_STR);
			INSN_ASSERT(insn.ops(0).reg == CSREG_DART_TMP);
			INSN_ASSERT(insn.ops(1).mem.base == CSREG_DART_THR && insn.ops(1).mem.disp == AOT_Thread_vm_tag_offset);
			++insn;
		}

		INSN_ASSERT(insn.id() == ARM64_INS_MOV);
		INSN_ASSERT(insn.ops(0).reg == ARM64_REG_SP);
		INSN_ASSERT(insn.ops(1).reg == saved_csp_reg);
		++insn;

		INSN_ASSERT(insn.id() == ARM64_INS_MOV);
		INSN_ASSERT(insn.ops(0).reg == CSREG_DART_SP);
		INSN_ASSERT(insn.ops(1).reg == CSREG_DART_FP);
		++insn;

		INSN_ASSERT(insn.id() == ARM64_INS_LDR && insn.writeback());
		INSN_ASSERT(insn.ops(0).reg == CSREG_DART_FP);
		INSN_ASSERT(insn.ops(1).mem.base == CSREG_DART_SP && insn.ops(2).imm == 8);
		++insn;

		return std::make_unique<CallLeafRuntimeInstr>(insn.Wrap(marker.Take()), thr_offset, std::move(movILs));
	}

	return nullptr;
}

StoreLocalResult FunctionAnalyzer::handleStoreLocal(AsmIterator& insn, arm64_reg expected_src_reg)
{
	arm64_reg srcReg = ARM64_REG_INVALID;
	int offset = 0;
	auto saved_ins = insn.Current();

	const auto strWithRegOffset = [&] {
		const auto tmpReg = insn.ops(0).reg;
		++insn;
		if (insn.id() == ARM64_INS_STR && insn.ops(1).mem.base == CSREG_DART_FP && insn.ops(1).mem.index == tmpReg &&
			(expected_src_reg == ARM64_REG_INVALID || expected_src_reg == insn.ops(0).reg))
		{
			srcReg = insn.ops(0).reg;
			++insn;
		}
		else {
			offset = 0;
		}
	};

	if (fnInfo->stackSize > 0x100 && insn.id() == ARM64_INS_MOVN) {
		offset = insn.ops(1).imm << insn.ops(1).shift.value;
		offset = ~offset;
		if (offset < -0x100)
			strWithRegOffset();
	}
	else if (fnInfo->stackSize > 0x200 && insn.id() == ARM64_INS_ORR && insn.ops(1).reg == ARM64_REG_XZR && insn.ops(2).type == ARM64_OP_IMM) {
		offset = insn.ops(2).imm;
		if (offset <= 0x200)
			strWithRegOffset();
	}
	else if (insn.id() == ARM64_INS_STUR && insn.ops(1).mem.base == CSREG_DART_FP && insn.ops(1).mem.disp < 0 &&
		(expected_src_reg == ARM64_REG_INVALID || expected_src_reg == insn.ops(0).reg))
	{
		srcReg = insn.ops(0).reg;
		offset = insn.ops(1).mem.disp;
		++insn;
	}

	if (offset == 0) {
		insn.SetCurrent(saved_ins);
	}
	return StoreLocalResult{ srcReg, offset };
}

void FunctionAnalyzer::handlePrologue(AsmIterator& insn, uint64_t endPrologueAddr)
{
	{
		auto ilEnter = processEnterFrameInstr(insn);
		if (!ilEnter) {
			return;
		}
		fnInfo->AddIL(std::move(ilEnter));
	}

	{
		auto ilAlloc = processAllocateStackInstr(insn);
		if (!ilAlloc) {
			return;
		}
		fnInfo->AddIL(std::move(ilAlloc));
	}

	bool hasPrologue = false;
#ifdef HAS_INIT_ASYNC
	if (fnInfo->stackSize) {
		fnInfo->InitVars();
		fnInfo->InitState();
		try {
			auto il = processPrologueParametersInstr(insn, endPrologueAddr);
			if (il) {
				fnInfo->AddIL(std::move(il));
				hasPrologue = true;
				for (auto& pending_il : fnInfo->Vars()->pending_ils) {
					fnInfo->AddIL(std::move(pending_il));
				}
				fnInfo->Vars()->pending_ils.clear();
			}
		}
		catch (InsnException& e) {
			printInsnException(e);
		}
		fnInfo->DestroyState();
		fnInfo->DestroyVars();
	}
#endif

	if (hasPrologue && endPrologueAddr != 0 && endPrologueAddr != insn.address()) {
	}

	auto ilStack = processCheckStackOverflowInstr(insn);
	if (ilStack) {
		fnInfo->AddIL(std::move(ilStack));
	}
}

enum FunctionVarTypeId : int32_t {
	VtNameBegin = -100,
	VtNameParamCnt,
	VtNameParamName,
	VtNameCurrParamPosSmi,
	VtNameCurrParamOffset,
	vtNameArgIdx,
	VtNameEnd,
};

std::tuple<A64::Register, A64::Register> FunctionAnalyzer::unboxParam(AsmIterator& insn, A64::Register expectedSrcReg)
{
	A64::Register srcReg;
	A64::Register dstReg;

	if (insn.id() == ARM64_INS_LDUR && insn.ops(1).mem.disp == AOT_Double_value_offset - dart::kHeapObjectTag) {
		dstReg = A64::Register{ insn.ops(0).reg };
		if (!dstReg.IsDecimal())
			return { A64::Register{}, A64::Register{} };
		srcReg = A64::Register{ insn.ops(1).mem.base };
		if (expectedSrcReg.IsSet() && expectedSrcReg != srcReg)
			return { A64::Register{}, A64::Register{} };
		++insn;
	}
	else {
		auto* saved_ins = insn.Current();
		auto il = processLoadInt32FromBoxOrSmiInstrFromSrcReg(insn, expectedSrcReg);
		if (!il)
			return { A64::Register{}, A64::Register{} };
		srcReg = il->srcObjReg;
		dstReg = il->dstReg;
	}

	return { dstReg, srcReg };
}

void FunctionAnalyzer::handleFixedParameters(AsmIterator& insn, arm64_reg paramCntReg, int paramCnt)
{
	if (paramCnt == 0)
		paramCnt = INT_MAX;
	for (auto i = 0; i < paramCnt; i++) {
		if (insn.id() != ARM64_INS_ADD)
			break;
		INSN_ASSERT(insn.ops(1).reg == CSREG_DART_FP);
		INSN_ASSERT(ToCapstoneReg(insn.ops(2).reg) == paramCntReg && insn.ops(2).ext == ARM64_EXT_SXTW && insn.ops(2).shift.value == 2);
		const auto tmpReg = insn.ops(0).reg;
		++insn;

		INSN_ASSERT(insn.id() == ARM64_INS_LDR);
		INSN_ASSERT(insn.ops(1).mem.base == tmpReg);
		const auto valReg = insn.ops(0).reg;
		++insn;

		fnInfo->State()->ClearRegister(tmpReg);
		auto val = fnInfo->Vars()->ValParam(fnInfo->params.NumParam());
		fnInfo->State()->SetRegister(valReg, val);

		const auto storeRes = handleStoreLocal(insn, valReg);
		if (storeRes.fpOffset != 0) {
			fnInfo->State()->SetLocal(storeRes.fpOffset, val);
		}

		fnInfo->params.add(FnParamInfo{ valReg, storeRes.fpOffset });
	}

	fnInfo->params.numFixedParam = fnInfo->params.NumParam();
	if (!dartFn->IsStatic() && fnInfo->params.numFixedParam > 0) {
		fnInfo->params[0].name = "this";
		fnInfo->params[0].type = dartFn->Class().DeclarationType();
	}
}

void FunctionAnalyzer::handleOptionalPositionalParameters(AsmIterator& insn, arm64_reg optionalParamCntReg)
{
	int i = 0;
	std::vector<int64_t> missingBranchTargets;
	while (insn.id() == ARM64_INS_CMP) {
		INSN_ASSERT(ToCapstoneReg(insn.ops(0).reg) == optionalParamCntReg);
		INSN_ASSERT(insn.ops(1).imm == (i + 1) << 1);
		++insn;

		if (insn.IsBranch(ARM64_CC_GE)) {
			const auto defaultValueTarget = insn.ops(0).imm;
			INSN_ASSERT(defaultValueTarget == insn.NextAddress());
			for (const auto missingTarget : missingBranchTargets) {
				INSN_ASSERT(missingTarget == defaultValueTarget);
			}
			missingBranchTargets.clear();
			++insn;
			break;
		}

		INSN_ASSERT(insn.IsBranch(ARM64_CC_LT));
		const auto defaultValueTarget = insn.ops(0).imm;
		missingBranchTargets.push_back(defaultValueTarget);
		++insn;

		if (insn.id() == ARM64_INS_ADD && insn.ops(1).reg == CSREG_DART_FP) {
			INSN_ASSERT(ToCapstoneReg(insn.ops(2).reg) == optionalParamCntReg && insn.ops(2).ext == ARM64_EXT_SXTW && insn.ops(2).shift.value == 2);
			const auto tmpReg = insn.ops(0).reg;
			++insn;

			INSN_ASSERT(insn.id() == ARM64_INS_LDR || insn.id() == ARM64_INS_LDUR);
			INSN_ASSERT(insn.ops(1).mem.base == tmpReg && insn.ops(1).mem.disp == 8 * (1 - i));
			const auto valReg = insn.ops(0).reg;
			fnInfo->State()->ClearRegister(tmpReg);
			auto val = fnInfo->Vars()->ValParam(fnInfo->params.NumParam());
			fnInfo->State()->SetRegister(valReg, val);
			fnInfo->params.add(FnParamInfo{ A64::Register{ valReg } });
			++insn;

			const auto storeRes = handleStoreLocal(insn, valReg);
			if (storeRes.fpOffset != 0) {
				fnInfo->State()->SetLocal(storeRes.fpOffset, val);
			}
		}
		else {
			fnInfo->params.add(FnParamInfo{});
		}

		++i;
	}

	if (!missingBranchTargets.empty()) {
		while (true) {
			const auto& [dstReg, srcReg] = unboxParam(insn);
			if (!dstReg.IsSet())
				break;

			auto val = fnInfo->State()->MoveRegister(dstReg, srcReg);
			INSN_ASSERT(val);
			auto& param = fnInfo->params[val->AsParam()->idx];
			param.type = app.TypeDb()->Get(dstReg.IsDecimal() ? dart::kDoubleCid : app.DartIntCid());
			param.valReg = dstReg;
		}

		while (!insn.IsBranch()) {
			INSN_ASSERT(insn.id() == ARM64_INS_MOV);
			INSN_ASSERT(insn.ops(0).type == ARM64_OP_REG && insn.ops(1).type == ARM64_OP_REG && insn.ops(1).reg != CSREG_DART_NULL);
			const auto srcReg = A64::Register{ insn.ops(1).reg };
			auto valParam = fnInfo->State()->MoveRegister(insn.ops(0).reg, srcReg);
			INSN_ASSERT(valParam);
			++insn;
		}
		const auto storingBranchTarget = insn.ops(0).imm;
		++insn;

		const auto num_optional_param = missingBranchTargets.size();
		while (insn.address() != missingBranchTargets.front()) {
			++insn;
		}

		std::vector<FnParamInfo> optParams2;
		while (insn.address() < storingBranchTarget) {
			auto ilValue = processLoadValueInstr(insn);
			if (ilValue) {
				optParams2.push_back(FnParamInfo{ ilValue->dstReg, ilValue->val.TakeValue() });
			}
			else if (insn.id() == ARM64_INS_MOV) {
				INSN_ASSERT(insn.ops(0).type == ARM64_OP_REG && insn.ops(1).type == ARM64_OP_REG);
				const auto srcReg = A64::Register{ insn.ops(1).reg };
				auto itr = std::find_if(optParams2.begin(), optParams2.end(), [&](auto const& param) { return param.valReg == srcReg; });
				INSN_ASSERT(itr != optParams2.end());
				itr->valReg = A64::Register{ insn.ops(0).reg };
				++insn;
			}
			else {
				FATAL("unexpected instruction");
			}
		}

		INSN_ASSERT(optParams2.size() <= fnInfo->params.NumOptionalParam());
		for (int i = fnInfo->params.numFixedParam, j = 0; i < fnInfo->params.NumParam(); i++) {
			if (fnInfo->params[i].valReg.IsSet()) {
				INSN_ASSERT(fnInfo->State()->GetValue(optParams2[j].valReg)->AsParam()->idx == i);
				INSN_ASSERT(j < optParams2.size());
				fnInfo->params[i].val = std::move(optParams2[j].val);
				j++;
			}
		}

		while (true) {
			const auto storeRes = handleStoreLocal(insn);
			if (storeRes.fpOffset == 0)
				break;
			auto val = fnInfo->State()->GetValue(storeRes.srcReg);
			INSN_ASSERT(val);
			INSN_ASSERT(val && val->RawTypeId() == VarValue::Parameter);
			fnInfo->State()->SetLocal(storeRes.fpOffset, val);
		}
	}
}

void FunctionAnalyzer::handleOptionalNamedParameters(AsmIterator& insn, arm64_reg paramCntReg)
{
	if (!(insn.id() == ARM64_INS_LDUR && fnInfo->State()->GetValue(insn.ops(1).reg) == fnInfo->Vars()->ValArgsDesc() && insn.ops(1).mem.disp >= AOT_ArgumentsDescriptor_first_named_entry_offset - dart::kHeapObjectTag))
		return;

	VarValue valNameParamCnt(VtNameParamCnt);
	VarValue valNameParamName(VtNameParamName);
	VarValue valNameCurrParamPosSmi(VtNameCurrParamPosSmi);
	VarValue valNameCurrParamOffset(VtNameCurrParamOffset);
	VarValue valNameArgIdx(vtNameArgIdx);

	int nameParamCnt = 0;
	bool isLastName = false;

	const auto loadNamedParamValue = [&](int expectedOffset, VarValue* val) {
		if (insn.id() == ARM64_INS_ADD && fnInfo->State()->GetValue(insn.ops(1).reg) == &valNameCurrParamOffset) {
			const auto offset = (int)insn.ops(2).imm;
			if (offset == expectedOffset) {
				const auto tmpReg = insn.ops(0).reg;
				++insn;

				INSN_ASSERT(insn.id() == ARM64_INS_ADD);
				INSN_ASSERT(fnInfo->State()->GetValue(insn.ops(1).reg) == fnInfo->Vars()->ValArgsDesc());
				INSN_ASSERT(insn.ops(2).reg == tmpReg && insn.ops(2).ext == ARM64_EXT_SXTW && insn.ops(2).shift.value == 1);
				const auto tmpReg2 = insn.ops(0).reg;
				++insn;

				INSN_ASSERT(insn.id() == ARM64_INS_LDUR);
				INSN_ASSERT(insn.ops(1).mem.base == tmpReg2 && insn.ops(1).mem.disp == sizeof(void*) * 2 - dart::kHeapObjectTag);
				const auto dstReg = ToCapstoneReg(insn.ops(0).reg);
				++insn;

				handleDecompressPointer(insn, dstReg);

				fnInfo->State()->ClearRegister(tmpReg);
				fnInfo->State()->ClearRegister(tmpReg2);
				fnInfo->State()->SetRegister(dstReg, val);
			}
			return offset;
		}
		return -1;
	};

	const auto loadNamedParamValueKnownOffset = [&](int expectedOffset, VarValue* val) {
		if (insn.id() == ARM64_INS_LDUR && fnInfo->State()->GetValue(insn.ops(1).reg) == fnInfo->Vars()->ValArgsDesc() &&
			insn.ops(1).mem.disp >= AOT_ArgumentsDescriptor_first_named_entry_offset - dart::kHeapObjectTag)
		{
			const auto name_offset = AOT_ArgumentsDescriptor_first_named_entry_offset +
				(AOT_ArgumentsDescriptor_named_entry_size * fnInfo->params.NumOptionalParam()) +
				AOT_ArgumentsDescriptor_name_offset - dart::kHeapObjectTag;

			int offset = insn.ops(1).mem.disp - name_offset;
			while (offset >= AOT_ArgumentsDescriptor_named_entry_size) {
				fnInfo->params.add(FnParamInfo{ "required" });
				offset -= AOT_ArgumentsDescriptor_named_entry_size;
			}
			if (offset == expectedOffset) {
				const auto dstReg = ToCapstoneReg(insn.ops(0).reg);
				++insn;

				handleDecompressPointer(insn, dstReg);

				fnInfo->State()->SetRegister(dstReg, val);
			}

			return offset;
		}
		return -1;
	};


	bool isRequired = false;
	while (!isLastName) {
		if (nameParamCnt) {

			if (!isRequired) {
				INSN_ASSERT(insn.id() == ARM64_INS_LSL);
				INSN_ASSERT(fnInfo->State()->GetValue(insn.ops(1).reg) == fnInfo->Vars()->ValCurrNumNameParam());
				INSN_ASSERT(insn.ops(2).imm == 1);
				fnInfo->State()->SetRegister(insn.ops(0).reg, &valNameCurrParamPosSmi);
				++insn;
			}

			while (insn.id() == ARM64_INS_ADD) {
				INSN_ASSERT(fnInfo->State()->GetValue(insn.ops(1).reg) == &valNameCurrParamPosSmi);
				INSN_ASSERT(insn.ops(2).imm == 2);
				fnInfo->State()->MoveRegister(insn.ops(0).reg, insn.ops(1).reg);
				++insn;
			}

			INSN_ASSERT(insn.id() == ARM64_INS_LSL);
			INSN_ASSERT(fnInfo->State()->GetValue(insn.ops(1).reg) == &valNameCurrParamPosSmi);
			INSN_ASSERT(insn.ops(2).imm == 1);
			fnInfo->State()->SetRegister(insn.ops(0).reg, &valNameCurrParamOffset);
			++insn;

			const auto nameOffset = loadNamedParamValue(8, &valNameParamName);
			if (nameOffset == 8)
				isRequired = false;
			else if (nameOffset == 0xa)
				isRequired = true;
			else
				INSN_ASSERT(false);
		}
		else {
			const auto nameOffset = loadNamedParamValueKnownOffset(AOT_ArgumentsDescriptor_name_offset, &valNameParamName);
			if (nameOffset == AOT_ArgumentsDescriptor_name_offset) {
				isRequired = false;
			}
			else if (nameOffset == AOT_ArgumentsDescriptor_position_offset) {
				isRequired = true;
			}
			else {
				INSN_ASSERT(nameOffset == -1);
				INSN_ASSERT(fnInfo->params.NumOptionalParam() > 0);
				break;
			}
		}

		std::string paramName;
		int64_t nameMismatchAddr;
		if (!isRequired) {
			const auto objPoolInstr = getObjectPoolInstruction(insn);
			INSN_ASSERT(objPoolInstr.dstReg == A64::TMP_REG);
			INSN_ASSERT(objPoolInstr.item.ValueTypeId() == dart::kStringCid);
			paramName = objPoolInstr.item.Get<VarString>()->str;

			INSN_ASSERT(insn.id() == ARM64_INS_CMP);
			INSN_ASSERT(fnInfo->State()->GetValue(insn.ops(0).reg) == &valNameParamName && A64::Register{ insn.ops(1).reg } == objPoolInstr.dstReg);
			++insn;

			if (insn.IsBranch(ARM64_CC_EQ)) {
				const auto branchTarget = insn.ops(0).imm;
				++insn;
				INSN_ASSERT(branchTarget == insn.address());
				fnInfo->params.add(FnParamInfo{ std::move(paramName) });
				++nameParamCnt;
				break;
			}

			INSN_ASSERT(insn.IsBranch(ARM64_CC_NE));
			nameMismatchAddr = insn.ops(0).imm;
			++insn;
		}
		else {
			paramName = "required";
			nameMismatchAddr = 0;
		}

		auto doLoadValue = false;
		if (nameParamCnt) {
			const auto posOffset = loadNamedParamValue(0xa, &valNameArgIdx);
			if (posOffset == 0xa)
				doLoadValue = true;
			else
				INSN_ASSERT(posOffset == -1);
		}
		else {
			const auto posOffset = loadNamedParamValueKnownOffset(AOT_ArgumentsDescriptor_position_offset, &valNameArgIdx);
			if (posOffset == AOT_ArgumentsDescriptor_position_offset)
				doLoadValue = true;
			else
				INSN_ASSERT(posOffset == -1);
		}

		if (doLoadValue) {
			INSN_ASSERT(insn.id() == ARM64_INS_SUB);
			INSN_ASSERT(ToCapstoneReg(insn.ops(1).reg) == paramCntReg);
			INSN_ASSERT(fnInfo->State()->GetValue(insn.ops(2).reg) == &valNameArgIdx);
			const auto tmpReg = insn.ops(0).reg;
			++insn;

			INSN_ASSERT(insn.id() == ARM64_INS_ADD);
			INSN_ASSERT(insn.ops(1).reg == CSREG_DART_FP);
			INSN_ASSERT(insn.ops(2).reg == tmpReg && insn.ops(2).ext == ARM64_EXT_SXTW && insn.ops(2).shift.value == 2);
			const auto tmpReg2 = insn.ops(0).reg;
			++insn;

			INSN_ASSERT(insn.id() == ARM64_INS_LDR);
			INSN_ASSERT(insn.ops(0).reg == tmpReg2);
			INSN_ASSERT(insn.ops(1).mem.base == tmpReg2 && insn.ops(1).mem.disp == sizeof(void*));
			const auto valReg = insn.ops(0).reg;
			++insn;

			fnInfo->State()->ClearRegister(tmpReg);
			fnInfo->State()->ClearRegister(tmpReg2);
			auto val = fnInfo->Vars()->ValParam(fnInfo->params.NumParam());
			fnInfo->State()->SetRegister(valReg, val);
			fnInfo->params.add(FnParamInfo{ A64::Register{valReg}, std::move(paramName) });

			const auto storeRes = handleStoreLocal(insn, valReg);
			if (storeRes.fpOffset != 0)
				fnInfo->State()->SetLocal(storeRes.fpOffset, val);
		}
		else {
			fnInfo->params.add(FnParamInfo{ std::move(paramName) });
		}

		if (nameParamCnt) {
			if (insn.id() == ARM64_INS_ADD) {
				INSN_ASSERT(fnInfo->State()->GetValue(insn.ops(1).reg) == &valNameCurrParamPosSmi);
				INSN_ASSERT(insn.ops(2).imm == 2);
				fnInfo->State()->MoveRegister(insn.ops(0).reg, insn.ops(1).reg);
				++insn;
			}
			else {
				isLastName = true;
			}
		}

		if (doLoadValue) {
			const auto& [dstReg, srcReg] = unboxParam(insn, fnInfo->params.back().valReg);
			if (dstReg.IsSet()) {
				const auto val = fnInfo->State()->MoveRegister(dstReg, srcReg);
				INSN_ASSERT(val && val->AsParam()->idx == fnInfo->params.NumParam() - 1);
				fnInfo->params.back().type = app.TypeDb()->Get(dstReg.IsDecimal() ? dart::kDoubleCid : app.DartIntCid());
				fnInfo->params.back().valReg = dstReg;
			}
		}

		if (!isRequired) {
			if (nameParamCnt && !isLastName) {
				if (insn.id() == ARM64_INS_SBFX) {
					INSN_ASSERT(fnInfo->State()->GetValue(insn.ops(1).reg) == &valNameCurrParamPosSmi);
					INSN_ASSERT(insn.ops(2).imm == 1 && insn.ops(3).imm == 0x1f);
					fnInfo->State()->SetRegister(insn.ops(0).reg, fnInfo->Vars()->ValCurrNumNameParam());
					++insn;
				}
			}
		}

		while (insn.id() == ARM64_INS_MOV && insn.ops(1).type == ARM64_OP_REG && insn.ops(1).reg != CSREG_DART_NULL) {
			auto val = fnInfo->State()->MoveRegister(insn.ops(0).reg, insn.ops(1).reg);
			INSN_ASSERT(val);
			++insn;
		}

		if (!nameParamCnt && !isRequired) {
			if (insn.IsMovz() && insn.ops(1).imm == fnInfo->params.NumOptionalParam()) {
				fnInfo->State()->SetRegister(insn.ops(0).reg, fnInfo->Vars()->ValCurrNumNameParam());
				++insn;
			}
			else {
				isLastName = true;
			}
		}

		if (!isRequired) {
			const auto nextParamAddr = [&] {
				if (doLoadValue || nameParamCnt == 0) {
					INSN_ASSERT(insn.IsBranch());
					const auto nextParamAddr = insn.ops(0).imm;
					++insn;
					return nextParamAddr;
				}
				return (int64_t)0;
			}();

			if (nextParamAddr) {
				if (nameMismatchAddr == nextParamAddr) {
					while (insn.address() < nextParamAddr)
						++insn;
					break;
				}
			}

			if (insn.id() == ARM64_INS_SBFX && insn.ops(2).imm == 1 && insn.ops(3).imm == 0x1f) {
				++insn;
			}

			while (insn.id() == ARM64_INS_MOV && insn.ops(1).type == ARM64_OP_REG && insn.ops(1).reg != CSREG_DART_NULL) {
				if (nextParamAddr == 0) {
					auto val = fnInfo->State()->MoveRegister(insn.ops(0).reg, insn.ops(1).reg);
					INSN_ASSERT(val);
				}

				++insn;
			}

			const auto processAssignParamPos0 = [&] {
				if (insn.IsMovz() && fnInfo->State()->GetValue(insn.ops(0).reg) == fnInfo->Vars()->ValCurrNumNameParam() && insn.ops(1).imm == fnInfo->params.NumOptionalParam() - 1) {
					++insn;
					return true;
				}
				return false;
			};

			auto foundAssignParamPos0 = false;
			if (!nameParamCnt && !isLastName) {
				foundAssignParamPos0 = processAssignParamPos0();
			}

			if (doLoadValue) {
				auto il = processLoadValueInstr(insn);
				if (!il)
					break;
				INSN_ASSERT(fnInfo->State()->GetValue(il->dstReg)->AsParam()->idx == fnInfo->params.NumParam() - 1);
				fnInfo->params.back().val = il->val.TakeValue();

				if (nextParamAddr != 0 && insn.address() < nextParamAddr) {
					auto min_diff = (!nameParamCnt && !isLastName && !foundAssignParamPos0) ? 4 : 0;
					if (nextParamAddr - insn.address() > min_diff)
						processLoadValueInstr(insn);
				}
			}

			if (!nameParamCnt && !isLastName && !foundAssignParamPos0) {
				foundAssignParamPos0 = processAssignParamPos0();
			}

			INSN_ASSERT(nextParamAddr == 0 || insn.address() == nextParamAddr);
		}

		if (doLoadValue) {
			const auto storeRes = handleStoreLocal(insn);
			if (storeRes.fpOffset != 0) {
				auto val = fnInfo->State()->GetValue(storeRes.srcReg);
				INSN_ASSERT(val && val->RawTypeId() == VarValue::Parameter);
				fnInfo->State()->SetLocal(storeRes.fpOffset, val);
			}
		}
		if (!isRequired)
			++nameParamCnt;

		if (nameParamCnt) {
			if (insn.id() != ARM64_INS_LSL) {
				break;
			}
		}
	}

	fnInfo->params.isNamedParam = true;
	for (auto& reg : fnInfo->State()->regs) {
		if (reg && reg->RawTypeId() > VtNameBegin && reg->RawTypeId() < VtNameEnd)
			reg = nullptr;
	}
}

void FunctionAnalyzer::handleArgumentsDescriptorTypeArguments(AsmIterator& insn)
{
	if (!(insn.id() == ARM64_INS_LDUR && fnInfo->State()->GetValue(insn.ops(1).reg) == fnInfo->Vars()->ValArgsDesc() && insn.ops(1).mem.disp == AOT_ArgumentsDescriptor_type_args_len_offset - dart::kHeapObjectTag))
		return;

	const auto typeArgLenReg = ToCapstoneReg(insn.ops(0).reg);
	++insn;

	handleExtraDecompressPointer(insn, typeArgLenReg);

	const auto storeTypeArgLenRes = handleStoreLocal(insn, typeArgLenReg);
	if (storeTypeArgLenRes.fpOffset != 0) {
	}

	if (insn.id() == ARM64_INS_CBZ) {
		INSN_ASSERT(ToCapstoneReg(insn.ops(0).reg) == typeArgLenReg);
		const auto contAddr = insn.ops(1).imm;
		++insn;

		INSN_ASSERT(insn.address() == contAddr);
		return;
	}

	INSN_ASSERT(insn.id() == ARM64_INS_CBNZ);
	INSN_ASSERT(ToCapstoneReg(insn.ops(0).reg) == typeArgLenReg);
	const auto loadTypeArgAddr = insn.ops(1).imm;
	++insn;

	INSN_ASSERT(insn.id() == ARM64_INS_MOV);
	INSN_ASSERT(insn.ops(1).reg == CSREG_DART_NULL);
	const auto typeArgReg = insn.ops(0).reg;
	++insn;

	INSN_ASSERT(insn.id() == ARM64_INS_B);
	const auto contAddr = insn.ops(0).reg;
	++insn;

	INSN_ASSERT(insn.address() == loadTypeArgAddr);
	INSN_ASSERT(insn.id() == ARM64_INS_LDUR);
	INSN_ASSERT(fnInfo->State()->GetValue(insn.ops(1).reg) == fnInfo->Vars()->ValArgsDesc() && insn.ops(1).mem.disp == AOT_ArgumentsDescriptor_size_offset - dart::kHeapObjectTag);
	const auto sizeReg = ToCapstoneReg(insn.ops(0).reg);
	fnInfo->State()->ClearRegister(sizeReg);
	++insn;

	handleExtraDecompressPointer(insn, sizeReg);

	INSN_ASSERT(insn.id() == ARM64_INS_ADD);
	INSN_ASSERT(insn.ops(1).reg == CSREG_DART_FP);
	INSN_ASSERT(ToCapstoneReg(insn.ops(2).reg) == sizeReg && insn.ops(2).ext == ARM64_EXT_SXTW && insn.ops(2).shift.value == 2);
	const auto tmpReg = insn.ops(0).reg;
	fnInfo->State()->ClearRegister(tmpReg);
	++insn;

	INSN_ASSERT(insn.id() == ARM64_INS_LDR);
	INSN_ASSERT(insn.ops(1).mem.base == tmpReg && insn.ops(1).mem.disp == 0x10);
	INSN_ASSERT(insn.ops(0).reg == tmpReg);
	++insn;

	if (tmpReg != typeArgReg) {
		INSN_ASSERT(insn.id() == ARM64_INS_MOV);
		INSN_ASSERT(insn.ops(0).reg == typeArgReg);
		INSN_ASSERT(insn.ops(1).reg == tmpReg);
		++insn;
	}
	fnInfo->typeArgumentReg = typeArgReg;
	fnInfo->State()->ClearRegister(fnInfo->typeArgumentReg);

	INSN_ASSERT(insn.address() == contAddr);
	if (insn.id() == ARM64_INS_CBNZ && ToCapstoneReg(insn.ops(0).reg) == typeArgLenReg) {
		const auto elseAddr = insn.ops(1).imm;
		++insn;

		const auto objPoolInstr = getObjectPoolInstruction(insn);
		INSN_ASSERT(objPoolInstr.item.ValueTypeId() == dart::kTypeArgumentsCid);
		fnInfo->State()->ClearRegister(objPoolInstr.dstReg);

		INSN_ASSERT(insn.IsBranch());
		const auto contAddr = insn.ops(0).imm;
		++insn;

		INSN_ASSERT(elseAddr == insn.address());
		INSN_ASSERT(insn.id() == ARM64_INS_MOV);
		INSN_ASSERT(insn.ops(1).reg == typeArgReg);
		const auto finalTypeArgReg = A64::Register{ insn.ops(0).reg };
		INSN_ASSERT(finalTypeArgReg == objPoolInstr.dstReg);
		++insn;

		INSN_ASSERT(contAddr == insn.address());
		fnInfo->typeArgumentReg = finalTypeArgReg;
	}

	fnInfo->State()->ClearRegister(fnInfo->typeArgumentReg);
}

static const A64::Register allowedParameterRegisters[] = {
	A64::Register::R1, A64::Register::R2, A64::Register::R3,
	A64::Register::R5, A64::Register::R6, A64::Register::R7,
	A64::Register::V0, A64::Register::V1, A64::Register::V2, A64::Register::V3,
	A64::Register::V4, A64::Register::V5, A64::Register::V6, A64::Register::V7,
};

static bool isAllowedParameterRegister(A64::Register reg)
{
	const auto eptr = std::end(allowedParameterRegisters);
	return std::find(std::begin(allowedParameterRegisters), eptr, reg) != eptr;
}

static bool isTmpForwardingRegister(A64::Register reg)
{
	return reg == A64::Register::TMP || reg == A64::Register::TMP2 || reg == A64::Register::VTMP;
}

void FunctionAnalyzer::handleParameterRegisters(AsmIterator& insn)
{

	struct TmpParamReg {
		A64::Register reg;
		int localOffset;
		A64::Register dstReg;
	};
	std::vector<TmpParamReg> paramRegs;
	const auto getParamReg = [&](A64::Register reg) -> TmpParamReg& {
		for (auto& param : paramRegs) {
			if (param.dstReg == reg)
				return param;
		}
		for (auto& param : paramRegs) {
			if (param.reg == reg)
				return param;
		}
		paramRegs.push_back(TmpParamReg{ .reg = reg });
		return paramRegs.back();
	};

	std::unordered_map<int32_t, A64::Register> aliases;
	const auto clearAliases = [&] {
		aliases.clear();
	};
	const auto killAlias = [&](A64::Register reg) {
		aliases.erase((int32_t)reg.value());
	};
	const auto setAlias = [&](A64::Register dst, A64::Register src) {
		aliases[(int32_t)dst.value()] = src;
	};
	const auto resolveAlias = [&](A64::Register reg) {
		A64::Register curr = reg;
		for (int i = 0; i < 8; i++) {
			const auto it = aliases.find((int32_t)curr.value());
			if (it == aliases.end() || it->second == curr)
				break;
			curr = it->second;
		}
		return curr;
	};

	while (true) {
		if (insn.id() == ARM64_INS_MOV && insn.ops(1).type == ARM64_OP_REG && insn.ops(1).reg != CSREG_DART_NULL) {
			const A64::Register srcReg = insn.ops(1).reg;
			const A64::Register dstReg = insn.ops(0).reg;
			const auto resolvedSrcReg = resolveAlias(srcReg);
			const bool isResolvedParamReg = isAllowedParameterRegister(resolvedSrcReg);
			const bool isResolvedTmpReg = isTmpForwardingRegister(resolvedSrcReg);
			if (!isResolvedParamReg && !isResolvedTmpReg)
				break;

			killAlias(dstReg);

			if (isResolvedParamReg) {
				auto& param = getParamReg(resolvedSrcReg);
				if (param.dstReg.IsSet()) {
					if (param.reg == resolvedSrcReg && (srcReg == resolvedSrcReg || param.dstReg == srcReg)) {
						setAlias(dstReg, resolvedSrcReg);
						++insn;
						continue;
					}
					if (param.dstReg != srcReg && param.dstReg != resolvedSrcReg) {
						clearAliases();
						break;
					}
				}
				param.dstReg = dstReg;
				setAlias(dstReg, resolvedSrcReg);
			}
			else {
				setAlias(dstReg, resolvedSrcReg);
			}

			++insn;
		}
		else if (insn.id() == ARM64_INS_STUR && insn.ops(1).mem.base == CSREG_DART_FP && insn.ops(1).mem.disp < 0) {
			const A64::Register srcReg = insn.ops(0).reg;
			const auto resolvedSrcReg = resolveAlias(srcReg);
			if (fnInfo->State()->GetValue(srcReg) != nullptr || !isAllowedParameterRegister(resolvedSrcReg))
				break;

			const int offset = insn.ops(1).mem.disp;
			auto& param = getParamReg(resolvedSrcReg);
			INSN_ASSERT(param.localOffset == 0);
			param.localOffset = offset;
			++insn;
		}
		else {
			if (insn.id() == ARM64_INS_BL || insn.id() == ARM64_INS_BLR || insn.id() == ARM64_INS_RET || insn.IsBranch())
				clearAliases();
			else if (insn.op_count() > 0 && insn.ops(0).type == ARM64_OP_REG)
				killAlias(A64::Register{ insn.ops(0).reg });
			break;
		}
	}
	clearAliases();

	if (!paramRegs.empty()) {
		std::ranges::sort(paramRegs, {}, &TmpParamReg::reg);

		for (auto& tmpParam : paramRegs) {
			const auto argIdx = fnInfo->params.numFixedParam;
			auto val = fnInfo->Vars()->ValParam(argIdx);
			if (tmpParam.localOffset != 0)
				fnInfo->State()->SetLocal(tmpParam.localOffset, val);
			fnInfo->State()->SetRegister(tmpParam.dstReg.IsSet() ? tmpParam.dstReg : tmpParam.reg, val);
			fnInfo->params.addFixedParam(FnParamInfo{ tmpParam.reg, tmpParam.dstReg, tmpParam.localOffset });
		}

		if (!dartFn->IsStatic() && paramRegs[0].reg == A64::Register::R1) {
			fnInfo->params[0].name = "this";
			fnInfo->params[0].type = dartFn->Class().DeclarationType();
		}
	}
}

std::unique_ptr<SetupParametersInstr> FunctionAnalyzer::processPrologueParametersInstr(AsmIterator& insn, uint64_t endPrologueAddr)
{
	auto optionalParamCntReg = ARM64_REG_INVALID;
	auto firstParamReg = ARM64_REG_INVALID;
	InsnMarker marker(insn);

	const auto handleInitialization = [&] {
		while (true) {
			auto il = processLoadValueInstr(insn);
			if (!il)
				break;
			fnInfo->State()->SetRegister(il->dstReg, il->val.Value());
			fnInfo->Vars()->pending_ils.push_back(std::move(il));
		}
	};

	const bool needSuspendState = [&] {
		if (insn.id() == ARM64_INS_STUR && insn.ops(0).reg == CSREG_DART_NULL && insn.ops(1).mem.base == CSREG_DART_FP && insn.ops(1).mem.disp == -8) {
			++insn;
			return true;
		}
		return false;
	}();

	const auto mightBeFirstParamOffset = [&](int offset) {
		if (offset <= sizeof(void*))
			return false;
		if (dartFn->NumParam() != 0) {
			if (offset != dartFn->FirstParamOffset())
				return false;
		}
		else if (offset != fnInfo->asmTexts.MaxParamStackOffset())
			return false;
		return true;
	};

	if (needSuspendState || dartFn->IsAsync()) {
		if (dartFn->IsAsync())
			INSN_ASSERT(needSuspendState);
		else
			;

		if (insn.id() == ARM64_INS_MOV && insn.ops(1).reg == CSREG_DART_NULL) {
			auto item = VarItem{ VarStorage::Immediate, new VarNull() };
			fnInfo->Vars()->pending_ils.push_back(std::make_unique<LoadValueInstr>(AddrRange(insn.address(), insn.NextAddress()), A64::Register{insn.ops(0).reg}, std::move(item)));
			++insn;
		}

		if (insn.IsMovz() && insn.ops(1).imm == 0) {
			optionalParamCntReg = insn.ops(0).reg;
			++insn;
		}

		handleParameterRegisters(insn);
	}
	else {
		handleParameterRegisters(insn);

		if (dartFn->IsClosure()) {
			handleInitialization();

			if (insn.id() == ARM64_INS_LDR && insn.ops(1).mem.base == CSREG_DART_FP && insn.ops(1).mem.disp > 0) {
				const auto firstParamOffset = insn.ops(1).mem.disp;
				if (!mightBeFirstParamOffset(firstParamOffset))
					return nullptr;
				firstParamReg = insn.ops(0).reg;
				fnInfo->State()->SetRegister(A64::Register{ insn.ops(0).reg }, fnInfo->Vars()->ValParam(0));
				++insn;
			}
		}
	}

	const auto argsDescReg = [&] {
		auto argsDescReg = ARM64_REG_INVALID;
		if (fnInfo->State()->GetValue(CSREG_ARGS_DESC) == nullptr) {
			const auto storeArgsDescRes = handleStoreLocal(insn, CSREG_ARGS_DESC);
			if (storeArgsDescRes.fpOffset != 0) {
				fnInfo->State()->SetLocal(storeArgsDescRes.fpOffset, fnInfo->Vars()->ValArgsDesc());
				argsDescReg = CSREG_ARGS_DESC;
			}

			if (insn.id() == ARM64_INS_MOV && insn.ops(1).reg == CSREG_ARGS_DESC) {
				argsDescReg = insn.ops(0).reg;
				++insn;
			}
			else if (insn.id() == ARM64_INS_LDUR && insn.ops(1).mem.base == CSREG_ARGS_DESC) {
				argsDescReg = CSREG_ARGS_DESC;
			}
			if (argsDescReg != ARM64_REG_INVALID)
				fnInfo->State()->SetRegister(argsDescReg, fnInfo->Vars()->ValArgsDesc());
		}
		return argsDescReg;
	}();

	if (argsDescReg == ARM64_REG_INVALID && !needSuspendState && !dartFn->IsClosure() && fnInfo->params.empty())
		return nullptr;

	int fixedParamCnt = 0;
	auto paramCntReg = ARM64_REG_INVALID;
	if (optionalParamCntReg == ARM64_REG_INVALID && argsDescReg != ARM64_REG_INVALID) {
		if (insn.id() == ARM64_INS_LDUR && insn.ops(1).mem.base == argsDescReg && insn.ops(1).mem.disp == AOT_ArgumentsDescriptor_count_offset - dart::kHeapObjectTag)
		{
			paramCntReg = ToCapstoneReg(insn.ops(0).reg);
			++insn;

			handleExtraDecompressPointer(insn, paramCntReg);

			ASSERT(fnInfo->useFramePointer);

			if (insn.id() == ARM64_INS_SUB && insn.ops(1).reg == paramCntReg) {
				fixedParamCnt = (int)insn.ops(2).imm >> dart::kSmiTagShift;
				optionalParamCntReg = insn.ops(0).reg;
				++insn;
			}
		}
	}

	if (optionalParamCntReg != ARM64_REG_INVALID) {
		handleFixedParameters(insn, optionalParamCntReg, fixedParamCnt);
	}

	if (argsDescReg != ARM64_REG_INVALID) {
		if (insn.id() == ARM64_INS_CMP) {
			handleOptionalPositionalParameters(insn, fixedParamCnt > 0 ? optionalParamCntReg : paramCntReg);
		}
		else {
			handleOptionalNamedParameters(insn, paramCntReg);
		}
	}

	while (insn.id() == ARM64_INS_LDUR && insn.ops(1).mem.base == CSREG_DART_FP && insn.ops(1).mem.disp < 0) {
		fnInfo->State()->SetRegister(insn.ops(0).reg, fnInfo->State()->GetLocal(insn.ops(1).mem.disp));
		++insn;
	}

	if (dartFn->IsClosure() && insn.id() == ARM64_INS_LDUR && insn.ops(1).mem.disp == AOT_Closure_context_offset - dart::kHeapObjectTag) {
		const auto arg1Reg = [&] {
			if (fnInfo->params.numFixedParam > 0) {
				return fnInfo->params[0].valReg;
			}
			else {
				INSN_ASSERT(fnInfo->params.empty());
				return A64::Register{ firstParamReg };
			}
			}();

			if (arg1Reg.IsSet()) {
				INSN_ASSERT(A64::Register{ insn.ops(1).mem.base } == arg1Reg);
				const auto contextReg = ToCapstoneReg(insn.ops(0).reg);
				++insn;

				handleDecompressPointer(insn, contextReg);
				fnInfo->closureContextReg = contextReg;
				fnInfo->State()->ClearRegister(fnInfo->closureContextReg);

				const auto storeContextRes = handleStoreLocal(insn, contextReg);
				if (storeContextRes.fpOffset != 0) {
					fnInfo->closureContextLocalOffset = storeContextRes.fpOffset;
				}
			}
	}

	if (argsDescReg != ARM64_REG_INVALID)
		handleArgumentsDescriptorTypeArguments(insn);

	if (endPrologueAddr != 0 && insn.address() < endPrologueAddr)
		handleInitialization();

	if (dartFn->IsClosure()) {
		const auto save_ins = insn.Current();

		const auto arg1Reg = [&] {
			arm64_reg a1reg = ARM64_REG_INVALID;
			if (insn.id() == ARM64_INS_LDR && insn.ops(1).mem.base == CSREG_DART_FP && mightBeFirstParamOffset(insn.ops(1).mem.disp)) {
				a1reg = insn.ops(0).reg;
				++insn;
			}
			if (insn.id() == ARM64_INS_LDUR && insn.ops(1).mem.disp == AOT_Closure_delayed_type_arguments_offset - dart::kHeapObjectTag) {
				if (a1reg != ARM64_REG_INVALID) {
					return A64::Register{ a1reg };
				}
				else if (fnInfo->params.numFixedParam > 0) {
					return fnInfo->params[0].valReg;
				}
				else {
					INSN_ASSERT(fnInfo->params.empty());
					return A64::Register{ firstParamReg };
				}
			}
			return A64::Register{};
		}();

		if (arg1Reg.IsSet() && A64::Register{ insn.ops(1).mem.base } == arg1Reg) {
			fnInfo->State()->SetRegister(arg1Reg, fnInfo->Vars()->ValParam(0));
			auto delayedTypeArgReg = ToCapstoneReg(insn.ops(0).reg);
			++insn;

			handleDecompressPointer(insn, delayedTypeArgReg);

#ifdef NO_METHOD_EXTRACTOR_STUB
			INSN_ASSERT(insn.id() == ARM64_INS_LDR);
			INSN_ASSERT(insn.ops(1).mem.base == CSREG_DART_THR && insn.ops(1).mem.disp == dart::Thread::empty_type_arguments_offset());
			A64::Register emptyTypeArgReg = insn.ops(0).reg;
			++insn;
#else
			auto ppEmptyTypeArg = getObjectPoolInstruction(insn);
			INSN_ASSERT(ppEmptyTypeArg.IsSet());
			INSN_ASSERT(ppEmptyTypeArg.item.ValueTypeId() == dart::kTypeArgumentsCid);
			A64::Register emptyTypeArgReg = ppEmptyTypeArg.dstReg;
#endif

			INSN_ASSERT(insn.id() == ARM64_INS_CMP);
			INSN_ASSERT(ToCapstoneReg(insn.ops(0).reg) == delayedTypeArgReg);
			INSN_ASSERT(A64::Register{ insn.ops(1).reg } == emptyTypeArgReg);
			fnInfo->State()->ClearRegister(emptyTypeArgReg);
			++insn;

			if (fnInfo->typeArgumentReg.IsSet() && insn.IsBranch(ARM64_CC_NE)) {
				const auto neAddr = insn.ops(0).imm;
				++insn;

				INSN_ASSERT(insn.id() == ARM64_INS_MOV);
				INSN_ASSERT(A64::Register{ insn.ops(1).reg } == fnInfo->typeArgumentReg);
				const auto tmpReg = insn.ops(0).reg;
				fnInfo->State()->ClearRegister(tmpReg);
				++insn;

				if (insn.address() == neAddr) {
					delayedTypeArgReg = tmpReg;
					fnInfo->typeArgumentReg = tmpReg;
				}
				else {
					INSN_ASSERT(insn.IsBranch());
					const auto contAddr = insn.ops(0).imm;
					++insn;

					INSN_ASSERT(insn.address() == neAddr);

					INSN_ASSERT(insn.id() == ARM64_INS_MOV);
					INSN_ASSERT(insn.ops(1).reg == delayedTypeArgReg);
					INSN_ASSERT(insn.ops(0).reg == tmpReg);
					delayedTypeArgReg = insn.ops(0).reg;
					++insn;

					fnInfo->typeArgumentReg = delayedTypeArgReg;

					INSN_ASSERT(insn.address() == contAddr);
				}
			}
			else {
				INSN_ASSERT(insn.IsBranch(ARM64_CC_EQ));
				const auto contAddr = insn.ops(0).imm;
				++insn;

				INSN_ASSERT(insn.id() == ARM64_INS_MOV);
				INSN_ASSERT(insn.ops(1).reg == delayedTypeArgReg);
				delayedTypeArgReg = insn.ops(0).reg;
				++insn;

				INSN_ASSERT(!fnInfo->typeArgumentReg.IsSet() || fnInfo->typeArgumentReg == A64::Register{ delayedTypeArgReg });
				fnInfo->typeArgumentReg = delayedTypeArgReg;

				INSN_ASSERT(insn.address() == contAddr);
			}

			fnInfo->State()->ClearRegister(fnInfo->typeArgumentReg);
		}
		else {
			insn.SetCurrent(save_ins);
		}
	}

	if (insn.address() < endPrologueAddr) {
		std::unordered_map<int32_t, A64::Register> aliases;
		std::unordered_map<int32_t, int> incomingParamIdxByReg;
		std::unordered_set<int> usedParamIdx;
		const auto clearAliases = [&] {
			aliases.clear();
		};
		const auto killAlias = [&](A64::Register reg) {
			aliases.erase((int32_t)reg.value());
		};
		const auto setAlias = [&](A64::Register dst, A64::Register src) {
			aliases[(int32_t)dst.value()] = src;
		};
		const auto resolveAlias = [&](A64::Register reg) {
			A64::Register curr = reg;
			for (int i = 0; i < 8; i++) {
				const auto it = aliases.find((int32_t)curr.value());
				if (it == aliases.end() || it->second == curr)
					break;
				curr = it->second;
			}
			return curr;
		};
		const auto findExistingParamIdx = [&](A64::Register reg) {
			for (int i = 0; i < fnInfo->params.NumParam(); i++) {
				if (fnInfo->params[i].valReg == reg || fnInfo->params[i].paramReg == reg)
					return i;
			}
			return -1;
		};
		const auto ensureIncomingParamValue = [&](A64::Register reg) -> VarValue* {
			const auto rootReg = resolveAlias(reg);
			if (!isAllowedParameterRegister(rootReg))
				return nullptr;

			int paramIdx = -1;
			const auto key = (int32_t)rootReg.value();
			const auto it = incomingParamIdxByReg.find(key);
			if (it != incomingParamIdxByReg.end()) {
				paramIdx = it->second;
			}
			else {
				paramIdx = findExistingParamIdx(rootReg);
				if (paramIdx < 0) {
					for (int i = 0; i < fnInfo->params.NumParam(); i++) {
						if (usedParamIdx.find(i) == usedParamIdx.end()) {
							paramIdx = i;
							break;
						}
					}
				}
				if (paramIdx < 0) {
					paramIdx = fnInfo->params.NumParam();
					fnInfo->params.add(FnParamInfo{ rootReg });
				}
				else if (!fnInfo->params[paramIdx].valReg.IsSet()) {
					fnInfo->params[paramIdx].valReg = rootReg;
				}
				incomingParamIdxByReg[key] = paramIdx;
				usedParamIdx.insert(paramIdx);
			}
			return fnInfo->Vars()->ValParam(paramIdx);
		};
		const auto resolveParamValueFromReg = [&](A64::Register reg) -> VarValue* {
			if (auto val = fnInfo->State()->GetValue(reg); val != nullptr)
				return val;
			const auto rootReg = resolveAlias(reg);
			if (rootReg != reg) {
				if (auto val = fnInfo->State()->GetValue(rootReg); val != nullptr)
					return val;
			}
			return ensureIncomingParamValue(rootReg);
		};

		while (insn.id() == ARM64_INS_LDR && insn.ops(1).mem.base == CSREG_DART_FP && insn.ops(1).mem.disp > 0) {
			const auto dst_reg = insn.ops(0).reg;
			const auto offset = insn.ops(1).mem.disp;
			++insn;
			if (insn.id() == ARM64_INS_LDUR && insn.ops(1).mem.base == dst_reg && insn.ops(1).mem.disp > 0) {
				--insn;
				break;
			}
			const auto paramIdx = (offset - sizeof(void*) * 2) / sizeof(void*);
			fnInfo->State()->SetRegister(dst_reg, fnInfo->Vars()->ValParam(paramIdx));
		}
		handleInitialization();

		while (true) {
			bool progressed = false;

			while (insn.id() == ARM64_INS_MOV && insn.ops(1).type == ARM64_OP_REG && insn.ops(1).reg != CSREG_DART_NULL) {
				const A64::Register srcReg = insn.ops(1).reg;
				const A64::Register dstReg = insn.ops(0).reg;
				killAlias(dstReg);
				auto val = resolveParamValueFromReg(srcReg);
				if (val == nullptr) {
					const auto rootReg = resolveAlias(srcReg);
					if (!isTmpForwardingRegister(rootReg)) {
						clearAliases();
						break;
					}
					setAlias(dstReg, rootReg);
					fnInfo->State()->ClearRegister(dstReg);
				}
				else {
					const auto rootReg = resolveAlias(srcReg);
					fnInfo->State()->SetRegister(dstReg, val);
					if (dstReg != srcReg)
						fnInfo->State()->ClearRegister(srcReg);
					setAlias(dstReg, rootReg);
				}
				++insn;
				progressed = true;
			}

			while (true) {
				const auto storeRes = handleStoreLocal(insn);
				if (storeRes.fpOffset == 0)
					break;
				progressed = true;

				const auto srcReg = A64::Register{ storeRes.srcReg };
				if (fnInfo->typeArgumentReg == srcReg) {
					fnInfo->typeArgumentLocalOffset = storeRes.fpOffset;
				}
				else if (fnInfo->closureContextReg == srcReg) {
					fnInfo->closureContextLocalOffset = storeRes.fpOffset;
				}
				else {
					auto val = resolveParamValueFromReg(srcReg);
					if (val != nullptr) {
						fnInfo->State()->SetLocal(storeRes.fpOffset, val);
					}
				}
			}

			if (!progressed)
				break;
			if (insn.id() == ARM64_INS_BL || insn.id() == ARM64_INS_BLR || insn.id() == ARM64_INS_RET || insn.IsBranch()) {
				clearAliases();
				break;
			}
		}
		clearAliases();
	}

	const auto ensureParamInfoSize = [&](int idx) {
		while (fnInfo->params.NumParam() <= idx) {
			fnInfo->params.add(FnParamInfo{});
		}
	};
	for (auto& param : fnInfo->params.params) {
		param.valReg = A64::Register{};
		param.localOffset = 0;
	}
	const auto& local_vars = fnInfo->State()->local_vars;
	for (auto i = 0; i < local_vars.size(); i++) {
		const auto local = local_vars[i];
		if (local && local->RawTypeId() == VarValue::Parameter) {
			const auto idx = local->AsParam()->idx;
			ensureParamInfoSize(idx);
			fnInfo->params[idx].localOffset = AnalyzingState::indexToLocalOffset(i);
		}
	}
	auto& regs = fnInfo->State()->regs;
	for (auto i = 0; i < A64::Register::kNumberOfRegisters; i++) {
		if (regs[i] && regs[i]->RawTypeId() == VarValue::Parameter) {
			const auto idx = regs[i]->AsParam()->idx;
			ensureParamInfoSize(idx);
			fnInfo->params[idx].valReg = A64::Register::Value{ i };
		}
	}

	if (insn.Current() == marker.Insn())
		return nullptr;

	return std::make_unique<SetupParametersInstr>(insn.Wrap(marker.Take()), &fnInfo->params);
}

std::unique_ptr<ILInstr> FunctionAnalyzer::processObjectPoolInstr(AsmIterator& insn)
{
	const auto ins0_addr = insn.address();
	auto objPoolInstr = getObjectPoolInstruction(insn);
	if (objPoolInstr.IsSet()) {
		if (objPoolInstr.isWrite) {
			return std::make_unique<StoreObjectPoolInstr>(insn.Wrap(ins0_addr), objPoolInstr.dstReg, objPoolInstr.item.storage.offset);
		}
		return std::make_unique<LoadValueInstr>(insn.Wrap(ins0_addr), objPoolInstr.dstReg, std::move(objPoolInstr.item));
	}

	return nullptr;
}

std::unique_ptr<LoadValueInstr> FunctionAnalyzer::processLoadValueNoObjectPoolInstr(AsmIterator& insn)
{
	const auto ins0_addr = insn.address();

	int64_t imm = 0;
	A64::Register dstReg;
	if (insn.IsMovz()) {
		imm = insn.ops(1).imm;
		const auto tmpReg = insn.ops(0).reg;
		++insn;

		if (insn.id() == ARM64_INS_MOVK && insn.ops(0).reg == tmpReg && insn.ops(1).shift.value == 16) {
			imm |= insn.ops(1).imm << 16;
			++insn;
		}
		dstReg = tmpReg;
	}
	else if (insn.id() == ARM64_INS_MOV && insn.ops(1).reg == CSREG_DART_NULL) {
		auto item = VarItem{ VarStorage::Immediate, new VarNull() };
		const auto dstReg = A64::Register{ insn.ops(0).reg };
		++insn;
		return std::make_unique<LoadValueInstr>(insn.Wrap(ins0_addr), dstReg, std::move(item));
	}
	else if (insn.id() == ARM64_INS_ORR && insn.ops(1).reg == ARM64_REG_XZR && insn.ops(2).type == ARM64_OP_IMM) {
		imm = insn.ops(2).imm;
		dstReg = insn.ops(0).reg;
		++insn;
	}
	else if (insn.id() == ARM64_INS_MOVN) {
		imm = insn.ops(1).imm << insn.ops(1).shift.value;
		imm = ~imm;
		dstReg = insn.ops(0).reg;
		++insn;
	}
	else if (insn.id() == ARM64_INS_EOR && insn.ops(0).reg == insn.ops(1).reg && insn.ops(0).reg == insn.ops(2).reg) {
		dstReg = insn.ops(0).reg;
		++insn;
		if (dstReg.IsDecimal()) {
			auto item = VarItem{ VarStorage::Immediate, new VarDouble{0, VarValue::NativeDouble} };
			return std::make_unique<LoadValueInstr>(insn.Wrap(ins0_addr), dstReg, std::move(item));
		}
	}
	else if (insn.id() == ARM64_INS_FMOV) {
		auto item = VarItem{ VarStorage::Immediate, new VarDouble{insn.ops(1).fp, VarValue::NativeDouble} };
		const auto dstReg = A64::Register{ insn.ops(0).reg };
		++insn;
		return std::make_unique<LoadValueInstr>(insn.Wrap(ins0_addr), dstReg, std::move(item));
	}

	if (dstReg.IsSet()) {
		auto item = VarItem{ VarStorage::Immediate, new VarInteger{imm, VarValue::NativeInt} };
		return std::make_unique<LoadValueInstr>(insn.Wrap(ins0_addr), dstReg, std::move(item));
	}

	return nullptr;
}

std::unique_ptr<LoadValueInstr> FunctionAnalyzer::processLoadValueInstr(AsmIterator& insn)
{
	auto il = processObjectPoolInstr(insn);
	if (il != nullptr) {
		if (il->Kind() != ILInstr::LoadValue)
			return nullptr;
		return std::unique_ptr<LoadValueInstr>((LoadValueInstr*)il.release());
	}

	return processLoadValueNoObjectPoolInstr(insn);
}

std::unique_ptr<ClosureCallInstr> FunctionAnalyzer::processClosureCallInstr(AsmIterator& insn)
{
	if (insn.id() == ARM64_INS_LDUR && insn.ops(0).reg == ARM64_REG_X2 && insn.ops(1).mem.base == ARM64_REG_X0 && insn.ops(1).mem.disp == AOT_Closure_entry_point_offset - dart::kHeapObjectTag) {
		auto il = fnInfo->LastIL();
		if (il->Kind() == ILInstr::LoadValue) {
			auto loadIL = reinterpret_cast<LoadValueInstr*>(il);
			if (loadIL->dstReg == A64::Register{ dart::ARGS_DESC_REG } && loadIL->val.ValueTypeId() == dart::kArrayCid) {
				const auto& arr = dart::Array::Handle(loadIL->val.Get<VarArray>()->ptr);
				const auto arrLen = arr.Length();
				const auto namedParamCmt = (arrLen - 5) / 2;
				auto arrPtr = dart::Array::DataOf(arr.ptr());

				INSN_ASSERT(!arrPtr->IsHeapObject());
				const auto typeArgLen = dart::RawSmiValue(dart::Smi::RawCast(arrPtr->DecompressSmi()));
				arrPtr++;
				INSN_ASSERT(!arrPtr->IsHeapObject());
				const auto argCnt = dart::RawSmiValue(dart::Smi::RawCast(arrPtr->DecompressSmi()));
				INSN_ASSERT(argCnt > 0);
				arrPtr++;
				INSN_ASSERT(!arrPtr->IsHeapObject());
				const auto argSize = dart::RawSmiValue(dart::Smi::RawCast(arrPtr->DecompressSmi()));
				INSN_ASSERT(argCnt == argSize);
				arrPtr++;
				INSN_ASSERT(!arrPtr->IsHeapObject());
				const auto positionalArgCnt = dart::RawSmiValue(dart::Smi::RawCast(arrPtr->DecompressSmi()));
				INSN_ASSERT(argCnt == positionalArgCnt + namedParamCmt);

				++insn;

				INSN_ASSERT(insn.id() == ARM64_INS_BLR);
				INSN_ASSERT(insn.ops(0).reg == ARM64_REG_X2);
				++insn;

				const auto ins0_addr = il->Start();
				fnInfo->RemoveLastIL();

				return std::make_unique<ClosureCallInstr>(insn.Wrap(ins0_addr), (int32_t)argCnt, (int32_t)typeArgLen);
			}
		}
	}

	return nullptr;
}

std::unique_ptr<MoveRegInstr> FunctionAnalyzer::processMoveRegInstr(AsmIterator& insn)
{
	if (insn.id() == ARM64_INS_MOV && insn.ops(1).type == ARM64_OP_REG) {
		const auto ins0_addr = insn.address();
		const A64::Register dstReg = insn.ops(0).reg;
		const A64::Register srcReg = insn.ops(1).reg;
		++insn;
		return std::make_unique<MoveRegInstr>(insn.Wrap(ins0_addr), dstReg, srcReg);
	}
	return nullptr;
}

std::unique_ptr<DecompressPointerInstr> FunctionAnalyzer::processDecompressPointerInstr(AsmIterator& insn)
{
	if (insn.id() == ARM64_INS_ADD && insn.ops(2).reg == CSREG_DART_HEAP && insn.ops(2).shift.value == 32) {
		INSN_ASSERT(insn.ops(0).reg == insn.ops(1).reg);
		const auto reg = A64::Register{ insn.ops(0).reg };
		const auto ins0_addr = insn.address();
		++insn;
		return std::make_unique<DecompressPointerInstr>(insn.Wrap(ins0_addr), reg);
	}
	return nullptr;
}

std::unique_ptr<SaveRegisterInstr> FunctionAnalyzer::processSaveRegisterInstr(AsmIterator& insn)
{
	if (insn.id() == ARM64_INS_STR && insn.ops(1).mem.base == CSREG_DART_SP && insn.writeback()) {
		INSN_ASSERT(insn.ops(1).mem.disp == -GetCsRegSize(insn.ops(0).reg));
		const auto reg = A64::Register{ insn.ops(0).reg };
		const auto ins0_addr = insn.address();
		++insn;
		return std::make_unique<SaveRegisterInstr>(insn.Wrap(ins0_addr), reg);
	}
	return nullptr;
}

std::unique_ptr<RestoreRegisterInstr> FunctionAnalyzer::processLoadSavedRegisterInstr(AsmIterator& insn)
{
	if (insn.id() == ARM64_INS_LDR && insn.ops(1).mem.base == CSREG_DART_SP && insn.writeback()) {
		INSN_ASSERT(insn.ops(2).imm == GetCsRegSize(insn.ops(0).reg));
		const auto reg = A64::Register{ insn.ops(0).reg };
		const auto ins0_addr = insn.address();
		++insn;
		return std::make_unique<RestoreRegisterInstr>(insn.Wrap(ins0_addr), reg);
	}
	return nullptr;
}

std::unique_ptr<InitAsyncInstr> FunctionAnalyzer::processInitAsyncInstr(AsmIterator& insn)
{
#ifdef HAS_INIT_ASYNC
	if (insn.id() == ARM64_INS_BL && insn.ops(0).type == ARM64_OP_IMM) {
		const auto fn = app.GetFunction(insn.ops(0).imm);
		if (fn && fn->IsStub()) {
			const auto stub = fn->AsStub();
			auto il = fnInfo->LastIL();
			if (stub->kind == DartStub::InitAsyncStub && il->Kind() == ILInstr::LoadValue) {
				auto ilLoad = reinterpret_cast<LoadValueInstr*>(il);
				INSN_ASSERT(ilLoad->dstReg == A64::Register::R0);
				auto& item = ilLoad->GetValue();
				DartType* returnType;
				if (item.ValueTypeId() == dart::kNullCid) {
					returnType = app.TypeDb()->FindOrAdd(app.DartFutureCid(), &DartTypeArguments::Null);
				}
				else {
					INSN_ASSERT(item.ValueTypeId() == dart::kTypeArgumentsCid);
					auto typeArg = &(item.Get<VarTypeArgument>()->typeArgs);
					returnType = app.TypeDb()->FindOrAdd(app.DartFutureCid(), typeArg);
				}
				fnInfo->returnType = returnType;
				const auto start = il->Start();
				fnInfo->RemoveLastIL();
				setAsmTextDataCall(insn.address(), (uint64_t)insn.ops(0).imm);
				++insn;
				return std::make_unique<InitAsyncInstr>(insn.Wrap(start), returnType);
			}
		}
	}
#endif

	return nullptr;
}

std::unique_ptr<CallInstr> FunctionAnalyzer::processCallInstr(AsmIterator& insn)
{
	if (insn.id() == ARM64_INS_BL) {
		if (insn.ops(0).type == ARM64_OP_IMM) {
			const auto target = (uint64_t)insn.ops(0).imm;
			const auto ins0_addr = insn.address();
			setAsmTextDataCall(ins0_addr, target);
			++insn;
			return std::make_unique<CallInstr>(insn.Wrap(ins0_addr), app.GetFunction(target), target);
		}
	}
	else if (insn.id() == ARM64_INS_B && insn.ops(0).type == ARM64_OP_IMM) {
		const auto target = (uint64_t)insn.ops(0).imm;
		if (target < dartFn->Address() || target >= dartFn->AddressEnd()) {
			const auto ins0_addr = insn.address();
			setAsmTextDataCall(ins0_addr, target);
			++insn;
			return std::make_unique<CallInstr>(insn.Wrap(ins0_addr), app.GetFunction(target), target);
		}
	}

	return nullptr;
}

std::unique_ptr<GdtCallInstr> FunctionAnalyzer::processGdtCallInstr(AsmIterator& insn)
{
	if (insn.ops(0).reg == CSREG_DART_LR && (insn.id() == ARM64_INS_ADD || insn.id() == ARM64_INS_SUB) &&
		insn.ops(1).reg == ToCapstoneReg(dart::DispatchTableNullErrorABI::kClassIdReg))
	{
		auto insn0_addr = insn.address();
		int64_t offset = 0;

		if (insn.ops(2).type == ARM64_OP_IMM) {
			offset = insn.ops(2).imm;
			if (insn.ops(2).shift.type != ARM64_SFT_INVALID) {
				ASSERT(insn.ops(2).shift.type == ARM64_SFT_LSL);
				offset <<= insn.ops(2).shift.value;
			}
			if (insn.id() == ARM64_INS_SUB)
				offset = -offset;
			++insn;
		}
		else {
			INSN_ASSERT(insn.id() == ARM64_INS_ADD);
			INSN_ASSERT(insn.ops(2).type == ARM64_OP_REG && insn.ops(2).reg == CSREG_DART_TMP2);

			auto il_loadImm = reinterpret_cast<LoadValueInstr*>(fnInfo->LastIL());
			INSN_ASSERT(il_loadImm->val.Storage().IsImmediate());
			INSN_ASSERT(il_loadImm->dstReg == A64::TMP2_REG);
			offset = il_loadImm->val.Get<VarInteger>()->Value();
			insn0_addr = il_loadImm->Start();
			fnInfo->RemoveLastIL();
			++insn;
		}

		INSN_ASSERT(insn.id() == ARM64_INS_LDR);
		INSN_ASSERT(insn.ops(0).reg == CSREG_DART_LR);
		ASSERT(insn.ops(1).mem.base == CSREG_DART_DISPATCH_TABLE && insn.ops(1).mem.index == CSREG_DART_LR && insn.ops(1).shift.value == 3);
		++insn;

		INSN_ASSERT(insn.id() == ARM64_INS_BLR);
		INSN_ASSERT(insn.ops(0).reg == CSREG_DART_LR);
		++insn;

		return std::make_unique<GdtCallInstr>(insn.Wrap(insn0_addr), offset);
	}

	return nullptr;
}

std::unique_ptr<ReturnInstr> FunctionAnalyzer::processReturnInstr(AsmIterator& insn)
{
	if (insn.id() == ARM64_INS_RET) {
		const auto ins0_addr = insn.address();
		++insn;
		return std::make_unique<ReturnInstr>(insn.Wrap(ins0_addr));
	}
	return nullptr;
}

std::unique_ptr<TestTypeInstr> FunctionAnalyzer::processInstanceofNoTypeArgumentInstr(AsmIterator& insn)
{
	InsnMarker marker(insn);
	const auto srcReg = [&] {
		if (insn.id() == ARM64_INS_MOV && insn.ops(0).reg == ToCapstoneReg(dart::TypeTestABI::kInstanceReg)) {
			const auto srcReg = insn.ops(1).reg;
			++insn;
			if (insn.id() == ARM64_INS_MOV && insn.ops(0).reg == ToCapstoneReg(dart::TypeTestABI::kInstantiatorTypeArgumentsReg) && insn.ops(1).reg == CSREG_DART_NULL) {
				++insn;
				if (insn.id() == ARM64_INS_MOV && insn.ops(0).reg == ToCapstoneReg(dart::TypeTestABI::kFunctionTypeArgumentsReg) && insn.ops(1).reg == CSREG_DART_NULL) {
					++insn;
					return srcReg;
				}
			}
		}
		return ARM64_REG_INVALID;
	}();

	if (srcReg != ARM64_REG_INVALID) {
		const auto ilBranch = processBranchIfSmiInstr(insn);
		if (!ilBranch)
			return nullptr;
		INSN_ASSERT(ilBranch->objReg == A64::Register{ dart::TypeTestABI::kInstanceReg });
		const auto done_addr = ilBranch->branchAddr;

		intptr_t typeCheckCid = 0;
		const auto ilLoadCid = processLoadClassIdInstr(insn);
		if (ilLoadCid) {
			INSN_ASSERT(ilLoadCid->objReg == A64::Register{ dart::TypeTestABI::kInstanceReg });
			INSN_ASSERT(ilLoadCid->cidReg == A64::Register{ dart::TypeTestABI::kScratchReg });

			INSN_ASSERT(insn.id() == ARM64_INS_SUB);
			INSN_ASSERT(insn.ops(0).reg == ToCapstoneReg(dart::TypeTestABI::kScratchReg));
			INSN_ASSERT(insn.ops(1).reg == ToCapstoneReg(dart::TypeTestABI::kScratchReg));
			INSN_ASSERT(insn.ops(2).imm == dart::kSmiCid);
			++insn;

			INSN_ASSERT(insn.id() == ARM64_INS_CMP);
			INSN_ASSERT(insn.ops(0).reg == ToCapstoneReg(dart::TypeTestABI::kScratchReg));
			INSN_ASSERT(insn.ops(1).imm == 1 || insn.ops(1).imm == 2);
			typeCheckCid = insn.ops(1).imm == 1 ? app.DartIntCid() : dart::kNumberCid;
			++insn;

			INSN_ASSERT(insn.IsBranch(ARM64_CC_LS));
			INSN_ASSERT(insn.ops(0).imm == done_addr);
			++insn;
		}

		const auto objPoolInstr = getObjectPoolInstruction(insn);
		INSN_ASSERT(objPoolInstr.dstReg == A64::Register{ dart::TypeTestABI::kDstTypeReg });
		INSN_ASSERT(objPoolInstr.item.ValueTypeId() == dart::kTypeCid);
		const auto vtype = objPoolInstr.item.Get<VarType>();
		INSN_ASSERT(typeCheckCid == 0 || typeCheckCid == vtype->type.Class().Id());

		auto test_ep_reg = ARM64_REG_INVALID;
		if (insn.id() == ARM64_INS_LDUR) {
			INSN_ASSERT(insn.ops(1).mem.base == ToCapstoneReg(dart::TypeTestABI::kDstTypeReg));
			INSN_ASSERT(insn.ops(1).mem.disp == AOT_AbstractType_type_test_stub_entry_point_offset - dart::kHeapObjectTag);
			test_ep_reg = insn.ops(0).reg;
			++insn;
		}

		const auto objPoolInstr2 = getObjectPoolInstruction(insn);
		INSN_ASSERT(objPoolInstr2.dstReg == A64::Register{ dart::TypeTestABI::kSubtypeTestCacheReg });
		INSN_ASSERT(objPoolInstr2.item.Value()->RawTypeId() == dart::kNullCid);

		if (test_ep_reg == ARM64_REG_INVALID) {
			INSN_ASSERT(insn.id() == ARM64_INS_BL);
			auto dartFn = app.GetFunction(insn.ops(0).imm);
			auto dartStub = dartFn->AsStub();
			auto typeName = dartStub->Name();
			if (typeCheckCid == app.DartIntCid()) {
				INSN_ASSERT(dartStub->kind == DartStub::TypeCheckStub);
				INSN_ASSERT(typeName == "int" || typeName == "int?");
			}
			else {
				INSN_ASSERT(typeName == vtype->ToString() || dartStub->kind == DartStub::DefaultTypeTestStub || dartStub->kind == DartStub::DefaultNullableTypeTestStub);
			}
			setAsmTextDataCall(insn.address(), (uint64_t)insn.ops(0).imm);
			++insn;
		}
		else {
			INSN_ASSERT(insn.id() == ARM64_INS_BLR);
			INSN_ASSERT(insn.ops(0).reg == test_ep_reg);
			++insn;
		}

		INSN_ASSERT(insn.address() == done_addr);

		return std::make_unique<TestTypeInstr>(insn.Wrap(marker.Take()), A64::Register{srcReg}, objPoolInstr.item.Get<VarType>()->ToString());
	}

	return nullptr;
}

std::unique_ptr<BranchIfSmiInstr> FunctionAnalyzer::processBranchIfSmiInstr(AsmIterator& insn)
{
	if (insn.id() == ARM64_INS_TBZ && insn.ops(1).imm == dart::kSmiTag && dart::kCompressedWordSize == GetCsRegSize(insn.ops(0).reg)) {
		const auto objReg = A64::Register{ insn.ops(0).reg };
		const auto branchAddr = insn.ops(2).imm;
		const auto ins0_addr = insn.address();
		++insn;
		return std::make_unique<BranchIfSmiInstr>(insn.Wrap(ins0_addr), objReg, branchAddr);
	}
	return nullptr;
}

std::unique_ptr<LoadClassIdInstr> FunctionAnalyzer::processLoadClassIdInstr(AsmIterator& insn)
{
	if (insn.id() == ARM64_INS_LDUR && insn.ops(1).mem.disp == -1 && kUntaggedObjectClassIdTagPos == 12) {
		const auto objReg = A64::Register{ insn.ops(1).mem.base };
		const auto cidReg = insn.ops(0).reg;
		const auto ins0_addr = insn.address();
		++insn;

		INSN_ASSERT(insn.id() == ARM64_INS_UBFX);
		INSN_ASSERT(insn.ops(0).reg == cidReg);
		INSN_ASSERT(insn.ops(1).reg == cidReg);
		INSN_ASSERT(insn.ops(2).imm == kUntaggedObjectClassIdTagPos);
		INSN_ASSERT(insn.ops(3).imm == dart::UntaggedObject::kClassIdTagSize);
		++insn;

		return std::make_unique<LoadClassIdInstr>(insn.Wrap(ins0_addr), objReg, A64::Register{cidReg});
	}
	else if (insn.id() == ARM64_INS_LDURH && insn.ops(1).mem.disp == 1 && kUntaggedObjectClassIdTagPos == 16) {
		const auto objReg = A64::Register{ insn.ops(1).mem.base };
		const auto cidReg = insn.ops(0).reg;
		const auto ins0_addr = insn.address();
		++insn;

		return std::make_unique<LoadClassIdInstr>(insn.Wrap(ins0_addr), objReg, A64::Register{cidReg});
	}
	return nullptr;
}

std::unique_ptr<LoadTaggedClassIdMayBeSmiInstr> FunctionAnalyzer::processLoadTaggedClassIdMayBeSmiInstr(AsmIterator& insn)
{
	auto& il = fnInfo->il_insns.back();
	if (insn.id() == ARM64_INS_LSL && insn.ops(0).reg == insn.ops(1).reg && insn.ops(2).imm == dart::kSmiTagSize && il->Kind() == ILInstr::LoadClassId && fnInfo->il_insns.size() >= 3) {
		auto il_loadClassId = reinterpret_cast<LoadClassIdInstr*>(il.get());
		if (il_loadClassId->cidReg == A64::Register{ insn.ops(0).reg }) {
			auto& il2 = fnInfo->il_insns[fnInfo->il_insns.size() - 2];
			if (il2->Kind() == ILInstr::BranchIfSmi) {
				auto il_branchIfSmi = reinterpret_cast<BranchIfSmiInstr*>(il2.get());
				INSN_ASSERT(il_branchIfSmi->objReg == il_loadClassId->objReg);
				auto& il3 = fnInfo->il_insns[fnInfo->il_insns.size() - 3];
				INSN_ASSERT(il3->Kind() == ILInstr::LoadValue);
				auto il_loadImm = reinterpret_cast<LoadValueInstr*>(il3.get());
				INSN_ASSERT(il_loadImm->dstReg == il_loadClassId->cidReg);
				INSN_ASSERT(il_loadImm->val.Storage().IsImmediate());
				INSN_ASSERT(il_loadImm->val.ValueTypeId() == dart::kIntegerCid);
				INSN_ASSERT(il_loadImm->val.Get<VarInteger>()->Value() == dart::Smi::RawValue(dart::kSmiCid));

				il.release();
				il2.release();
				il3.release();
				++insn;
				auto il_new = std::make_unique<LoadTaggedClassIdMayBeSmiInstr>(insn.Wrap(il_loadImm->Start()),
					std::unique_ptr<LoadValueInstr>(il_loadImm), std::unique_ptr<BranchIfSmiInstr>(il_branchIfSmi),
					std::unique_ptr<LoadClassIdInstr>(il_loadClassId));
				fnInfo->il_insns.resize(fnInfo->il_insns.size() - 3);
				return std::move(il_new);
			}
		}
	}
	return nullptr;
}

std::unique_ptr<BoxInt64Instr> FunctionAnalyzer::processBoxInt64Instr(AsmIterator& insn)
{
	if (insn.id() == ARM64_INS_SBFIZ && insn.ops(2).imm == dart::kSmiTagSize && insn.ops(3).imm == 31) {
		const auto out_reg = insn.ops(0).reg;
		const auto in_reg = insn.ops(1).reg;
		InsnMarker marker(insn);
		++insn;

		if (insn.id() == ARM64_INS_CMP && insn.ops(0).reg == in_reg && insn.ops(1).reg == out_reg && insn.ops(1).shift.type == ARM64_SFT_ASR && insn.ops(1).shift.value == dart::kSmiTagSize) {
			++insn;

			INSN_ASSERT(insn.id() == ARM64_INS_B && insn.cc() == ARM64_CC_EQ);
			const auto contAddr = insn.ops(0).imm;
			++insn;

			const auto assertAllocateMintStub = [&](DartFnBase* stub) {
				INSN_ASSERT(stub->IsStub());
				const auto stubKind = reinterpret_cast<DartStub*>(stub)->kind;
				INSN_ASSERT(stubKind == DartStub::AllocateMintSharedWithoutFPURegsStub || stubKind == DartStub::AllocateMintSharedWithFPURegsStub);
			};

			bool doEnterFrame = false;
			if (!fnInfo->useFramePointer) {
				if (insn.id() == ARM64_INS_STP && insn.ops(0).reg == CSREG_DART_FP && insn.ops(1).reg == ARM64_REG_LR && insn.ops(2).mem.base == CSREG_DART_SP) {
					INSN_ASSERT(insn.writeback());
					++insn;

					INSN_ASSERT(insn.id() == ARM64_INS_MOV);
					INSN_ASSERT(insn.ops(0).reg == CSREG_DART_FP);
					INSN_ASSERT(insn.ops(1).reg == CSREG_DART_SP);
					++insn;
					doEnterFrame = true;
				}
			}

			if (insn.id() == ARM64_INS_BL) {
				assertAllocateMintStub(app.GetFunction(insn.ops(0).imm));
				setAsmTextDataCall(insn.address(), (uint64_t)insn.ops(0).imm);
				++insn;
			}
			else {
				const auto objPoolInstr = getObjectPoolInstruction(insn);
				INSN_ASSERT(objPoolInstr.IsSet());
				INSN_ASSERT(objPoolInstr.dstReg == A64::Register{ dart::CODE_REG });
				INSN_ASSERT(objPoolInstr.item.ValueTypeId() == dart::kFunctionCid);
				assertAllocateMintStub(&objPoolInstr.item.Get<VarFunctionCode>()->fn);

				INSN_ASSERT(insn.id() == ARM64_INS_LDUR);
				INSN_ASSERT(insn.ops(0).reg == CSREG_DART_LR);
				INSN_ASSERT(insn.ops(1).mem.base == ToCapstoneReg(dart::CODE_REG) && insn.ops(1).mem.disp == AOT_Code_entry_point_offset[(int)dart::CodeEntryKind::kNormal] - dart::kHeapObjectTag);
				++insn;

				INSN_ASSERT(insn.id() == ARM64_INS_BLR);
				INSN_ASSERT(insn.ops(0).reg == CSREG_DART_LR);
				++insn;
			}

			if (doEnterFrame) {
				if (!(insn.id() == ARM64_INS_MOV && insn.ops(0).reg == CSREG_DART_SP && insn.ops(1).reg == CSREG_DART_FP))
					return nullptr;
				++insn;
				if (!tryConsumeLeaveFrameRestore(insn))
					return nullptr;
			}

			INSN_ASSERT(insn.id() == ARM64_INS_STUR);
			INSN_ASSERT(insn.ops(0).reg == in_reg);
			INSN_ASSERT(insn.ops(1).mem.base == out_reg && insn.ops(1).mem.disp == dart::Mint::value_offset() - dart::kHeapObjectTag);
			++insn;

			INSN_ASSERT(insn.address() == contAddr);

			const auto objReg = A64::Register{ out_reg };
			const auto srcReg = A64::Register{ in_reg };
			return std::make_unique<BoxInt64Instr>(insn.Wrap(marker.Take()), objReg, srcReg);
		}
	}
	return nullptr;
}

std::unique_ptr<LoadInt32Instr> FunctionAnalyzer::processLoadInt32FromBoxOrSmiInstrFromSrcReg(AsmIterator& insn, A64::Register expectedSrcReg)
{
	if (insn.id() == ARM64_INS_SBFX && insn.ops(2).imm == dart::kSmiTagSize && insn.ops(3).imm == 31) {
		const auto in_reg = insn.ops(1).reg;
		const auto srcReg = A64::Register{ in_reg };
		if (!expectedSrcReg.IsSet() || expectedSrcReg == srcReg) {
			const auto out_reg = insn.ops(0).reg;
			const auto dstReg = A64::Register{ out_reg };
			const auto ins0_addr = insn.address();
			++insn;

			if (insn.id() == ARM64_INS_TBZ && A64::Register{ insn.ops(0).reg } == srcReg && insn.ops(1).imm == dart::kSmiTag) {
				const auto cont_addr = insn.ops(2).imm;
				++insn;

				INSN_ASSERT(insn.id() == ARM64_INS_LDUR);
				INSN_ASSERT(insn.ops(0).reg == out_reg);
				INSN_ASSERT(insn.ops(1).mem.base == in_reg && insn.ops(1).mem.disp == dart::Mint::value_offset() - dart::kHeapObjectTag);
				++insn;

				INSN_ASSERT(insn.address() == cont_addr);
			}
			else {
			}

			return std::make_unique<LoadInt32Instr>(insn.Wrap(ins0_addr), dstReg, srcReg);
		}
	}
	return nullptr;
}

std::unique_ptr<LoadInt32Instr> FunctionAnalyzer::processLoadInt32FromBoxOrSmiInstr(AsmIterator& insn)
{
	return processLoadInt32FromBoxOrSmiInstrFromSrcReg(insn);
}

std::unique_ptr<ILInstr> FunctionAnalyzer::processLoadFieldTableInstr(AsmIterator& insn)
{
	if (insn.id() == ARM64_INS_LDR && insn.ops(1).mem.base == CSREG_DART_THR && insn.ops(1).mem.disp == AOT_Thread_field_table_values_offset) {
		const auto result_reg = insn.ops(0).reg;
		const auto dstReg = A64::Register{ result_reg };
		auto tmp_reg = insn.ops(0).reg;
		auto load_offset = 0;
		InsnMarker marker(insn);
		++insn;

		if (insn.id() == ARM64_INS_ADD && insn.ops(1).reg == tmp_reg && insn.ops(2).type == ARM64_OP_IMM && insn.ops(2).shift.type == ARM64_SFT_LSL) {
			tmp_reg = insn.ops(0).reg;
			load_offset = insn.ops(2).imm << insn.ops(2).shift.value;
			++insn;
		}

		if (insn.id() != ARM64_INS_STR && insn.id() != ARM64_INS_LDR) {
			FATAL("static field without STR or LDR");
		}

		INSN_ASSERT(insn.ops(1).mem.base == tmp_reg);
		load_offset |= insn.ops(1).mem.disp;
		const auto field_offset = load_offset >> 1;

		if (insn.id() == ARM64_INS_STR) {
			const auto reg = A64::Register{ insn.ops(0).reg };
			++insn;
			return std::make_unique<StoreStaticFieldInstr>(insn.Wrap(marker.Take()), reg, field_offset);
		}
		else {
			INSN_ASSERT(insn.ops(0).reg == result_reg);
			++insn;

			const auto objPoolInstr = getObjectPoolInstruction(insn);
			if (!objPoolInstr.IsSet() || objPoolInstr.dstReg != A64::TMP_REG || objPoolInstr.item.ValueTypeId() != dart::kSentinelCid) {
				return std::make_unique<LoadStaticFieldInstr>(insn.Wrap(marker.Take()), dstReg, field_offset);
			}

			const auto loadStaicInstr_endIns = insn.Current();

			INSN_ASSERT(insn.id() == ARM64_INS_CMP);
			INSN_ASSERT(A64::Register{ insn.ops(0).reg } == dstReg);
			INSN_ASSERT(A64::Register{ insn.ops(1).reg } == A64::TMP_REG);
			++insn;

			INSN_ASSERT(insn.id() == ARM64_INS_B);
			if (insn.cc() == ARM64_CC_NE) {
				const auto cont_addr = insn.ops(0).imm;
				++insn;

				const auto objPoolInstr = getObjectPoolInstruction(insn);
				if (objPoolInstr.IsSet()) {
					INSN_ASSERT(objPoolInstr.dstReg == A64::Register{ dart::InitStaticFieldABI::kFieldReg });
					INSN_ASSERT(objPoolInstr.item.ValueTypeId() == dart::kFieldCid);
					auto& dartField = objPoolInstr.item.Get<VarField>()->field;
					INSN_ASSERT(dartField.Offset() == field_offset);

					if (insn.id() == ARM64_INS_BL) {
						auto dartFn = app.GetFunction(insn.ops(0).imm);
						ASSERT(dartFn->IsStub());
						const auto stubKind = reinterpret_cast<DartStub*>(dartFn)->kind;
						INSN_ASSERT(stubKind == DartStub::InitLateStaticFieldStub || stubKind == DartStub::InitLateFinalStaticFieldStub);
						setAsmTextDataCall(insn.address(), (uint64_t)insn.ops(0).imm);
						++insn;
					}
					else {
						const auto objPoolInstr = getObjectPoolInstruction(insn);
						INSN_ASSERT(objPoolInstr.IsSet() && objPoolInstr.dstReg == A64::Register{ dart::CODE_REG });

						INSN_ASSERT(insn.id() == ARM64_INS_LDUR);
						INSN_ASSERT(insn.ops(0).reg == CSREG_DART_LR);
						INSN_ASSERT(insn.ops(1).mem.base == ToCapstoneReg(dart::CODE_REG));
						INSN_ASSERT(insn.ops(1).mem.disp == dart::Code::entry_point_offset(dart::CodeEntryKind::kNormal) - dart::kHeapObjectTag);
						++insn;

						INSN_ASSERT(insn.id() == ARM64_INS_BLR);
						INSN_ASSERT(insn.ops(0).reg == CSREG_DART_LR);
						++insn;
					}
					INSN_ASSERT(insn.address() == cont_addr);

					return std::make_unique<InitLateStaticFieldInstr>(insn.Wrap(marker.Take()), dstReg, dartField);
				}
			}
			else {
				INSN_ASSERT(insn.cc() == ARM64_CC_EQ);
				const auto error_addr = insn.ops(0).imm;
				INSN_ASSERT(error_addr > insn.NextAddress() && error_addr < dartFn->AddressEnd());
				++insn;

				auto insn2 = AsmIterator(insn, error_addr);
				const auto objPoolInstr = getObjectPoolInstruction(insn2);
				if (!objPoolInstr.IsSet() && objPoolInstr.dstReg == A64::Register{dart::LateInitializationErrorABI::kFieldReg} && objPoolInstr.item.ValueTypeId() == dart::kFieldCid) {
					auto& dartField = objPoolInstr.item.Get<VarField>()->field;
					INSN_ASSERT(dartField.Offset() == field_offset);
					insn2.Next();

					INSN_ASSERT(insn2.id() == ARM64_INS_BL && insn2.ops(0).type == ARM64_OP_IMM);
					auto fn = app.GetFunction(insn2.ops(0).imm);
					auto stub = fn->AsStub();
					INSN_ASSERT(stub->kind == DartStub::LateInitializationErrorSharedWithoutFPURegsStub || stub->kind == DartStub::LateInitializationErrorSharedWithFPURegsStub);
					setAsmTextDataCall(insn2.address(), (uint64_t)insn.ops(0).imm);
					insn2.Next();
					return std::make_unique<LoadStaticFieldInstr>(insn.Wrap(marker.Take()), dstReg, field_offset);
				}
			}

			insn.SetCurrent(loadStaicInstr_endIns);
			return std::make_unique<LoadStaticFieldInstr>(insn.Wrap(marker.Take()), dstReg, field_offset);
		}
	}

	return nullptr;
}

std::unique_ptr<AllocateObjectInstr> FunctionAnalyzer::processTryAllocateObject(AsmIterator& insn)
{
	if (insn.id() == ARM64_INS_LDP && insn.ops(2).mem.base == CSREG_DART_THR && insn.ops(2).mem.disp == dart::Thread::top_offset()) {
		const auto inst_reg = insn.ops(0).reg;
		const auto temp_reg = insn.ops(1).reg;
		InsnMarker marker(insn);
		++insn;

		INSN_ASSERT(insn.id() == ARM64_INS_ADD);
		INSN_ASSERT(insn.ops(0).reg == inst_reg);
		INSN_ASSERT(insn.ops(1).reg == inst_reg);
		const auto inst_size = insn.ops(2).imm;
		INSN_ASSERT(inst_size == 0x10 || inst_size == 0x20);
		++insn;

		INSN_ASSERT(insn.id() == ARM64_INS_CMP);
		INSN_ASSERT(insn.ops(0).reg == temp_reg);
		INSN_ASSERT(insn.ops(1).reg == inst_reg);
		++insn;

		INSN_ASSERT(insn.id() == ARM64_INS_B && insn.cc() == ARM64_CC_LS);
		const uint64_t slow_path = (uint64_t)insn.ops(0).imm;
		INSN_ASSERT(insn.address() < slow_path && slow_path < dartFn->AddressEnd());
		++insn;

		INSN_ASSERT(insn.id() == ARM64_INS_STR);
		INSN_ASSERT(insn.ops(0).reg == inst_reg);
		INSN_ASSERT(insn.ops(1).mem.base == CSREG_DART_THR && insn.ops(1).mem.disp == dart::Thread::top_offset());
		++insn;

		INSN_ASSERT(insn.id() == ARM64_INS_SUB);
		INSN_ASSERT(insn.ops(0).reg == inst_reg);
		INSN_ASSERT(insn.ops(1).reg == inst_reg);
		INSN_ASSERT(insn.ops(2).imm == inst_size - 1);
		++insn;

		INSN_ASSERT(insn.IsMovz());
		INSN_ASSERT(insn.ops(0).reg == temp_reg);
		auto tag = insn.ops(1).imm;
		++insn;

		if (insn.id() == ARM64_INS_MOVK) {
			INSN_ASSERT(insn.ops(0).reg == temp_reg);
			INSN_ASSERT(insn.ops(1).shift.value == 16);
			tag |= (insn.ops(1).imm << 16);
			++insn;
		}

		INSN_ASSERT(insn.id() == ARM64_INS_STUR);
		INSN_ASSERT(insn.ops(0).reg == temp_reg);
		INSN_ASSERT(insn.ops(1).mem.base == inst_reg && insn.ops(1).mem.disp == -1);
		++insn;

		const uint32_t cid = (tag >> kUntaggedObjectClassIdTagPos) & ((1 << dart::UntaggedObject::kClassIdTagSize) - 1);
		auto dartCls = app.GetClass(cid);

		const auto dstReg = A64::Register{ inst_reg };


		return std::make_unique<AllocateObjectInstr>(insn.Wrap(marker.Take()), dstReg, *dartCls);
	}

	return nullptr;
}

std::unique_ptr<WriteBarrierInstr> FunctionAnalyzer::processWriteBarrierInstr(AsmIterator& insn)
{
	A64::Register objReg;
	A64::Register valReg;

	InsnMarker marker(insn);

	uint64_t contSmiAddr = 0;
	if (insn.id() == ARM64_INS_TBZ) {
		if (insn.ops(1).imm != dart::kSmiTag)
			return nullptr;
		valReg = A64::Register{ insn.ops(0).reg };
		contSmiAddr = (uint64_t)insn.ops(2).imm;
		++insn;
	}

	if (insn.id() != ARM64_INS_LDURB || A64::Register{ insn.ops(0).reg } != A64::TMP_REG || insn.ops(1).mem.disp != -1)
		return nullptr;
	objReg = A64::Register{ insn.ops(1).mem.base };
	++insn;

	if (insn.id() != ARM64_INS_LDURB || A64::Register{ insn.ops(0).reg } != A64::TMP2_REG || insn.ops(1).mem.disp != -1)
		return nullptr;
	if (valReg != A64::Register::kNoRegister) {
		INSN_ASSERT(A64::Register{ insn.ops(1).mem.base } == valReg);
	}
	else {
		valReg = A64::Register{ insn.ops(1).mem.base };
	}
	++insn;

	INSN_ASSERT(insn.id() == ARM64_INS_AND);
	INSN_ASSERT(A64::Register{ insn.ops(0).reg } == A64::TMP_REG);
	INSN_ASSERT(A64::Register{ insn.ops(1).reg } == A64::TMP2_REG);
	INSN_ASSERT(A64::Register{ insn.ops(2).reg } == A64::TMP_REG);
	INSN_ASSERT(insn.ops(2).shift.type == ARM64_SFT_LSR && insn.ops(2).shift.value == 2);
	++insn;

	INSN_ASSERT(insn.id() == ARM64_INS_TST);
	INSN_ASSERT(insn.ops(0).reg == CSREG_DART_TMP);
	INSN_ASSERT(insn.ops(1).reg == CSREG_DART_HEAP);
	INSN_ASSERT(insn.ops(1).shift.type == ARM64_SFT_LSR && insn.ops(1).shift.value == 32);
	++insn;

	INSN_ASSERT(insn.id() == ARM64_INS_B && insn.cc() == ARM64_CC_EQ);
	const auto contAddr = (uint64_t)insn.ops(0).imm;
	INSN_ASSERT(contSmiAddr == 0 || contSmiAddr == contAddr);
	++insn;

	bool spill_lr = false;
	if (insn.id() == ARM64_INS_STR) {
		INSN_ASSERT(insn.writeback());
		INSN_ASSERT(insn.ops(0).reg == CSREG_DART_LR);
		INSN_ASSERT(insn.ops(1).mem.base == CSREG_DART_SP && insn.ops(1).mem.disp == -8);
		spill_lr = true;
		++insn;
	}

	bool isArray;
	if (insn.id() == ARM64_INS_BL) {
		auto stub = app.GetFunction(insn.ops(0).imm);
		INSN_ASSERT(stub->IsStub());
		const auto stubKind = reinterpret_cast<DartStub*>(stub)->kind;
		INSN_ASSERT(stubKind == DartStub::WriteBarrierWrappersStub || stubKind == DartStub::ArrayWriteBarrierStub);
		isArray = stubKind == DartStub::ArrayWriteBarrierStub;
		setAsmTextDataCall(insn.address(), (uint64_t)insn.ops(0).imm);
		++insn;
	}
	else {
		INSN_ASSERT(insn.id() == ARM64_INS_LDR);
		INSN_ASSERT(insn.ops(0).reg == CSREG_DART_LR);
		INSN_ASSERT(insn.ops(1).mem.base == CSREG_DART_THR);
		if (insn.ops(1).mem.disp == AOT_Thread_array_write_barrier_entry_point_offset) {
			isArray = true;
		}
		else {
			const auto existed = std::find(std::begin(AOT_Thread_write_barrier_wrappers_thread_offset),
				std::end(AOT_Thread_write_barrier_wrappers_thread_offset), insn.ops(1).mem.disp) != std::end(AOT_Thread_write_barrier_wrappers_thread_offset);
			INSN_ASSERT(existed);
			isArray = false;
		}
		const auto epReg = insn.ops(0).reg;
		++insn;

		INSN_ASSERT(insn.id() == ARM64_INS_BLR);
		INSN_ASSERT(insn.ops(0).reg == CSREG_DART_LR);
		++insn;
	}

	if (spill_lr) {
		INSN_ASSERT(insn.id() == ARM64_INS_LDR && insn.writeback());
		INSN_ASSERT(insn.ops(0).reg == CSREG_DART_LR);
		INSN_ASSERT(insn.ops(1).mem.base == CSREG_DART_SP);
		INSN_ASSERT(insn.ops(2).imm == 8);
		++insn;
	}

	INSN_ASSERT(insn.address() == contAddr);

	return std::make_unique<WriteBarrierInstr>(insn.Wrap(marker.Take()), objReg, valReg, isArray);
}

static ArrayOp getArrayOp(AsmIterator& insn, int32_t arr_data_offset)
{
	ArrayOp op;
	if (insn.writeback())
		return ArrayOp();
	switch (insn.id()) {
	case ARM64_INS_LDUR: {
		const auto regSize = GetCsRegSize(insn.ops(0).reg);
		return ArrayOp(regSize, true, arr_data_offset == 0x17 ? ArrayOp::List : ArrayOp::Unknown);
	}
	case ARM64_INS_LDURSW:
		return ArrayOp(4, true, ArrayOp::TypedSigned);
	case ARM64_INS_LDRB:
		return ArrayOp(1, true, arr_data_offset == 0x17 ? ArrayOp::List : ArrayOp::TypedUnsigned);
	case ARM64_INS_LDRSB:
		return ArrayOp(1, true, ArrayOp::TypedSigned);
	case ARM64_INS_LDRH:
		return ArrayOp(2, true, ArrayOp::TypedUnsigned);
	case ARM64_INS_LDURSH:
		return ArrayOp(2, true, ArrayOp::TypedSigned);
	case ARM64_INS_STUR: {
		const auto regSize = GetCsRegSize(insn.ops(0).reg);
		return ArrayOp(regSize, false, arr_data_offset == 0x17 ? ArrayOp::List : ArrayOp::Unknown);
	}
	case ARM64_INS_STRB:
		return ArrayOp(1, false, ArrayOp::TypedUnknown);
	case ARM64_INS_STURH:
		return ArrayOp(2, false, ArrayOp::TypedUnknown);
	}
	return ArrayOp();
}

std::unique_ptr<ILInstr> FunctionAnalyzer::processLoadStore(AsmIterator& insn)
{
	InsnMarker marker(insn);

	if (insn.id() == ARM64_INS_ADD) {
		if (insn.ops(0).reg == CSREG_DART_WB_SLOT) {
			if (insn.ops(1).reg != CSREG_DART_WB_OBJECT)
				return nullptr;

			const auto objReg = A64::Register{ dart::kWriteBarrierObjectReg };
			const auto valReg = A64::Register{ dart::kWriteBarrierValueReg };
			const int64_t arrayDataOffset = dart::Array::data_offset() - dart::kHeapObjectTag;
			auto idx = VarStorage::NewSmallImm(0);
			bool hasExplicitArrayDataOffset = false;
			if (insn.ops(2).type == ARM64_OP_IMM) {
				const auto arr_idx = (insn.ops(2).imm + dart::kHeapObjectTag - dart::Array::data_offset()) / dart::kCompressedWordSize;
				if (arr_idx < 0)
					return nullptr;
				idx = VarStorage::NewSmallImm(arr_idx);
				hasExplicitArrayDataOffset = true;
				++insn;
			}
			else {
				const auto shift = insn.ops(2).shift;
				const auto ext = insn.ops(2).ext;
				const bool shiftCompatible =
					(shift.type == ARM64_SFT_LSL &&
						(shift.value == dart::kCompressedWordSizeLog2 || shift.value == dart::kCompressedWordSizeLog2 - 1)) ||
					(shift.type == ARM64_SFT_INVALID &&
						(ext == ARM64_EXT_INVALID || ext == ARM64_EXT_SXTW || ext == ARM64_EXT_UXTW));
				if (!shiftCompatible)
					return nullptr;
				idx = VarStorage(A64::Register{ insn.ops(2).reg });
				++insn;

				if (insn.id() == ARM64_INS_ADD && insn.ops(0).reg == CSREG_DART_WB_SLOT &&
					insn.ops(1).reg == CSREG_DART_WB_SLOT && insn.ops(2).type == ARM64_OP_IMM)
				{
					if (insn.ops(2).imm != arrayDataOffset)
						return nullptr;
					hasExplicitArrayDataOffset = true;
					++insn;
				}
			}

			if (insn.id() != ARM64_INS_STR)
				return nullptr;
			if (A64::Register{ insn.ops(0).reg } != valReg || GetCsRegSize(insn.ops(0).reg) != dart::kCompressedWordSize)
				return nullptr;
			if (insn.ops(1).mem.base != CSREG_DART_WB_SLOT)
				return nullptr;
			const auto storeDisp = insn.ops(1).mem.disp;
			if (hasExplicitArrayDataOffset) {
				if (storeDisp != 0)
					return nullptr;
			}
			else if (storeDisp == arrayDataOffset) {
			}
			else {
				return nullptr;
			}
			++insn;

			const auto il_wb = processWriteBarrierInstr(insn);
			INSN_ASSERT(il_wb);
			INSN_ASSERT(il_wb->isArray);
			INSN_ASSERT(il_wb->objReg == objReg && il_wb->valReg == valReg);

			ArrayOp arrayOp(dart::kCompressedWordSize, false, ArrayOp::List);
			return std::make_unique<StoreArrayElementInstr>(insn.Wrap(marker.Take()), valReg, objReg, idx, arrayOp);
		}

		if (insn.ops(2).type == ARM64_OP_REG && insn.ops(1).reg != CSREG_DART_FP && GetCsRegSize(insn.ops(0).reg) == 8) {
			const auto tmpReg = insn.ops(0).reg;
			const auto arrReg = A64::Register{ insn.ops(1).reg };
			const auto idx = VarStorage(A64::Register{ insn.ops(2).reg });
			const auto shift = insn.ops(2).shift;
			if (shift.type != ARM64_SFT_INVALID && shift.type != ARM64_SFT_LSL)
				return nullptr;
			const auto ext = insn.ops(2).ext;
			++insn;

			const auto arr_data_offset = insn.ops(1).mem.disp;
			if (insn.ops(1).mem.base != tmpReg || arr_data_offset < 8)
				return nullptr;
			const auto arrayOp = getArrayOp(insn, arr_data_offset);
			if (!arrayOp.IsArrayOp())
				return nullptr;
			const auto idxShiftVal = arrayOp.SizeLog2();
			if (arrayOp.arrType == ArrayOp::List) {
			}
			else if (shift.value == idxShiftVal) {
				if (idxShiftVal == 0) {
				}
			}
			else if (shift.value + 1 == idxShiftVal) {
			}
			else {
				INSN_ASSERT(shift.value == idxShiftVal);
			}
			bool isTypedData = dart::UntaggedTypedData::payload_offset() - dart::kHeapObjectTag == arr_data_offset;
			INSN_ASSERT(isTypedData || arr_data_offset == dart::Array::data_offset() - dart::kHeapObjectTag);
			const auto op0Reg = A64::Register{ insn.ops(0).reg };
			++insn;
			if (arrayOp.isLoad) {
				INSN_ASSERT(tmpReg == CSREG_DART_TMP);
				return std::make_unique<LoadArrayElementInstr>(insn.Wrap(marker.Take()), op0Reg, arrReg, idx, arrayOp);
			}
			else {
				return std::make_unique<StoreArrayElementInstr>(insn.Wrap(marker.Take()), op0Reg, arrReg, idx, arrayOp);
			}
		}
	}

	if (insn.ops(1).mem.base != CSREG_DART_FP && insn.ops(1).mem.disp != 0) {
		const auto arrayOp = getArrayOp(insn, insn.ops(1).mem.disp);
		if (arrayOp.IsArrayOp()) {
			const auto valReg = A64::Register{ insn.ops(0).reg };
			const auto objReg = A64::Register{ insn.ops(1).mem.base };
			const auto offset = insn.ops(1).mem.disp;
			++insn;

			if (arrayOp.arrType == ArrayOp::Unknown) {
				if (arrayOp.isLoad) {
					return std::make_unique<LoadFieldInstr>(insn.Wrap(marker.Take()), valReg, objReg, offset);
				}
				else {
					const auto il_wb = processWriteBarrierInstr(insn);
					if (il_wb) {
						INSN_ASSERT(il_wb->objReg == objReg && il_wb->valReg == valReg);
						if (il_wb->isArray)
							return std::make_unique<StoreArrayElementInstr>(insn.Wrap(marker.Take()), valReg, objReg, VarStorage::NewSmallImm(offset), arrayOp);
						else
							return std::make_unique<StoreFieldInstr>(insn.Wrap(marker.Take()), valReg, objReg, offset);
					}
					else {
						return std::make_unique<StoreFieldInstr>(insn.Wrap(marker.Take()), valReg, objReg, offset);
					}
				}
			}
			else {
				const auto idx = VarStorage::NewSmallImm((offset + dart::kHeapObjectTag - dart::UntaggedTypedData::payload_offset()) / arrayOp.size);
				if (arrayOp.isLoad) {
					return std::make_unique<LoadArrayElementInstr>(insn.Wrap(marker.Take()), valReg, objReg, idx, arrayOp);
				}
				else {
					const auto il_wb = processWriteBarrierInstr(insn);
					if (il_wb) {
						return std::make_unique<StoreArrayElementInstr>(insn.Wrap(marker.Take()), valReg, objReg, idx, arrayOp);
					}
					else {
						return std::make_unique<StoreArrayElementInstr>(insn.Wrap(marker.Take()), valReg, objReg, idx, arrayOp);
					}
				}
			}
		}
	}

	return nullptr;
}

void FunctionAnalyzer::asm2il()
{
	AsmIterator insn(asm_insns.FirstPtr(), asm_insns.LastPtr());

	handlePrologue(insn, fnInfo->asmTexts.FirstStackLimitAddress());

	do {
		bool ok = false;
		try {
			for (auto matcher : matcherFns) {
				auto il = std::invoke(matcher, this, insn);
				if (il) {
					fnInfo->AddIL(std::move(il));
					ok = true;
					break;
				}
			}
		}
		catch (InsnException& e) {
			printInsnException(e);
		}

		if (!ok) {
			auto ins = insn.Current();
			fnInfo->AddIL(std::make_unique<UnknownInstr>(ins, fnInfo->asmTexts.AtAddr(ins->address)));
			++insn;
		}
	} while (!insn.IsEnd());
}

void CodeAnalyzer::asm2il(DartFunction* dartFn, AsmInstructions& asm_insns)
{
	FunctionAnalyzer analyzer{ dartFn->GetAnalyzedData(), dartFn, asm_insns, app };
	analyzer.asm2il();
}

AsmTexts CodeAnalyzer::convertAsm(AsmInstructions& asm_insns)
{
	std::vector<AsmText> asm_texts(asm_insns.Count());
	uint64_t first_stack_limit_addr = 0;
	int max_param_stack_offset = 0;

	for (size_t i = 0; i < asm_insns.Count(); i++) {
		auto insn = asm_insns.Ptr(i);
		auto& text_asm = asm_texts.at(i);

		text_asm.addr = insn->address;
		text_asm.dataType = AsmText::None;

		memset(text_asm.text, ' ', 16);
		memcpy(text_asm.text, insn->mnemonic, strlen(insn->mnemonic));
		auto ptr = text_asm.text + 16;
		auto op_ptr = insn->op_str;
		bool token_start = true;
		while (*op_ptr != '\0') {
			if (token_start) {
				if (op_ptr[0] == 'x' || op_ptr[0] == 'w') {
					bool do_replacement = true;
					if (op_ptr[1] == '1' && op_ptr[2] == '5') {
						*ptr++ = 'S';
						*ptr++ = 'P';
					}
					else if (op_ptr[1] == '2' && op_ptr[2] == '2') {
						*ptr++ = 'N';
						*ptr++ = 'U';
						*ptr++ = 'L';
						*ptr++ = 'L';
					}
					else if (op_ptr[1] == '2' && op_ptr[2] == '6') {
						*ptr++ = 'T';
						*ptr++ = 'H';
						*ptr++ = 'R';
						auto& op = insn->detail->arm64.operands[insn->detail->arm64.op_count - 1];
						if (op.type == ARM64_OP_MEM && op.mem.base == CSREG_DART_THR) {
							text_asm.threadOffset = op.mem.disp;
							text_asm.dataType = AsmText::ThreadOffset;
							if (first_stack_limit_addr == 0 && op.mem.disp == AOT_Thread_stack_limit_offset) {
								first_stack_limit_addr = insn->address;
							}
						}
					}
					else if (op_ptr[1] == '2' && op_ptr[2] == '7') {
						*ptr++ = 'P';
						*ptr++ = 'P';
					}
					else if (op_ptr[1] == '2' && op_ptr[2] == '8') {
						*ptr++ = 'H';
						*ptr++ = 'E';
						*ptr++ = 'A';
						*ptr++ = 'P';
					}
					else if (op_ptr[1] == '2' && op_ptr[2] == '9') {
						*ptr++ = 'f';
						*ptr++ = 'p';
						if (insn->id == ARM64_INS_LDR) {
							auto& op = insn->detail->arm64.operands[1];
							if (op.mem.base == CSREG_DART_FP && op.mem.disp > max_param_stack_offset) {
								max_param_stack_offset = op.mem.disp;
							}
						}
					}
					else if (op_ptr[1] == '3' && op_ptr[2] == '0') {
						*ptr++ = 'l';
						*ptr++ = 'r';
					}
					else {
						do_replacement = false;
					}

					if (do_replacement) {
						op_ptr += 3;
						continue;
					}
				}
			}
			switch (*op_ptr) {
			case ' ':
			case '[':
				token_start = true;
				break;
			default:
				token_start = false;
				break;
			}
			*ptr++ = *op_ptr++;
		}
		*ptr = '\0';
	}

	return AsmTexts{ asm_texts, first_stack_limit_addr, max_param_stack_offset };
}

#endif

