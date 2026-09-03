#pragma once
#include "Disassembler.h"

constexpr arm64_reg ToCapstoneReg(dart::Register r)
{
#define REG_CASE(n) case dart::Register::R##n: \
		return ARM64_REG_X##n

	switch (r) {
		REG_CASE(0); REG_CASE(1); REG_CASE(2); REG_CASE(3); REG_CASE(4);
		REG_CASE(5); REG_CASE(6); REG_CASE(7); REG_CASE(8); REG_CASE(9);
		REG_CASE(10); REG_CASE(11); REG_CASE(12); REG_CASE(13); REG_CASE(14);
		REG_CASE(15); REG_CASE(16); REG_CASE(17); REG_CASE(18); REG_CASE(19);
		REG_CASE(20); REG_CASE(21); REG_CASE(22); REG_CASE(23); REG_CASE(24);
		REG_CASE(25); REG_CASE(26); REG_CASE(27); REG_CASE(28); REG_CASE(29);
		REG_CASE(30);
	default:
		return ARM64_REG_INVALID;
	}
#undef REG_CASE
}

constexpr arm64_reg ToCapstoneReg(arm64_reg r)
{
#define REG_CASE(n) case ARM64_REG_X##n: \
	case ARM64_REG_W##n: \
		return ARM64_REG_X##n

	switch (r) {
		REG_CASE(0); REG_CASE(1); REG_CASE(2); REG_CASE(3); REG_CASE(4);
		REG_CASE(5); REG_CASE(6); REG_CASE(7); REG_CASE(8); REG_CASE(9);
		REG_CASE(10); REG_CASE(11); REG_CASE(12); REG_CASE(13); REG_CASE(14);
		REG_CASE(15); REG_CASE(16); REG_CASE(17); REG_CASE(18); REG_CASE(19);
		REG_CASE(20); REG_CASE(21); REG_CASE(22); REG_CASE(23); REG_CASE(24);
		REG_CASE(25); REG_CASE(26); REG_CASE(27); REG_CASE(28); REG_CASE(29);
		REG_CASE(30);
	case ARM64_REG_XZR:
	case ARM64_REG_WZR:
		return ARM64_REG_XZR;
	case ARM64_REG_SP:
		return ARM64_REG_SP;
	default:
		return ARM64_REG_INVALID;
	}
#undef REG_CASE
}

constexpr dart::Register ToDartReg(arm64_reg r)
{
#define REG_CASE(n) case ARM64_REG_X##n: \
	case ARM64_REG_W##n: \
		return dart::Register::R##n

	switch (r) {
		REG_CASE(0); REG_CASE(1); REG_CASE(2); REG_CASE(3); REG_CASE(4);
		REG_CASE(5); REG_CASE(6); REG_CASE(7); REG_CASE(8); REG_CASE(9);
		REG_CASE(10); REG_CASE(11); REG_CASE(12); REG_CASE(13); REG_CASE(14);
		REG_CASE(15); REG_CASE(16); REG_CASE(17); REG_CASE(18); REG_CASE(19);
		REG_CASE(20); REG_CASE(21); REG_CASE(22); REG_CASE(23); REG_CASE(24);
		REG_CASE(25); REG_CASE(26); REG_CASE(27); REG_CASE(28); REG_CASE(29);
		REG_CASE(30);
	case ARM64_REG_XZR:
	case ARM64_REG_WZR:
		return dart::Register::ZR;
	case ARM64_REG_SP:
		return dart::Register::CSP;
	default:
		return dart::Register::kNoRegister;
	}
#undef REG_CASE
}

constexpr arm64_reg CSREG_ARGS_DESC = ToCapstoneReg(dart::ARGS_DESC_REG);
constexpr arm64_reg CSREG_DART_SP = ToCapstoneReg(dart::SPREG);
constexpr arm64_reg CSREG_DART_FP = ToCapstoneReg(dart::FPREG);
constexpr arm64_reg CSREG_DART_LR = ToCapstoneReg(dart::Register::R30);
constexpr arm64_reg CSREG_DART_DISPATCH_TABLE = ToCapstoneReg(dart::DISPATCH_TABLE_REG);
constexpr arm64_reg CSREG_DART_NULL = ToCapstoneReg(dart::NULL_REG);
constexpr arm64_reg CSREG_DART_WB_OBJECT = ToCapstoneReg(dart::kWriteBarrierObjectReg);
constexpr arm64_reg CSREG_DART_WB_VALUE = ToCapstoneReg(dart::kWriteBarrierValueReg);
constexpr arm64_reg CSREG_DART_WB_SLOT = ToCapstoneReg(dart::kWriteBarrierSlotReg);
constexpr arm64_reg CSREG_DART_THR = ToCapstoneReg(dart::THR);
constexpr arm64_reg CSREG_DART_PP = ToCapstoneReg(dart::PP);
#if defined(DART_COMPRESSED_POINTERS)
constexpr arm64_reg CSREG_DART_HEAP = ToCapstoneReg(dart::HEAP_BITS);
#endif
constexpr arm64_reg CSREG_DART_TMP = ToCapstoneReg(dart::TMP);
constexpr arm64_reg CSREG_DART_TMP2 = ToCapstoneReg(dart::TMP2);

const char* GetCsRegisterName(arm64_reg reg);

inline constexpr uint32_t GetCsRegSize(arm64_reg reg){
	if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31)
		return 16;
	if ((reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) || reg == ARM64_REG_WZR)
		return 4;
	return 8;
}

namespace A64 {

class alignas(int32_t) Register {
public:
	enum Value : int32_t {
		R0 = 0,
		R1 = 1,
		R2 = 2,
		R3 = 3,
		R4 = 4,
		R5 = 5,
		R6 = 6,
		R7 = 7,
		R8 = 8,
		R9 = 9,
		R10 = 10,
		R11 = 11,
		R12 = 12,
		R13 = 13,
		R14 = 14,
		R15 = 15,
		R16 = 16,
		R17 = 17,
		R18 = 18,
		R19 = 19,
		R20 = 20,
		R21 = 21,
		R22 = 22,
		R23 = 23,
		R24 = 24,
		R25 = 25,
		R26 = 26,
		R27 = 27,
		R28 = 28,
		R29 = 29,
		R30 = 30,
		R31 = 31,
		V0 = 32,
		V1 = 33,
		V2 = 34,
		V3 = 35,
		V4 = 36,
		V5 = 37,
		V6 = 38,
		V7 = 39,
		V8 = 40,
		V9 = 41,
		V10 = 42,
		V11 = 43,
		V12 = 44,
		V13 = 45,
		V14 = 46,
		V15 = 47,
		V16 = 48,
		V17 = 49,
		V18 = 50,
		V19 = 51,
		V20 = 52,
		V21 = 53,
		V22 = 54,
		V23 = 55,
		V24 = 56,
		V25 = 57,
		V26 = 58,
		V27 = 59,
		V28 = 60,
		V29 = 61,
		V30 = 62,
		V31 = 63,
		kNumberOfRegisters = 64,
		kNoRegister = -1,

		VTMP = V31,

		CSP = 64,
		ZR = 65,
		NZCV = 66,

		TMP = R16,
		TMP2 = R17,
		FP = R29,
		LR = R30,
	};

	constexpr Register() : reg(kNoRegister) {}
	constexpr Register(Value reg) : reg(reg) {}
	constexpr Register(dart::Register r) {
		switch (r) {
#define REG_CASE(n) case dart::Register::R##n: \
		reg = R##n; break
			REG_CASE(0); REG_CASE(1); REG_CASE(2); REG_CASE(3); REG_CASE(4);
			REG_CASE(5); REG_CASE(6); REG_CASE(7); REG_CASE(8); REG_CASE(9);
			REG_CASE(10); REG_CASE(11); REG_CASE(12); REG_CASE(13); REG_CASE(14);
			REG_CASE(15); REG_CASE(16); REG_CASE(17); REG_CASE(18); REG_CASE(19);
			REG_CASE(20); REG_CASE(21); REG_CASE(22); REG_CASE(23); REG_CASE(24);
			REG_CASE(25); REG_CASE(26); REG_CASE(27); REG_CASE(28); REG_CASE(29);
			REG_CASE(30);
#undef REG_CASE
		case dart::Register::CSP:
			reg = CSP;
			break;
		case dart::Register::ZR:
			reg = ZR;
			break;
		default:
			reg = kNoRegister;
			break;
		}
	}
	constexpr Register(arm64_reg r) {
		switch (r) {
#define REG_CASE(n) case ARM64_REG_X##n: \
	case ARM64_REG_W##n: \
		reg = R##n; break
			REG_CASE(0); REG_CASE(1); REG_CASE(2); REG_CASE(3); REG_CASE(4);
			REG_CASE(5); REG_CASE(6); REG_CASE(7); REG_CASE(8); REG_CASE(9);
			REG_CASE(10); REG_CASE(11); REG_CASE(12); REG_CASE(13); REG_CASE(14);
			REG_CASE(15); REG_CASE(16); REG_CASE(17); REG_CASE(18); REG_CASE(19);
			REG_CASE(20); REG_CASE(21); REG_CASE(22); REG_CASE(23); REG_CASE(24);
			REG_CASE(25); REG_CASE(26); REG_CASE(27); REG_CASE(28); REG_CASE(29);
			REG_CASE(30);
#undef REG_CASE
		case ARM64_REG_XZR:
		case ARM64_REG_WZR:
			reg = ZR;
			break;
		case ARM64_REG_SP:
			reg = Register{ dart::SPREG }.reg;
			break;
		case ARM64_REG_NZCV:
			reg = NZCV;
			break;
#define REG_CASE(n) case ARM64_REG_V##n: \
	case ARM64_REG_Q##n: \
	case ARM64_REG_D##n: \
	case ARM64_REG_S##n: \
		reg = V##n; break
			REG_CASE(0); REG_CASE(1); REG_CASE(2); REG_CASE(3); REG_CASE(4);
			REG_CASE(5); REG_CASE(6); REG_CASE(7); REG_CASE(8); REG_CASE(9);
			REG_CASE(10); REG_CASE(11); REG_CASE(12); REG_CASE(13); REG_CASE(14);
			REG_CASE(15); REG_CASE(16); REG_CASE(17); REG_CASE(18); REG_CASE(19);
			REG_CASE(20); REG_CASE(21); REG_CASE(22); REG_CASE(23); REG_CASE(24);
			REG_CASE(25); REG_CASE(26); REG_CASE(27); REG_CASE(28); REG_CASE(29);
			REG_CASE(30); REG_CASE(31);
#undef REG_CASE
		default:
			reg = kNoRegister;
			break;
		}
	}

	constexpr bool operator==(Register a) const { return reg == a.reg; }
	constexpr bool operator!=(Register a) const { return reg != a.reg; }
	constexpr bool operator==(Value v) const { return reg == v; }
	constexpr bool operator!=(Value v) const { return reg != v; }

	inline bool Clear() {
		return reg = kNoRegister;
	}

	inline bool IsSet() const {
		return reg != kNoRegister;
	}

	inline bool IsDecimal() const {
		return reg >= V0 && reg <= V31;
	}

	static const char* RegisterNames[];

	inline const char* Name() const {
		ASSERT(reg != kNoRegister);
		return RegisterNames[reg];
	}

	constexpr operator int() const { return reg; }
	constexpr Value value() const {
		return reg;
	}

private:
	Value reg;
};

constexpr auto ARGS_DESC_REG = Register{ dart::ARGS_DESC_REG };
constexpr auto SP_REG = Register{ dart::SPREG };
constexpr auto TMP_REG = Register{ dart::TMP };
constexpr auto TMP2_REG = Register{ dart::TMP2 };
constexpr auto NULL_REG = Register{ dart::NULL_REG };
};

constexpr arm64_reg ToCapstoneReg(A64::Register r)
{
#define REG_CASE(n) case A64::Register::R##n: \
		return ARM64_REG_X##n

	switch (r.value()) {
		REG_CASE(0); REG_CASE(1); REG_CASE(2); REG_CASE(3); REG_CASE(4);
		REG_CASE(5); REG_CASE(6); REG_CASE(7); REG_CASE(8); REG_CASE(9);
		REG_CASE(10); REG_CASE(11); REG_CASE(12); REG_CASE(13); REG_CASE(14);
		REG_CASE(15); REG_CASE(16); REG_CASE(17); REG_CASE(18); REG_CASE(19);
		REG_CASE(20); REG_CASE(21); REG_CASE(22); REG_CASE(23); REG_CASE(24);
		REG_CASE(25); REG_CASE(26); REG_CASE(27); REG_CASE(28); REG_CASE(29);
		REG_CASE(30);
	default:
		return ARM64_REG_INVALID;
	}
#undef REG_CASE
}


class AsmInstruction {
private:
	cs_insn* insn;
public:
	class Operands {
		cs_arm64_op* operands;
		Operands(cs_arm64_op* operands) : operands(operands) {}
	public:
		const cs_arm64_op& operator[](size_t idx) const { return operands[idx]; }
		friend class AsmInstruction;
	} ops;

	AsmInstruction(cs_insn* insn) : insn((insn->id == ARM64_INS_NOP) ? ++insn : insn), ops(insn->detail->arm64.operands) {}
	AsmInstruction& operator=(const AsmInstruction&) = default;
	AsmInstruction& operator++() {
		++insn;
		if (insn->id == ARM64_INS_NOP)
			++insn;
		ops = insn->detail->arm64.operands;
		return *this;
	}
	AsmInstruction& operator--() {
		--insn;
		ops = insn->detail->arm64.operands;
		return *this;
	}
	AsmInstruction& operator+=(int cnt) {
		insn += cnt;
		if (insn->id == ARM64_INS_NOP)
			++insn;
		ops = insn->detail->arm64.operands;
		return *this;
	}
	AsmInstruction Next() { return AsmInstruction(insn + 1); }
	AsmInstruction Prev() { return AsmInstruction(insn - 1); }

	AsmInstruction MoveTo(uint64_t addr) {
		const auto offset = (addr - insn->address) / 4;
		return AsmInstruction(insn + offset);
	}

	friend inline bool operator==(const AsmInstruction& lhs, const AsmInstruction& rhs) {
		return lhs.insn->size == rhs.insn->size && memcmp(lhs.insn->bytes, rhs.insn->bytes, lhs.insn->size) == 0;
	}

	bool IsMovz() {
		return insn->id == ARM64_INS_MOVZ || (insn->id == ARM64_INS_MOV && op_count() == 2 && ops[1].type == ARM64_OP_IMM);
	}
	bool IsBranch(arm64_cc cond = ARM64_CC_INVALID) { return insn->id == ARM64_INS_B && cc() == cond; }
	bool IsDartArrayLoad() const {
		if (writeback())
			return false;
		switch (insn->id) {
		case ARM64_INS_LDUR:
		case ARM64_INS_LDRB:
			return true;
		}
		return false;
	}
	int GetLoadSize() {
		if (insn->id == ARM64_INS_LDRB || insn->id == ARM64_INS_LDURB)
			return 1;
		return GetCsRegSize(ops[0].reg);
	}
	bool IsDartArrayStore() const {
		if (writeback())
			return false;
		switch (insn->id) {
		case ARM64_INS_STUR:
		case ARM64_INS_STRB:
			return true;
		}
		return false;
	}
	int GetStoreSize() {
		if (insn->id == ARM64_INS_STRB || insn->id == ARM64_INS_STURB)
			return 1;
		return GetCsRegSize(ops[0].reg);
	}

	cs_insn* ptr() { return insn; }
	uint64_t address() const { return insn->address; }
	uint16_t size() const { return insn->size; }
	uint64_t NextAddress() const { return insn->address + insn->size; }
	unsigned int id() const { return insn->id; }
	arm64_cc cc() const { return insn->detail->arm64.cc; }
	bool writeback() const { return insn->detail->arm64.writeback; }
	uint8_t op_count() const { return insn->detail->arm64.op_count; }

	const char* mnemonic() const { return insn->mnemonic; }
	const char* op_str() const { return insn->op_str; }
};

struct AddrRange {
	uint64_t start{ 0 };
	uint64_t end{ 0 };

	AddrRange() = default;
	AddrRange(uint64_t start, uint64_t end) : start{ start }, end{ end } {}

	bool Has(uint64_t addr) const { return addr >= start && addr < end; }
};

class AsmIterator {
	cs_insn* insnStart;
	cs_insn* insnEnd;
	cs_insn* insn;
	cs_insn dummyInsnEnd;
public:
	AsmIterator(cs_insn* start, cs_insn* end) : insnStart(start), insnEnd(end), insn(insnStart) {
		dummyInsnEnd.id = 0;
		dummyInsnEnd.address = insnEnd->address + insnEnd->size;
		dummyInsnEnd.size = 0;
	}

	AsmIterator(AsmIterator& rhs, int64_t addr) : insnStart(rhs.insnStart), insnEnd(rhs.insnEnd) {
		const auto offset = (addr - rhs.insn->address) / 4;
		insn = rhs.insn + offset;
		dummyInsnEnd.id = 0;
		dummyInsnEnd.address = rhs.dummyInsnEnd.address;
		dummyInsnEnd.size = 0;
	}

	cs_insn* Current() { return insn; }
	void SetCurrent(cs_insn* ins) { insn = ins; }
	cs_insn* Next() {
		return operator++().insn;
	}
	AsmIterator& operator++() {
		ASSERT(insn != &dummyInsnEnd);
		if (insn == insnEnd) {
			insn = &dummyInsnEnd;
		}
		else {
			++insn;
			if (insn->id == ARM64_INS_NOP) {
				if (insn == insnEnd)
					insn = &dummyInsnEnd;
				else
					++insn;
			}
		}
		return *this;
	}
	AsmIterator& operator--() {
		--insn;
		return *this;
	}
	AddrRange Wrap(int64_t start) {
		return AddrRange(start, insn->address);
	}
	bool IsEnd() {
		return insn == &dummyInsnEnd;
	}

	bool IsMovz() const {
		return insn->id == ARM64_INS_MOVZ || (insn->id == ARM64_INS_MOV && op_count() == 2 && ops(1).type == ARM64_OP_IMM);
	}
	bool IsBranch(arm64_cc cond = ARM64_CC_INVALID) const { return insn->id == ARM64_INS_B && cc() == cond; }
	bool IsDartArrayLoad() const {
		if (writeback())
			return false;
		switch (insn->id) {
		case ARM64_INS_LDUR:
		case ARM64_INS_LDRB:
			return true;
		}
		return false;
	}
	int GetLoadSize() const {
		if (insn->id == ARM64_INS_LDRB || insn->id == ARM64_INS_LDURB)
			return 1;
		return GetCsRegSize(ops(0).reg);
	}
	bool IsDartArrayStore() const {
		if (writeback())
			return false;
		switch (insn->id) {
		case ARM64_INS_STUR:
		case ARM64_INS_STRB:
			return true;
		}
		return false;
	}
	int GetStoreSize() const {
		if (insn->id == ARM64_INS_STRB || insn->id == ARM64_INS_STURB)
			return 1;
		return GetCsRegSize(ops(0).reg);
	}

	uint64_t address() const { return insn->address; }
	uint16_t size() const { return insn->size; }
	uint64_t NextAddress() const { return insn->address + insn->size; }
	unsigned int id() const { return insn->id; }
	arm64_cc cc() const { return insn->detail->arm64.cc; }
	bool writeback() const { return insn->detail->arm64.writeback; }
	cs_arm64_op& ops(int i) const { return insn->detail->arm64.operands[i]; }
	uint8_t op_count() const { return insn->detail->arm64.op_count; }
};
