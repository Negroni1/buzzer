// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ebpf

import (
	"fmt"
)

// IMMJMPOperation Represents an eBPF jump (branching) operation.
type IMMJMPOperation struct {
	instructionNumber uint32

	// Instruction that this instance represents.
	Instruction uint8

	// InsClass is the instruction class of this instance.
	InsClass uint8

	// DstReg is from where the value to compare for the jump will be taken.
	DstReg uint8

	// Imm is the immediate value that will be used as the other comparing
	// operand.
	Imm int32

	// TrueBranchNextInstr instruction that will be executed if the operation
	// evaluates to true.
	TrueBranchNextInstr Operation
	trueBranchGenerator func(prog *Program) Operation

	// FalseBranchNextInstr is the instruction that will be executed if
	// the operation evaluates to false.
	FalseBranchNextInstr Operation

	// FalseBranchSize is how many instructions there are in the false
	// branch.
	FalseBranchSize      int16
	falseBranchGenerator func(prog *Program) (Operation, int16)
}

// GenerateBytecode generates the bytecode associated with this instruction.
func (c *IMMJMPOperation) GenerateBytecode() []uint64 {
	bytecode := []uint64{encodeImmediateJmpOperation(c.Instruction, c.InsClass, c.DstReg, c.Imm, c.FalseBranchSize)}
	if c.FalseBranchNextInstr != nil {
		// Only take the `c.FalseBranchSize` number of opcodes of the
		// false brach generated bytecode.
		falseBranchBytecode := c.FalseBranchNextInstr.GenerateBytecode()[0:c.FalseBranchSize]
		bytecode = append(bytecode, falseBranchBytecode...)
	}
	if c.TrueBranchNextInstr != nil {
		bytecode = append(bytecode, c.TrueBranchNextInstr.GenerateBytecode()...)
	}
	return bytecode
}

// GenerateNextInstruction uses the prog generator to create the rest of the tree.
func (c *IMMJMPOperation) GenerateNextInstruction(prog *Program) {
	if c.FalseBranchNextInstr != nil {
		c.FalseBranchNextInstr.GenerateNextInstruction(prog)
	} else if c.falseBranchGenerator != nil {
		nextInstr, bSize := c.falseBranchGenerator(prog)
		c.FalseBranchNextInstr = nextInstr
		c.FalseBranchSize = bSize
	}

	if c.TrueBranchNextInstr != nil {
		c.TrueBranchNextInstr.GenerateNextInstruction(prog)
	} else if c.trueBranchGenerator != nil {
		c.TrueBranchNextInstr = c.trueBranchGenerator(prog)
	}
}

// NumerateInstruction sets the instruction number recursively
func (c *IMMJMPOperation) NumerateInstruction(instrNo uint32) int {
	c.instructionNumber = instrNo
	instrNo++

	// This logic will result in us traversing the tree in dfs twice
	// (if we also need to traverse the true branch). But for now
	// this is the best idea I can come up with to numerate instructions
	// on conditional branches.
	if c.FalseBranchNextInstr != nil {
		c.FalseBranchNextInstr.NumerateInstruction(instrNo)
	}

	instrNo += uint32(c.FalseBranchSize)

	if c.TrueBranchNextInstr != nil {
		return 1 + int(c.FalseBranchSize) + c.TrueBranchNextInstr.NumerateInstruction(instrNo)
	}

	return 1 + int(c.FalseBranchSize)
}

// SetNextInstruction manually sets the next instruction.
func (c *IMMJMPOperation) SetNextInstruction(next Operation) {
	// For now, always pass the next instruction to the true branch.
	if c.TrueBranchNextInstr != nil {
		c.TrueBranchNextInstr.SetNextInstruction(next)
	} else {
		c.TrueBranchNextInstr = next
	}
}

// GeneratePoc generates the C macros to repro this program.
func (c *IMMJMPOperation) GeneratePoc() []string {
	if c.Instruction == JmpExit {
		return []string{"BPF_EXIT_INSN()"}
	}
	var insClass string
	if c.InsClass == InsClassJmp {
		insClass = "BPF_JMP"
	} else {
		insClass = "BPF_JMP32"
	}
	insName := NameForJmpInstruction(c.Instruction)
	regName := NameForBPFRegister(c.DstReg)
	macro := fmt.Sprintf("BPF_JMP_IMM(%s, /*dst=*/%s, /*imm=*/%d, /*off=*/%d, /*ins_class=*/%s)", insName, regName, c.Imm, c.FalseBranchSize, insClass)
	r := []string{macro}
	if c.FalseBranchNextInstr != nil {
		r = append(r, c.FalseBranchNextInstr.GeneratePoc()...)
	}
	if c.TrueBranchNextInstr != nil {
		r = append(r, c.TrueBranchNextInstr.GeneratePoc()...)
	}
	return r
}

// ExitOperation Terminates the execution of a given program.
func ExitOperation() Operation {
	return &IMMJMPOperation{Instruction: JmpExit, InsClass: InsClassJmp, Imm: UnusedField}
}

// GuardJump Generates a jmp instruction where false branch of the jump will
// terminate the program.
func GuardJump(ins, insClass, dstReg uint8, imm int32) *IMMJMPOperation {
	jmp := &IMMJMPOperation{Instruction: ins, InsClass: insClass, Imm: imm, DstReg: dstReg}
	jmp.falseBranchGenerator = func(prog *Program) (Operation, int16) {
		// We return 1 because an Exit Operation has 1 opcode.
		return ExitOperation(), 1
	}
	jmp.trueBranchGenerator = func(prog *Program) Operation {
		return prog.Gen.GenerateNextInstruction(prog)
	}
	return jmp
}

// CallOperation represents a call to an ebpf auxiliary function.
type CallOperation struct {
	instructionNumber uint32
	fnNumber          int32

	nextInstr Operation
}

// GenerateBytecode generates the bytecode associated with this instruction.
func (c *CallOperation) GenerateBytecode() []uint64 {
	bytecode := []uint64{encodeImmediateJmpOperation(JmpCALL, InsClassJmp, UnusedField, c.fnNumber /*offset=*/, 0)}
	if c.nextInstr != nil {
		bytecode = append(bytecode, c.nextInstr.GenerateBytecode()...)
	}
	return bytecode
}

// GenerateNextInstruction uses the prog generator to create the rest of the tree.
func (c *CallOperation) GenerateNextInstruction(prog *Program) {
	if c.nextInstr != nil {
		c.nextInstr.GenerateNextInstruction(prog)
	} else {
		c.nextInstr = prog.Gen.GenerateNextInstruction(prog)
	}
}

// NumerateInstruction sets the instruction number recursively
func (c *CallOperation) NumerateInstruction(instrNo uint32) int {
	c.instructionNumber = instrNo
	instrNo++
	if c.nextInstr != nil {
		return 1 + c.nextInstr.NumerateInstruction(instrNo)
	}
	return 1
}

// SetNextInstruction manually sets the next instruction.
func (c *CallOperation) SetNextInstruction(next Operation) {
	if c.nextInstr != nil {
		c.nextInstr.SetNextInstruction(next)
	} else {
		c.nextInstr = next
	}
}

// GeneratePoc generates the C macros to repro this program.
func (c *CallOperation) GeneratePoc() []string {
	macro := fmt.Sprintf("BPF_CALL_FUNC(%s)", GetBpfFuncName(c.fnNumber))
	r := []string{macro}
	if c.nextInstr != nil {
		r = append(r, c.nextInstr.GeneratePoc()...)
	}
	return r
}

// CallFunction is an auxiliary function that returns an EBPFCallOperation
// structure.
func CallFunction(functionValue int32) Operation {
	return &CallOperation{fnNumber: functionValue}
}

// RegJMPOperation Represents an eBPF jump (branching) operation.
type RegJMPOperation struct {
	instructionNumber uint32

	// Instruction that this instance represents.
	Instruction uint8

	// InsClass is the instruction class of this instance.
	InsClass uint8

	// DstReg is from where the value to compare for the jump will be taken.
	DstReg uint8

	// SrcReg holds the value that will be used as the other comparing
	// operand.
	SrcReg uint8

	// TrueBranchNextInstr instruction that will be executed if the operation
	// evaluates to true.
	TrueBranchNextInstr Operation
	trueBranchGenerator func(prog *Program) Operation

	// FalseBranchNextInstr is the instruction that will be executed if
	// the operation evaluates to false.
	FalseBranchNextInstr Operation

	// FalseBranchSize is how many instructions there are in the false
	// branch.
	FalseBranchSize      int16
	falseBranchGenerator func(prog *Program) (Operation, int16)
}

// GenerateBytecode generates the bytecode for this instruction.
func (c *RegJMPOperation) GenerateBytecode() []uint64 {
	bytecode := []uint64{encodeRegisterJmpOperation(c.Instruction, c.InsClass, c.DstReg, c.SrcReg, c.FalseBranchSize)}
	if c.FalseBranchNextInstr != nil {
		// Only take the `c.FalseBranchSize` number of opcodes of the
		// false brach generated bytecode.
		falseBranchBytecode := c.FalseBranchNextInstr.GenerateBytecode()[0:c.FalseBranchSize]
		bytecode = append(bytecode, falseBranchBytecode...)
	}
	if c.TrueBranchNextInstr != nil {
		bytecode = append(bytecode, c.TrueBranchNextInstr.GenerateBytecode()...)
	}
	return bytecode
}

// GenerateNextInstruction builds the next instruction for this operation.
func (c *RegJMPOperation) GenerateNextInstruction(prog *Program) {
	if c.FalseBranchNextInstr != nil {
		c.FalseBranchNextInstr.GenerateNextInstruction(prog)
	} else if c.falseBranchGenerator != nil {
		nextInstr, bSize := c.falseBranchGenerator(prog)
		c.FalseBranchNextInstr = nextInstr
		c.FalseBranchSize = bSize
	}

	if c.TrueBranchNextInstr != nil {
		c.TrueBranchNextInstr.GenerateNextInstruction(prog)
	} else if c.trueBranchGenerator != nil {
		c.TrueBranchNextInstr = c.trueBranchGenerator(prog)
	}
}

// SetNextInstruction sets the next instruction for this operation.
func (c *RegJMPOperation) SetNextInstruction(next Operation) {
	// For now, always pass the next instruction to the true branch.
	if c.TrueBranchNextInstr != nil {
		c.TrueBranchNextInstr.SetNextInstruction(next)
	} else {
		c.TrueBranchNextInstr = next
	}
}

// NumerateInstruction sets the instruction numbers recursively.
func (c *RegJMPOperation) NumerateInstruction(instrNo uint32) int {
	c.instructionNumber = instrNo
	instrNo++

	// This logic will result in us traversing the tree in dfs twice
	// (if we also need to traverse the true branch). But for now
	// this is the best idea I can come up with to numerate instructions
	// on conditional branches.
	if c.FalseBranchNextInstr != nil {
		c.FalseBranchNextInstr.NumerateInstruction(instrNo)
	}

	instrNo += uint32(c.FalseBranchSize)

	if c.TrueBranchNextInstr != nil {
		return 1 + int(c.FalseBranchSize) + c.TrueBranchNextInstr.NumerateInstruction(instrNo)
	}

	return 1 + int(c.FalseBranchSize)
}

// GeneratePoc generates the C macros to repro this program.
func (c *RegJMPOperation) GeneratePoc() []string {
	var insClass string
	if c.InsClass == InsClassJmp {
		insClass = "BPF_JMP"
	} else {
		insClass = "BPF_JMP32"
	}
	insName := NameForJmpInstruction(c.Instruction)
	dstRegName := NameForBPFRegister(c.DstReg)
	srcRegName := NameForBPFRegister(c.SrcReg)
	macro := fmt.Sprintf("BPF_JMP_REG(%s, /*dst=*/%s, /*src=*/%s, /*off=*/%d, /*ins_class=*/%s)", insName, dstRegName, srcRegName, c.FalseBranchSize, insClass)
	r := []string{macro}
	if c.FalseBranchNextInstr != nil {
		r = append(r, c.FalseBranchNextInstr.GeneratePoc()...)
	}
	if c.TrueBranchNextInstr != nil {
		r = append(r, c.TrueBranchNextInstr.GeneratePoc()...)
	}
	return r
}
