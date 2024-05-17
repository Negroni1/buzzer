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
	"reflect"
	"testing"

	pb "buzzer/proto/ebpf_go_proto"
	protobuf "github.com/golang/protobuf/proto"
)

func TestMemoryInstructionCorrectEncoding(t *testing.T) {
	testDstReg := pb.Reg_R9
	testSrcReg := pb.Reg_R0
	testImm := int32(1337)
	testOffset := int16(-8)
	tests := []struct {
		testName    string
		instruction *pb.Instruction

		wantDstReg           pb.Reg
		wantSrcReg           pb.Reg
		wantOffset           int16
		wantImm              int32
		wantInstructionClass pb.InsClass
		wantSize             pb.StLdSize
		wantMode             pb.StLdMode

		// The values for expected encoding are calculated manually
		wantEncoding []uint64
	}{
		{
			testName:             "Encoding StxDW Instruction",
			instruction:          StDW(testDstReg, testSrcReg, testOffset),
			wantMode:             pb.StLdMode_StLdModeMEM,
			wantSize:             pb.StLdSize_StLdSizeDW,
			wantInstructionClass: pb.InsClass_InsClassStx,
			wantOffset:           testOffset,
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantImm:              0,
			wantEncoding:         []uint64{0xfff8097b},
		},
		{
			testName:             "Encoding StDW Instruction",
			instruction:          StDW(testDstReg, testImm, testOffset),
			wantMode:             pb.StLdMode_StLdModeMEM,
			wantSize:             pb.StLdSize_StLdSizeDW,
			wantInstructionClass: pb.InsClass_InsClassSt,
			wantOffset:           testOffset,
			wantDstReg:           testDstReg,
			wantSrcReg:           UnusedField,
			wantImm:              testImm,
			wantEncoding:         []uint64{0x539fff8097a},
		},
		{
			testName:             "Encoding StxW Instruction",
			instruction:          StW(testDstReg, testSrcReg, testOffset),
			wantMode:             pb.StLdMode_StLdModeMEM,
			wantSize:             pb.StLdSize_StLdSizeW,
			wantInstructionClass: pb.InsClass_InsClassStx,
			wantOffset:           testOffset,
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantImm:              0,
			wantEncoding:         []uint64{0xfff80963},
		},
		{
			testName:             "Encoding StW Instruction",
			instruction:          StW(testDstReg, testImm, testOffset),
			wantMode:             pb.StLdMode_StLdModeMEM,
			wantSize:             pb.StLdSize_StLdSizeW,
			wantInstructionClass: pb.InsClass_InsClassSt,
			wantOffset:           testOffset,
			wantDstReg:           testDstReg,
			wantSrcReg:           UnusedField,
			wantImm:              testImm,
			wantEncoding:         []uint64{0x539fff80962},
		},
		{
			testName:             "Encoding StxH Instruction",
			instruction:          StH(testDstReg, testSrcReg, testOffset),
			wantMode:             pb.StLdMode_StLdModeMEM,
			wantSize:             pb.StLdSize_StLdSizeH,
			wantInstructionClass: pb.InsClass_InsClassStx,
			wantOffset:           testOffset,
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantImm:              0,
			wantEncoding:         []uint64{0xfff8096b},
		},
		{
			testName:             "Encoding StH Instruction",
			instruction:          StH(testDstReg, testImm, testOffset),
			wantMode:             pb.StLdMode_StLdModeMEM,
			wantSize:             pb.StLdSize_StLdSizeH,
			wantInstructionClass: pb.InsClass_InsClassSt,
			wantOffset:           testOffset,
			wantDstReg:           testDstReg,
			wantSrcReg:           UnusedField,
			wantImm:              testImm,
			wantEncoding:         []uint64{0x539fff8096a},
		},
		{
			testName:             "Encoding StxB Instruction",
			instruction:          StB(testDstReg, testSrcReg, testOffset),
			wantMode:             pb.StLdMode_StLdModeMEM,
			wantSize:             pb.StLdSize_StLdSizeB,
			wantInstructionClass: pb.InsClass_InsClassStx,
			wantOffset:           testOffset,
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantImm:              0,
			wantEncoding:         []uint64{0xfff80973},
		},
		{
			testName:             "Encoding StB Instruction",
			instruction:          StB(testDstReg, testImm, testOffset),
			wantMode:             pb.StLdMode_StLdModeMEM,
			wantSize:             pb.StLdSize_StLdSizeB,
			wantInstructionClass: pb.InsClass_InsClassSt,
			wantOffset:           testOffset,
			wantDstReg:           testDstReg,
			wantSrcReg:           UnusedField,
			wantImm:              testImm,
			wantEncoding:         []uint64{0x539fff80972},
		},
		{
			testName:             "Encoding LdxDW Instruction",
			instruction:          LdDW(testDstReg, testSrcReg, testOffset),
			wantMode:             pb.StLdMode_StLdModeMEM,
			wantSize:             pb.StLdSize_StLdSizeDW,
			wantInstructionClass: pb.InsClass_InsClassLdx,
			wantOffset:           testOffset,
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantImm:              0,
			wantEncoding:         []uint64{0xfff80979},
		},
		{
			testName:             "Encoding LdxW Instruction",
			instruction:          LdW(testDstReg, testSrcReg, testOffset),
			wantMode:             pb.StLdMode_StLdModeMEM,
			wantSize:             pb.StLdSize_StLdSizeW,
			wantInstructionClass: pb.InsClass_InsClassLdx,
			wantOffset:           testOffset,
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantImm:              0,
			wantEncoding:         []uint64{0xfff80961},
		},
		{
			testName:             "Encoding LdxH Instruction",
			instruction:          LdH(testDstReg, testSrcReg, testOffset),
			wantMode:             pb.StLdMode_StLdModeMEM,
			wantSize:             pb.StLdSize_StLdSizeH,
			wantInstructionClass: pb.InsClass_InsClassLdx,
			wantOffset:           testOffset,
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantImm:              0,
			wantEncoding:         []uint64{0xfff80969},
		},
		{
			testName:             "Encoding LdxB Instruction",
			instruction:          LdB(testDstReg, testSrcReg, testOffset),
			wantMode:             pb.StLdMode_StLdModeMEM,
			wantSize:             pb.StLdSize_StLdSizeB,
			wantInstructionClass: pb.InsClass_InsClassLdx,
			wantOffset:           testOffset,
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantImm:              0,
			wantEncoding:         []uint64{0xfff80971},
		},
		{
			testName:             "Encoding LdMapByFd Instruction",
			instruction:          LdMapByFd(testDstReg, 42),
			wantMode:             pb.StLdMode_StLdModeIMM,
			wantSize:             pb.StLdSize_StLdSizeDW,
			wantInstructionClass: pb.InsClass_InsClassLd,
			wantOffset:           0,
			wantDstReg:           testDstReg,
			wantSrcReg:           PseudoMapFD,
			wantImm:              42,
			wantEncoding:         []uint64{0x2a00001918, 0},
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			t.Logf("Running test case %s", tc.testName)

			instruction := tc.instruction
			var opcode *pb.MemOpcode
			switch o := instruction.Opcode.(type) {
			case *pb.Instruction_MemOpcode:
				opcode = o.MemOpcode
			default:
				t.Fatalf("could not convert opcode to mem type, proto: %s", protobuf.MarshalTextString(instruction))

			}

			if opcode.Mode != tc.wantMode {
				t.Errorf("instruction.mode = %d, want = %d", opcode.Mode, tc.wantMode)
			}

			if opcode.Size != tc.wantSize {
				t.Errorf("instruction.Size = %d, want = %d", opcode.Size, tc.wantSize)
			}

			if opcode.InstructionClass != tc.wantInstructionClass {
				t.Errorf("instruction.InstructionClass = %d, want = %d", opcode.InstructionClass, tc.wantInstructionClass)
			}

			if instruction.Offset != int32(tc.wantOffset) {
				t.Errorf("instruction.Offset = %d, want = %d", instruction.Offset, tc.wantOffset)
			}

			if instruction.DstReg != tc.wantDstReg {
				t.Errorf("instruction.DstReg = %v, want = %v", instruction.DstReg, tc.wantDstReg)
			}

			if instruction.SrcReg != tc.wantSrcReg {
				t.Errorf("instruction.SrcReg = %v, want = %v", instruction.SrcReg, tc.wantSrcReg)
			}

			if instruction.Immediate != tc.wantImm {
				t.Errorf("instruction.Imm = %d, want = %d", instruction.Immediate, tc.wantImm)
			}

			encodingArray, err := encodeInstruction(instruction)

			if err != nil {
				t.Fatalf("unexpected error when ecoding: %v", err)
			}

			if !reflect.DeepEqual(encodingArray, tc.wantEncoding) {
				t.Errorf("operation.generateBytecode() = %x, want %x", encodingArray, tc.wantEncoding)
			}
		})
	}
}
