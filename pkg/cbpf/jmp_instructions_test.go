// Copyright 2024 Google LLC
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

package cbpf

import (
	pb "buzzer/proto/cbpf_go_proto"
	"testing"
)

func TestJmpInstructionGenerationAndEncoding(t *testing.T) {
	testK := int32(65535)
	tests := []struct {
		testName             string
		instruction          *pb.Instruction
		wantInstructionClass int32
		wantSrc              int32
		wantOperationCode    int32
		wantJmpTrue          int32
		wantJmpFalse         int32
		wantK                int32
	}{
		{
			testName:             "Encoding JmpJA Instruction",
			instruction:          JmpJA(1),
			wantInstructionClass: int32(pb.InsClass_InsClassJmp),
			wantSrc:              int32(pb.SrcOperand_Immediate),
			wantOperationCode:    int32(pb.JmpOperationCode_JmpJA),
			wantJmpTrue:          1,
			wantJmpFalse:         0,
			wantK:                0,
		},
		{
			testName:             "Encoding JmpEQ Instruction with Register as source",
			instruction:          JmpEQ(1, 2, X),
			wantInstructionClass: int32(pb.InsClass_InsClassJmp),
			wantSrc:              int32(pb.SrcOperand_RegSrc),
			wantOperationCode:    int32(pb.JmpOperationCode_JmpJEQ),
			wantJmpTrue:          1,
			wantJmpFalse:         2,
			wantK:                int32(X),
		},
		{
			testName:             "Encoding JmpEQ Instruction with Int as source",
			instruction:          JmpEQ(1, 2, testK),
			wantInstructionClass: int32(pb.InsClass_InsClassJmp),
			wantSrc:              int32(pb.SrcOperand_Immediate),
			wantOperationCode:    int32(pb.JmpOperationCode_JmpJEQ),
			wantJmpTrue:          1,
			wantJmpFalse:         2,
			wantK:                testK,
		},
		{
			testName:             "Encoding JmpGT Instruction with Register as source",
			instruction:          JmpGT(1, 2, X),
			wantInstructionClass: int32(pb.InsClass_InsClassJmp),
			wantSrc:              int32(pb.SrcOperand_RegSrc),
			wantOperationCode:    int32(pb.JmpOperationCode_JmpJGT),
			wantJmpTrue:          1,
			wantJmpFalse:         2,
			wantK:                int32(X),
		},
		{
			testName:             "Encoding JmpGT Instruction with Int as source",
			instruction:          JmpGT(1, 2, testK),
			wantInstructionClass: int32(pb.InsClass_InsClassJmp),
			wantSrc:              int32(pb.SrcOperand_Immediate),
			wantOperationCode:    int32(pb.JmpOperationCode_JmpJGT),
			wantJmpTrue:          1,
			wantJmpFalse:         2,
			wantK:                testK,
		},
		{
			testName:             "Encoding JmpGE Instruction with Register as source",
			instruction:          JmpGE(1, 2, X),
			wantInstructionClass: int32(pb.InsClass_InsClassJmp),
			wantSrc:              int32(pb.SrcOperand_RegSrc),
			wantOperationCode:    int32(pb.JmpOperationCode_JmpJGE),
			wantJmpTrue:          1,
			wantJmpFalse:         2,
			wantK:                int32(X),
		},
		{
			testName:             "Encoding JmpGE Instruction with Int as source",
			instruction:          JmpGE(1, 2, testK),
			wantInstructionClass: int32(pb.InsClass_InsClassJmp),
			wantSrc:              int32(pb.SrcOperand_Immediate),
			wantOperationCode:    int32(pb.JmpOperationCode_JmpJGE),
			wantJmpTrue:          1,
			wantJmpFalse:         2,
			wantK:                testK,
		},
		{
			testName:             "Encoding JmpSET Instruction with Register as source",
			instruction:          JmpSET(1, 2, X),
			wantInstructionClass: int32(pb.InsClass_InsClassJmp),
			wantSrc:              int32(pb.SrcOperand_RegSrc),
			wantOperationCode:    int32(pb.JmpOperationCode_JmpJSET),
			wantJmpTrue:          1,
			wantJmpFalse:         2,
			wantK:                int32(X),
		},
		{
			testName:             "Encoding JmpSET Instruction with Int as source",
			instruction:          JmpSET(1, 2, testK),
			wantInstructionClass: int32(pb.InsClass_InsClassJmp),
			wantSrc:              int32(pb.SrcOperand_Immediate),
			wantOperationCode:    int32(pb.JmpOperationCode_JmpJSET),
			wantJmpTrue:          1,
			wantJmpFalse:         2,
			wantK:                testK,
		},
	}
	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			instruction := tc.instruction
			t.Logf("Running test case %s", tc.testName)

			// The LSB are the instruction class
			ocClass := instruction.Opcode & 0x07

			// The fourth bit is the source operand
			ocSrc := instruction.Opcode & 0x08

			// The 4 MSB are the operation code
			ocCode := instruction.Opcode & 0xf0

			if ocClass != tc.wantInstructionClass {
				t.Fatalf("instruction.Opcode Class = %d, want %d", ocClass, tc.wantInstructionClass)
			}

			if ocSrc != tc.wantSrc {
				t.Fatalf("instruction.Opcode Source = %d, want %d", ocSrc, tc.wantSrc)
			}

			if ocCode != tc.wantOperationCode {
				t.Fatalf("instruction.Opcode Code = %d, want %d", ocCode, tc.wantOperationCode)
			}

			if instruction.Jt != tc.wantJmpTrue {
				t.Fatalf("instruction.jt = %d, want %d", instruction.Jt, tc.wantJmpTrue)
			}

			if instruction.Jf != tc.wantJmpFalse {
				t.Fatalf("instruction.jf = %d, want %d", instruction.Jf, tc.wantJmpFalse)
			}

			if instruction.K != tc.wantK {
				t.Fatalf("instruction.k = %d, want %d", instruction.K, tc.wantK)
			}

		})
	}
}
