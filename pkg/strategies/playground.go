package strategies

import (
	. "buzzer/pkg/ebpf/ebpf"
	"buzzer/pkg/units/units"
	epb "buzzer/proto/ebpf_go_proto"
	fpb "buzzer/proto/ffi_go_proto"
	"fmt"
//    btf "github.com/cilium/ebpf/btf"
)

func NewPlaygroundStrategy() *Playground {
	return &Playground{isFinished: false}
}

// Playground is a strategy meant for testing, users can generate Arbitrary
// programs and then the results of the verifier will be displayed on screen.
type Playground struct {
	isFinished bool
}

// GenerateProgram should return the instructions to feed the verifier.i

func (pg *Playground) GenerateProgram(ffi *units.FFI) (*epb.Program, error) {
	/*
	       call := &epb.Instruction{
	   		Opcode: &epb.Instruction_JmpOpcode{
	   			JmpOpcode: &epb.JmpOpcode{
	                   OperationCode:    epb.JmpOperationCode_JmpCALL,
	   				Source:           epb.SrcOperand_Immediate,
	   				InstructionClass: epb.InsClass_InsClassJmp,
	   			},
	   		},
	   		DstReg: R0,
	   		SrcReg: R1,
	   		// Oh protobuf why don't you have int16 support?, need to cast
	   		// this to int32 to make golang happy.
	   		Offset:    0,
	   		Immediate: 2,
	   		PseudoInstruction: &epb.Instruction_Empty{
	   			Empty: &epb.Empty{},
	   		},
	   	}
	           Mov(R0, 0),
	           Exit(),
	*/
	call := &epb.Instruction{
		Opcode: &epb.Instruction_MemOpcode{
			MemOpcode: &epb.MemOpcode{
				Mode:             epb.StLdMode_StLdModeIMM,
				Size:             epb.StLdSize_StLdSizeDW,
				InstructionClass: epb.InsClass_InsClassLd,
			},
		},
		DstReg:    R2,
		SrcReg:    epb.Reg_R4,
		Offset:    0,
		Immediate: 3,
		PseudoInstruction: &epb.Instruction_PseudoValue{
			PseudoValue: &epb.Instruction{
				Opcode: &epb.Instruction_MemOpcode{
					MemOpcode: &epb.MemOpcode{
						Mode:             0,
						Size:             0,
						InstructionClass: 0,
					},
				},
				DstReg:    0,
				SrcReg:    0,
				Offset:    0,
				Immediate: 0,
				PseudoInstruction: &epb.Instruction_Empty{
					Empty: &epb.Empty{},
				},
			},
		},
	}
	insn, err := InstructionSequence(
		Mov(R1, 1),
		call,
		Call(181),
		Exit(),
		Mov(R0, 0),
		Mov(R0, 0),
		Exit(),
	)
//    fmt.Println(btf.LoadKernelSpec())
	if err != nil {
		return nil, err
	}
	return &epb.Program{Instructions: insn}, nil
}

// OnVerifyDone process the results from the verifier. Here the strategy
// can also tell the fuzzer to continue with execution by returning true
// or start over and generate a new program by returning false.
func (pg *Playground) OnVerifyDone(ffi *units.FFI, verificationResult *fpb.ValidationResult) bool {
	fmt.Println(verificationResult.VerifierLog)
	pg.isFinished = true
	return true
}

// OnExecuteDone should validate if the program behaved like the
// verifier expected, if that was not the case it should return false.
func (pg *Playground) OnExecuteDone(ffi *units.FFI, executionResult *fpb.ExecutionResult) bool {
	return true
}

// OnError is used to determine if the fuzzer should continue on errors.
// true represents continue, false represents halt.
func (pg *Playground) OnError(e error) bool {
	fmt.Printf("error %v\n", e)
	return false
}

// IsFuzzingDone if true, buzzer will break out of the main fuzzing loop
// and return normally.
func (pg *Playground) IsFuzzingDone() bool {
	return pg.isFinished
}

// StrategyName is used for strategy selection via runtime flags.
func (pg *Playground) Name() string {
	return "playground"
}
