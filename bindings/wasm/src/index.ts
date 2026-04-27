import {
  ApprovalProofCircuitGenerationErrorCode,
  ApprovalProofCircuitIdErrorCode,
  ApprovalProofError,
  ApprovalProofErrorStage,
  ApprovalProofProverErrorCode,
  ApprovalProofVerifierErrorCode,
} from "./errors.js";
import {
  encodeProverInput,
  encodeStatement,
  ProverInput,
  Statement,
} from "./layout.js";

interface NativeModule {
  HEAPU8: Uint8Array;
  _malloc(size: number): number;
  _free(ptr: number): void;
  _generate_approval_proof_v1_circuit(outPtrPtr: number, outLenPtr: number): number;
  _run_approval_proof_v1_prover_from_bytes(
    circuitPtr: number,
    circuitLen: number,
    inputPtr: number,
    inputLen: number,
    proofPtrPtr: number,
    proofLenPtr: number,
  ): number;
  _run_approval_proof_v1_verifier_from_bytes(
    circuitPtr: number,
    circuitLen: number,
    statementPtr: number,
    statementLen: number,
    proofPtr: number,
    proofLen: number,
  ): number;
  _approval_proof_v1_circuit_id(idPtr: number, circuitPtr: number, circuitLen: number): number;
  _approval_proof_v1_free(ptr: number): void;
  _approval_proof_v1_prover_error_string(code: number): number;
  _approval_proof_v1_verifier_error_string(code: number): number;
  _approval_proof_v1_circuit_generation_error_string(code: number): number;
  _approval_proof_v1_circuit_id_error_string(code: number): number;
  UTF8ToString(ptr: number): string;
  getValue(ptr: number, type: string): number;
}

type NativeModuleFactory = () => Promise<NativeModule>;

export class ApprovalProofV1Wasm {
  constructor(private readonly native: NativeModule) {}

  async generateCircuit(): Promise<Uint8Array> {
    const outPtrPtr = this.native._malloc(4);
    const outLenPtr = this.native._malloc(4);
    try {
      const code = this.native._generate_approval_proof_v1_circuit(outPtrPtr, outLenPtr);
      if (code !== ApprovalProofCircuitGenerationErrorCode.Success) {
        throw new ApprovalProofError(
          code as ApprovalProofCircuitGenerationErrorCode,
          ApprovalProofErrorStage.CircuitGeneration,
          this.native.UTF8ToString(
            this.native._approval_proof_v1_circuit_generation_error_string(code),
          ),
        );
      }
      const outPtr = this.native.getValue(outPtrPtr, "*");
      const outLen = this.native.getValue(outLenPtr, "i32");
      const bytes = this.native.HEAPU8.slice(outPtr, outPtr + outLen);
      this.native._approval_proof_v1_free(outPtr);
      return bytes;
    } finally {
      this.native._free(outPtrPtr);
      this.native._free(outLenPtr);
    }
  }

  async prove(circuit: Uint8Array, input: ProverInput): Promise<Uint8Array> {
    const inputBytes = encodeProverInput(input);
    return this.withInput(circuit, (circuitPtr, circuitLen) =>
      this.withInput(inputBytes, (inputPtr, inputLen) => {
        const outPtrPtr = this.native._malloc(4);
        const outLenPtr = this.native._malloc(4);
        try {
          const code = this.native._run_approval_proof_v1_prover_from_bytes(
            circuitPtr, circuitLen, inputPtr, inputLen, outPtrPtr, outLenPtr,
          );
          if (code !== ApprovalProofProverErrorCode.Success) {
            throw new ApprovalProofError(
              code as ApprovalProofProverErrorCode,
              ApprovalProofErrorStage.Prover,
              this.native.UTF8ToString(
                this.native._approval_proof_v1_prover_error_string(code),
              ),
            );
          }
          const outPtr = this.native.getValue(outPtrPtr, "*");
          const outLen = this.native.getValue(outLenPtr, "i32");
          const proof = this.native.HEAPU8.slice(outPtr, outPtr + outLen);
          this.native._approval_proof_v1_free(outPtr);
          return proof;
        } finally {
          this.native._free(outPtrPtr);
          this.native._free(outLenPtr);
        }
      }),
    );
  }

  async verify(circuit: Uint8Array, statement: Statement, proof: Uint8Array): Promise<void> {
    const statementBytes = encodeStatement(statement);
    await this.withInput(circuit, (circuitPtr, circuitLen) =>
      this.withInput(statementBytes, (statementPtr, statementLen) =>
        this.withInput(proof, (proofPtr, proofLen) => {
          const code = this.native._run_approval_proof_v1_verifier_from_bytes(
            circuitPtr, circuitLen, statementPtr, statementLen, proofPtr, proofLen,
          );
          if (code !== ApprovalProofVerifierErrorCode.Success) {
            throw new ApprovalProofError(
              code as ApprovalProofVerifierErrorCode,
              ApprovalProofErrorStage.Verifier,
              this.native.UTF8ToString(
                this.native._approval_proof_v1_verifier_error_string(code),
              ),
            );
          }
        }),
      ),
    );
  }

  async circuitID(circuit: Uint8Array): Promise<Uint8Array> {
    return this.withInput(circuit, (circuitPtr, circuitLen) => {
      const idPtr = this.native._malloc(32);
      try {
        const code = this.native._approval_proof_v1_circuit_id(idPtr, circuitPtr, circuitLen);
        if (code !== ApprovalProofCircuitIdErrorCode.Success) {
          throw new ApprovalProofError(
            code as ApprovalProofCircuitIdErrorCode,
            ApprovalProofErrorStage.CircuitId,
            this.native.UTF8ToString(
              this.native._approval_proof_v1_circuit_id_error_string(code),
            ),
          );
        }
        return this.native.HEAPU8.slice(idPtr, idPtr + 32);
      } finally {
        this.native._free(idPtr);
      }
    });
  }

  private withInput<T>(bytes: Uint8Array, body: (ptr: number, len: number) => T): T {
    const ptr = this.native._malloc(bytes.length);
    try {
      this.native.HEAPU8.set(bytes, ptr);
      return body(ptr, bytes.length);
    } finally {
      this.native._free(ptr);
    }
  }
}

export async function loadApprovalProofV1Wasm(): Promise<ApprovalProofV1Wasm> {
  const moduleUrl = new URL("../dist/attested_key_zk.mjs", import.meta.url);
  const { default: ModuleFactory } = await import(moduleUrl.href) as {
    default: NativeModuleFactory;
  };
  const native = await ModuleFactory();
  return new ApprovalProofV1Wasm(native as NativeModule);
}

export * from "./errors.js";
export * from "./layout.js";
