import CAttestedKeyZK
import Foundation

public enum ApprovalProofV1ZKError: Error, CustomStringConvertible {
    case invalidLength(field: String, expected: Int, actual: Int)
    case circuitGeneration(code: Int32, message: String)
    case prover(code: Int32, message: String)
    case verifier(code: Int32, message: String)
    case circuitID(code: Int32, message: String)

    public var description: String {
        switch self {
        case let .invalidLength(field, expected, actual):
            return "\(field) length \(actual), expected \(expected)"
        case let .circuitGeneration(_, message):
            return "circuit generation: \(message)"
        case let .prover(_, message):
            return "prover: \(message)"
        case let .verifier(_, message):
            return "verifier: \(message)"
        case let .circuitID(_, message):
            return "circuit id: \(message)"
        }
    }
}

public enum ApprovalProofV1ZK {
    public static let hashLength = 32
    public static let p256CoordLength = 32
    public static let signatureLength = 64
    public static let policyVersionLength = 4
    public static let timeLength = 8
    public static let domainLength = 16
    public static let attestationLength = 136
    public static let approvalAssertionLength = 120
    public static let statementLength = 204
    public static let proverInputLength = 588

    public static let attestationDomain = Data("AKZK-ATTEST-KEY1".utf8)
    public static let approvalAssertionDomain = Data("AKZK-APPROVAL-V1".utf8)

    public struct Statement: Sendable {
        public let issuerPublicKeyX: Data
        public let issuerPublicKeyY: Data
        public let appIDHash: Data
        public let policyVersion: Data
        public let now: Data
        public let challengeNonce: Data
        public let audienceHash: Data
        public let approvalHash: Data

        public init(
            issuerPublicKeyX: Data,
            issuerPublicKeyY: Data,
            appIDHash: Data,
            policyVersion: Data,
            now: Data,
            challengeNonce: Data,
            audienceHash: Data,
            approvalHash: Data
        ) throws {
            try ApprovalProofV1ZK.expectLength(issuerPublicKeyX, field: "issuerPublicKeyX", expected: p256CoordLength)
            try ApprovalProofV1ZK.expectLength(issuerPublicKeyY, field: "issuerPublicKeyY", expected: p256CoordLength)
            try ApprovalProofV1ZK.expectLength(appIDHash, field: "appIDHash", expected: hashLength)
            try ApprovalProofV1ZK.expectLength(policyVersion, field: "policyVersion", expected: policyVersionLength)
            try ApprovalProofV1ZK.expectLength(now, field: "now", expected: timeLength)
            try ApprovalProofV1ZK.expectLength(challengeNonce, field: "challengeNonce", expected: hashLength)
            try ApprovalProofV1ZK.expectLength(audienceHash, field: "audienceHash", expected: hashLength)
            try ApprovalProofV1ZK.expectLength(approvalHash, field: "approvalHash", expected: hashLength)
            self.issuerPublicKeyX = issuerPublicKeyX
            self.issuerPublicKeyY = issuerPublicKeyY
            self.appIDHash = appIDHash
            self.policyVersion = policyVersion
            self.now = now
            self.challengeNonce = challengeNonce
            self.audienceHash = audienceHash
            self.approvalHash = approvalHash
        }

        public func serialized() -> Data {
            var out = Data(capacity: statementLength)
            out.append(issuerPublicKeyX)
            out.append(issuerPublicKeyY)
            out.append(appIDHash)
            out.append(policyVersion)
            out.append(now)
            out.append(challengeNonce)
            out.append(audienceHash)
            out.append(approvalHash)
            return out
        }
    }

    public struct ProverInput: Sendable {
        public let statement: Statement
        public let attestation: Data
        public let attestationSignature: Data
        public let approvalAssertion: Data
        public let approvalAssertionSignature: Data

        public init(
            statement: Statement,
            attestation: Data,
            attestationSignature: Data,
            approvalAssertion: Data,
            approvalAssertionSignature: Data
        ) throws {
            try ApprovalProofV1ZK.expectLength(attestation, field: "attestation", expected: attestationLength)
            try ApprovalProofV1ZK.expectLength(attestationSignature, field: "attestationSignature", expected: signatureLength)
            try ApprovalProofV1ZK.expectLength(approvalAssertion, field: "approvalAssertion", expected: approvalAssertionLength)
            try ApprovalProofV1ZK.expectLength(approvalAssertionSignature, field: "approvalAssertionSignature", expected: signatureLength)
            self.statement = statement
            self.attestation = attestation
            self.attestationSignature = attestationSignature
            self.approvalAssertion = approvalAssertion
            self.approvalAssertionSignature = approvalAssertionSignature
        }

        public func serialized() -> Data {
            var out = Data(capacity: proverInputLength)
            out.append(statement.serialized())
            out.append(attestation)
            out.append(attestationSignature)
            out.append(approvalAssertion)
            out.append(approvalAssertionSignature)
            return out
        }
    }

    public static func uint64BE(_ value: UInt64) -> Data {
        var bigEndian = value.bigEndian
        return Data(bytes: &bigEndian, count: MemoryLayout<UInt64>.size)
    }

    public static func buildAttestation(
        statement: Statement,
        devicePublicKeyX: Data,
        devicePublicKeyY: Data,
        notBefore: UInt64,
        notAfter: UInt64
    ) throws -> Data {
        try expectLength(devicePublicKeyX, field: "devicePublicKeyX", expected: p256CoordLength)
        try expectLength(devicePublicKeyY, field: "devicePublicKeyY", expected: p256CoordLength)
        var out = Data(count: attestationLength)
        out.replaceSubrange(0..<16, with: attestationDomain)
        out.replaceSubrange(16..<48, with: statement.appIDHash)
        out.replaceSubrange(48..<52, with: statement.policyVersion)
        // The in-circuit assertion at src/approval_proof_v1_zk.cc:218-219
        // rejects any key_class other than 1 (kSecureHardwareP256). Match
        // the Go binding by hardcoding it here -- callers cannot pick a
        // different value today, and a future spec extension will land
        // alongside an in-circuit change.
        out[52] = UInt8(kApprovalProofV1KeyClassSecureHardwareP256)
        out.replaceSubrange(56..<64, with: uint64BE(notBefore))
        out.replaceSubrange(64..<72, with: uint64BE(notAfter))
        out.replaceSubrange(72..<104, with: devicePublicKeyX)
        out.replaceSubrange(104..<136, with: devicePublicKeyY)
        return out
    }

    public static func buildApprovalAssertion(
        statement: Statement,
        expiresAt: UInt64
    ) -> Data {
        var out = Data(count: approvalAssertionLength)
        out.replaceSubrange(0..<16, with: approvalAssertionDomain)
        out.replaceSubrange(16..<48, with: statement.challengeNonce)
        out.replaceSubrange(48..<80, with: statement.audienceHash)
        out.replaceSubrange(80..<112, with: statement.approvalHash)
        out.replaceSubrange(112..<120, with: uint64BE(expiresAt))
        return out
    }

    public static func generateCircuit() throws -> Data {
        var circuitPtr: UnsafeMutablePointer<UInt8>?
        var circuitLen: size_t = 0
        let code = generate_approval_proof_v1_circuit(&circuitPtr, &circuitLen)
        guard code == APPROVAL_PROOF_V1_CIRCUIT_GENERATION_SUCCESS else {
            throw ApprovalProofV1ZKError.circuitGeneration(
                code: Int32(code.rawValue),
                message: String(cString: approval_proof_v1_circuit_generation_error_string(code))
            )
        }
        guard let circuitPtr else {
            throw ApprovalProofV1ZKError.circuitGeneration(code: -1, message: "library returned nil circuit")
        }
        defer { approval_proof_v1_free(circuitPtr) }
        return Data(bytes: circuitPtr, count: Int(circuitLen))
    }

    public static func prove(circuit: Data, input: ProverInput) throws -> Data {
        let inputBytes = input.serialized()
        return try withBytes(circuit) { circuitPtr in
            try withBytes(inputBytes) { inputPtr in
                var proofPtr: UnsafeMutablePointer<UInt8>?
                var proofLen: size_t = 0
                let code = run_approval_proof_v1_prover_from_bytes(
                    circuitPtr, circuit.count,
                    inputPtr, inputBytes.count,
                    &proofPtr, &proofLen
                )
                guard code == APPROVAL_PROOF_V1_PROVER_SUCCESS else {
                    throw ApprovalProofV1ZKError.prover(
                        code: Int32(code.rawValue),
                        message: String(cString: approval_proof_v1_prover_error_string(code))
                    )
                }
                guard let proofPtr else {
                    throw ApprovalProofV1ZKError.prover(code: -1, message: "library returned nil proof")
                }
                defer { approval_proof_v1_free(proofPtr) }
                return Data(bytes: proofPtr, count: Int(proofLen))
            }
        }
    }

    public static func verify(circuit: Data, statement: Statement, proof: Data) throws {
        let statementBytes = statement.serialized()
        let code = withBytes(circuit) { circuitPtr in
            withBytes(statementBytes) { statementPtr in
                withBytes(proof) { proofPtr in
                    run_approval_proof_v1_verifier_from_bytes(
                        circuitPtr, circuit.count,
                        statementPtr, statementBytes.count,
                        proofPtr, proof.count
                    )
                }
            }
        }
        guard code == APPROVAL_PROOF_V1_VERIFIER_SUCCESS else {
            throw ApprovalProofV1ZKError.verifier(
                code: Int32(code.rawValue),
                message: String(cString: approval_proof_v1_verifier_error_string(code))
            )
        }
    }

    public static func circuitID(circuit: Data) throws -> Data {
        var out = Data(count: hashLength)
        let code = withBytes(circuit) { circuitPtr in
            out.withUnsafeMutableBytes { outBytes in
                approval_proof_v1_circuit_id(
                    outBytes.bindMemory(to: UInt8.self).baseAddress,
                    circuitPtr,
                    circuit.count
                )
            }
        }
        guard code == APPROVAL_PROOF_V1_CIRCUIT_ID_SUCCESS else {
            throw ApprovalProofV1ZKError.circuitID(
                code: Int32(code.rawValue),
                message: String(cString: approval_proof_v1_circuit_id_error_string(code))
            )
        }
        return out
    }

    private static func withBytes<T>(_ data: Data, _ body: (UnsafePointer<UInt8>?) throws -> T) rethrows -> T {
        try data.withUnsafeBytes { rawBuffer in
            try body(rawBuffer.bindMemory(to: UInt8.self).baseAddress)
        }
    }

    private static func expectLength(_ data: Data, field: String, expected: Int) throws {
        guard data.count == expected else {
            throw ApprovalProofV1ZKError.invalidLength(field: field, expected: expected, actual: data.count)
        }
    }
}
