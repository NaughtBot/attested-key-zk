import AttestedKeyZK
import CryptoKit
import XCTest

final class AttestedKeyZKTests: XCTestCase {
    func testProveAndVerify() throws {
        let input = try makeInput()
        let circuit = try ApprovalProofV1ZK.generateCircuit()
        let proof = try ApprovalProofV1ZK.prove(circuit: circuit, input: input)
        try ApprovalProofV1ZK.verify(circuit: circuit, statement: input.statement, proof: proof)
    }

    func testRejectMismatchedNonce() throws {
        let input = try makeInput()
        let circuit = try ApprovalProofV1ZK.generateCircuit()
        let proof = try ApprovalProofV1ZK.prove(circuit: circuit, input: input)

        var wrongNonce = Data(input.statement.challengeNonce)
        wrongNonce[0] ^= 0xff
        let wrong = try ApprovalProofV1ZK.Statement(
            issuerPublicKeyX: input.statement.issuerPublicKeyX,
            issuerPublicKeyY: input.statement.issuerPublicKeyY,
            appIDHash: input.statement.appIDHash,
            policyVersion: input.statement.policyVersion,
            now: input.statement.now,
            challengeNonce: wrongNonce,
            audienceHash: input.statement.audienceHash,
            approvalHash: input.statement.approvalHash
        )

        XCTAssertThrowsError(try ApprovalProofV1ZK.verify(circuit: circuit, statement: wrong, proof: proof))
    }

    func testStatementInitRejectsTruncatedField() {
        XCTAssertThrowsError(try ApprovalProofV1ZK.Statement(
            issuerPublicKeyX: Data(repeating: 0, count: 16),  // wrong length
            issuerPublicKeyY: Data(repeating: 0, count: 32),
            appIDHash: Data(repeating: 0, count: 32),
            policyVersion: Data([0, 0, 0, 1]),
            now: ApprovalProofV1ZK.uint64BE(1000),
            challengeNonce: Data(repeating: 0, count: 32),
            audienceHash: Data(repeating: 0, count: 32),
            approvalHash: Data(repeating: 0, count: 32)
        )) { error in
            guard case ApprovalProofV1ZKError.invalidLength(let field, _, _) = error else {
                XCTFail("expected invalidLength, got \(error)")
                return
            }
            XCTAssertEqual(field, "issuerPublicKeyX")
        }
    }

    func testProverRejectsZeroSignatureScalar() throws {
        let input = try makeInput()
        // Zero out r in the attestation signature.
        var brokenSig = Data(input.attestationSignature)
        for i in 0..<32 { brokenSig[i] = 0 }
        let broken = try ApprovalProofV1ZK.ProverInput(
            statement: input.statement,
            attestation: input.attestation,
            attestationSignature: brokenSig,
            approvalAssertion: input.approvalAssertion,
            approvalAssertionSignature: input.approvalAssertionSignature
        )
        let circuit = try ApprovalProofV1ZK.generateCircuit()
        XCTAssertThrowsError(try ApprovalProofV1ZK.prove(circuit: circuit, input: broken)) { error in
            guard case ApprovalProofV1ZKError.prover(let code, _) = error else {
                XCTFail("expected prover error, got \(error)")
                return
            }
            // APPROVAL_PROOF_V1_PROVER_MALFORMED_SIGNATURE = 9
            XCTAssertEqual(code, 9, "expected MALFORMED_SIGNATURE, got code \(code)")
        }
    }

    func testCircuitIDRejectsEmptyInput() {
        XCTAssertThrowsError(try ApprovalProofV1ZK.circuitID(circuit: Data())) { error in
            guard case ApprovalProofV1ZKError.circuitID(let code, _) = error else {
                XCTFail("expected circuitID error, got \(error)")
                return
            }
            // APPROVAL_PROOF_V1_CIRCUIT_ID_INVALID_INPUT = 2 (NULL_INPUT=1 only when ptr is null)
            XCTAssertEqual(code, 2, "expected INVALID_INPUT, got code \(code)")
        }
    }

    private func makeInput() throws -> ApprovalProofV1ZK.ProverInput {
        let serviceKey = P256.Signing.PrivateKey()
        let deviceKey = P256.Signing.PrivateKey()

        let servicePub = serviceKey.publicKey.x963Representation
        let devicePub = deviceKey.publicKey.x963Representation

        let statement = try ApprovalProofV1ZK.Statement(
            issuerPublicKeyX: servicePub[1..<33],
            issuerPublicKeyY: servicePub[33..<65],
            appIDHash: Data((0..<32).map { UInt8(0xa0 + $0) }),
            policyVersion: Data([0, 0, 0, 1]),
            now: ApprovalProofV1ZK.uint64BE(1000),
            challengeNonce: Data((0..<32).map { UInt8(0x10 + $0) }),
            audienceHash: Data((0..<32).map { UInt8(0x20 + $0) }),
            approvalHash: Data((0..<32).map { UInt8(0x30 + $0) })
        )

        let attestation = try ApprovalProofV1ZK.buildAttestation(
            statement: statement,
            devicePublicKeyX: devicePub[1..<33],
            devicePublicKeyY: devicePub[33..<65],
            notBefore: 900,
            notAfter: 2000
        )
        let approvalAssertion = ApprovalProofV1ZK.buildApprovalAssertion(statement: statement, expiresAt: 1500)
        let attestationSignature = try serviceKey.signature(for: attestation).rawRepresentation
        let approvalAssertionSignature = try deviceKey.signature(for: approvalAssertion).rawRepresentation
        return try ApprovalProofV1ZK.ProverInput(
            statement: statement,
            attestation: attestation,
            attestationSignature: attestationSignature,
            approvalAssertion: approvalAssertion,
            approvalAssertionSignature: approvalAssertionSignature
        )
    }
}
