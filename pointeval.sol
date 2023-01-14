pragma solidity ^0.8.14;

type MemOffset is uint256;

library MemOffsetHelpers {
    function alloc(uint256 size) internal pure returns (MemOffset m) {
        assembly {
            m := mload(0x40)
            mstore(0x40, add(m, size))
        }
    }

    function inc(MemOffset m1, uint256 i) internal pure returns (MemOffset m2) {
        assembly {
            m2 := add(m1, i)
        }
    }
}

using MemOffsetHelpers for MemOffset global;

function freeMemoryPointer() pure returns (MemOffset ret) {
    assembly {
        ret := mload(0x40)
    }
}

// BLS12-381 implementation utilising EIP-2357 precompiles
// Note: this has implementation choices specific for the PointEvaluationPrecompile
library BLS12 {
    uint256 private constant BLS12_G1ADD_ADDR = 0x0a;
    uint256 private constant BLS12_G1MUL_ADDR = 0x0b;
    uint256 private constant BLS12_G2ADD_ADDR = 0x0d;
    uint256 private constant BLS12_G2MUL_ADDR = 0x0e;
    uint256 private constant BLS12_PAIRING_ADDR = 0x10;

    uint256 constant MODULUS = 52435875175126190479447740508185965837690552500527637822603658699938581184513;

    // The precompile expects x,y order.
    // Note it is enforced that *_hi's top 128-bits are zero.
    struct G1Point {
        uint256 X_hi;
        uint256 X_lo;
        uint256 Y_hi;
        uint256 Y_lo;
    }

    // The precompile expects x0, x1, y0, y1.
    // Note it is enforced that *_hi's top 128-bits are zero.
    struct G2Point {
        uint256 X0_hi;
        uint256 X0_lo;
        uint256 X1_hi;
        uint256 X1_lo;
        uint256 Y0_hi;
        uint256 Y0_lo;
        uint256 Y1_hi;
        uint256 Y1_lo;
    }

    // memory[m..m+128] will be overwritten
    function g1_encode_to_memory(G1Point memory p, MemOffset m) private pure {
        uint256 X_hi = p.X_hi;
        uint256 X_lo = p.X_lo;
        uint256 Y_hi = p.X_hi;
        uint256 Y_lo = p.X_lo;
        assembly {
            mstore(m, X_hi)
            mstore(add(m, 32), X_lo)
            mstore(add(m, 64), Y_hi)
            mstore(add(m, 96), Y_lo)
        }
    }

    function g1_decode_from_memory(MemOffset m, G1Point memory p) private pure {
        // FIXME: add (also consider memory overlaps)
    }

    // memory[m..m+256] will be overwritten
    function g2_encode_to_memory(G2Point memory p, MemOffset m) private pure {
        uint256 X0_hi = p.X0_hi;
        uint256 X0_lo = p.X0_lo;
        uint256 X1_hi = p.X1_hi;
        uint256 X1_lo = p.X1_lo;
        uint256 Y0_hi = p.Y0_hi;
        uint256 Y0_lo = p.Y0_lo;
        uint256 Y1_hi = p.Y1_hi;
        uint256 Y1_lo = p.Y1_lo;
        assembly {
            mstore(m, X0_hi)
            mstore(add(m, 32), X0_lo)
            mstore(add(m, 64), X1_hi)
            mstore(add(m, 96), X1_lo)
            mstore(add(m, 128), Y0_lo)
            mstore(add(m, 160), Y0_lo)
            mstore(add(m, 192), Y1_lo)
            mstore(add(m, 224), Y1_lo)
        }
    }

    function g1() internal pure returns (G1Point memory) {
        // FIXME: add
    }

    function g2() internal pure returns (G2Point memory) {
        // FIXME: add
    }

    function g2_neg() internal pure returns (G2Point memory) {
        // FIXME: precalculate this to avoid the need for runtime negation
    }

    // Field element from little-endian encoded data.
    function fe_from_le(bytes32 a) internal pure returns (uint256 ret) {
        assembly {
            ret := a // FIXME: do byteswapping from little endian
        }
        assert(ret < MODULUS);
    }

    // This expects 384-bits of input.
    function g1_decompress(bytes calldata) internal pure returns (G1Point memory ret) {
        assert(false);
    }

    function g1_add(G1Point memory a, G1Point memory b) internal view returns (G1Point memory ret) {
        // This offset is reused for the return value
        MemOffset m = freeMemoryPointer();
        g1_encode_to_memory(a, m);
        g1_encode_to_memory(b, m.inc(128));

        assembly {
            if iszero(staticcall(gas(), BLS12_G1ADD_ADDR, m, 256, m, 128)) { revert(0, 0) }
        }

        g1_decode_from_memory(m, ret);
    }

    function g1_multiply(G1Point memory a, uint256 s) internal view returns (G1Point memory ret) {
        assert(false);
    }

    function g2_add(G2Point memory a, G2Point memory b) internal view returns (G2Point memory ret) {
        assert(false);
    }

    function g2_multiply(G2Point memory a, uint256 s) internal view returns (G2Point memory ret) {
        assert(false);
    }

    // Optimised version for k=2.
    function pairing_check_two(G1Point memory g1_1, G2Point memory g2_1, G1Point memory g1_2, G2Point memory g2_2) internal view returns (bool ret) {
        MemOffset m = freeMemoryPointer();
        g1_encode_to_memory(g1_1, m);
        g2_encode_to_memory(g2_1, m.inc(128));
        g1_encode_to_memory(g1_2, m.inc(256));
        g2_encode_to_memory(g2_2, m.inc(128));

        assembly {
            if iszero(staticcall(gas(), BLS12_PAIRING_ADDR, m, 768, 0, 32)) { revert(0, 0) }
            ret := mload(0)
        }
    }
}

// This is an implementation of the EIP-4844 precompile.
contract PointEvaluationPrecompile {
    function verify_kzg_proof(bytes calldata polynomial_kzg, bytes32 z, bytes32 y, bytes calldata kzg_proof) private view {
        BLS12.G2Point memory KZG_SETUP_G2; // FIXME set this

        BLS12.G2Point memory X_minus_z = BLS12.g2_add(KZG_SETUP_G2, BLS12.g2_multiply(BLS12.g2(), BLS12.MODULUS - BLS12.fe_from_le(z)));
        BLS12.G1Point memory P_minus_y = BLS12.g1_add(BLS12.g1_decompress(polynomial_kzg), BLS12.g1_multiply(BLS12.g1(), BLS12.MODULUS - BLS12.fe_from_le(y)));
        assert(BLS12.pairing_check_two(P_minus_y, BLS12.g2_neg(), BLS12.g1_decompress(kzg_proof), X_minus_z));

//        BLS12.Pair[] memory pairs = new BLS12.Pair[](2);
//        pairs[0] = BLS12.Pair(P_minus_y, BLS12.G2_NEG);
//        pairs[1] = BLS12.Pair(BLS12.g1_decompress(kzg_proof), X_minus_z);
//        assert(BLS12.pairing_check(pairs));
    }

    // Note the precompile doesn't explicitly reject value transfers (hence the payable modifier).
    fallback() external payable {
        // Step 1: Verify the hash
        assembly {
            // Copy commitment
            calldatacopy(0, 48, 96)
            // Hash using sha256
            if iszero(staticcall(gas(), 2, 0, 48, 0, 32)) { revert(0, 0) }
            // Insert BLOB_COMMITMENT_VERSION_KZG
            mstore8(0, 1)
            // Memory 0..32 contains versioned_hash now

            // assert kzg_to_versioned_hash(commitment) == versioned_hash
            let commitment := calldataload(0)
            if iszero(eq(commitment, mload(0))) { revert(0, 0) }
        }

        // Step 2: Verify the KZG proof
        bytes32 z;
        bytes32 y;
        assembly {
            z := calldataload(32)
            y := calldataload(64)
        }
        verify_kzg_proof(msg.data[96:144], z, y, msg.data[144:192]);

        // Step 3: Return BLS12 details
        assembly {
            // FIELD_ELEMENTS_PER_BLOB
            mstore(0, 4096)
            // BLS_MODULUS
            mstore(32, 52435875175126190479447740508185965837690552500527637822603658699938581184513)
            return(0, 64)
        }
    }
}
