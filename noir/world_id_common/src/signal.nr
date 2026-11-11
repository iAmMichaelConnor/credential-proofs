pub global DOMAIN: Field = 0x574f524c445f49445f415a5445435f5631;

// Context: [chain_id, version, consumer, action, beneficiary, nonce].
// The binding stops an existing proof from being re-bound to another context.
// It does not show who chose the beneficiary or that the nonce is fresh or
// RP-issued: the request path that builds the signal is trusted
// (docs/world-id.md "Request-path obligations").
pub fn signal_hash(context: [Field; 6]) -> Field {
    let mut bytes = [0u8; 224];
    let domain = DOMAIN.to_be_bytes::<32>();
    for j in 0..32 {
        bytes[j] = domain[j];
    }
    for i in 0..6 {
        let word = context[i].to_be_bytes::<32>();
        for j in 0..32 {
            bytes[32 + i * 32 + j] = word[j];
        }
    }
    let digest = keccak256::keccak256(bytes, 224);
    // World ID hashToField = uint256(keccak256(signal)) >> 8, not mod Fr.
    let mut value: Field = 0;
    for i in 0..31 {
        value = value * 256 + digest[i] as Field;
    }
    value
}
