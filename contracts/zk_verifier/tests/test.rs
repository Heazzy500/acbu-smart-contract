#![cfg(test)]

use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Events, Ledger},
    Address, BytesN, Env, FromVal, IntoVal, Symbol,
};
use zk_verifier::{
    VerificationInputs, VerificationPolicy, VerifiedEvent, ZkVerifier, ZkVerifierClient,
    VERIFICATION_VALIDITY_LEDGERS,
};

fn bytes(env: &Env, value: u8) -> BytesN<32> {
    BytesN::from_array(env, &[value; 32])
}

fn inputs(env: &Env, nullifier: u8, commitment: u8) -> VerificationInputs {
    VerificationInputs {
        min_tier: 2,
        country_code: 566,
        requested_amount: 1_000,
        daily_cap: 10_000,
        already_used: 500,
        nullifier: bytes(env, nullifier),
        commitment: bytes(env, commitment),
    }
}

fn setup() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, ZkVerifier);
    let client = ZkVerifierClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    (env, contract_id, admin)
}

#[test]
fn verification_records_named_inputs_and_policy() {
    let (env, contract_id, _) = setup();
    let client = ZkVerifierClient::new(&env, &contract_id);
    let wallet = Address::generate(&env);
    let inputs = inputs(&env, 1, 2);

    client.register_commitment(&inputs.commitment);
    client.verify(&wallet, &inputs);

    let record = client.verification(&wallet).unwrap();
    assert_eq!(record.nullifier, inputs.nullifier);
    assert_eq!(
        record.policy,
        VerificationPolicy {
            min_tier: inputs.min_tier,
            country_code: inputs.country_code,
            requested_amount: inputs.requested_amount,
            daily_cap: inputs.daily_cap,
            already_used: inputs.already_used,
        }
    );
    assert_eq!(
        record.expires_at_ledger,
        env.ledger().sequence() + VERIFICATION_VALIDITY_LEDGERS
    );
    assert!(client.is_verified(&wallet));
    assert!(client.is_nullifier_spent(&inputs.commitment, &inputs.nullifier));

    let event = env
        .events()
        .all()
        .iter()
        .find(|event| {
            event.0 == contract_id
                && Symbol::from_val(&env, &event.1.get(0).unwrap()) == symbol_short!("verified")
        })
        .expect("verified event must be emitted");
    let event: VerifiedEvent = event.2.into_val(&env);
    assert_eq!(event.user, wallet);
    assert_eq!(event.nullifier, inputs.nullifier);
    assert_eq!(event.policy, record.policy);
}

#[test]
#[should_panic(expected = "Error(Contract, #17)")]
fn verification_rejects_unattested_commitment() {
    let (env, contract_id, _) = setup();
    let client = ZkVerifierClient::new(&env, &contract_id);
    client.verify(&Address::generate(&env), &inputs(&env, 1, 2));
}

#[test]
#[should_panic(expected = "Error(Contract, #18)")]
fn verification_rejects_reused_scoped_nullifier() {
    let (env, contract_id, _) = setup();
    let client = ZkVerifierClient::new(&env, &contract_id);
    let inputs = inputs(&env, 1, 2);
    client.register_commitment(&inputs.commitment);
    client.verify(&Address::generate(&env), &inputs);
    client.verify(&Address::generate(&env), &inputs);
}

#[test]
fn verification_expires_without_read_extension() {
    let (env, contract_id, _) = setup();
    let client = ZkVerifierClient::new(&env, &contract_id);
    let wallet = Address::generate(&env);
    let inputs = inputs(&env, 1, 2);
    client.register_commitment(&inputs.commitment);
    client.verify(&wallet, &inputs);

    let expires_at = client.verification(&wallet).unwrap().expires_at_ledger;
    env.ledger()
        .with_mut(|ledger| ledger.sequence_number = expires_at);

    assert!(!client.is_verified(&wallet));
    assert!(client.verification(&wallet).is_none());
}

#[test]
fn admin_can_revoke_verification() {
    let (env, contract_id, _) = setup();
    let client = ZkVerifierClient::new(&env, &contract_id);
    let wallet = Address::generate(&env);
    let inputs = inputs(&env, 1, 2);
    client.register_commitment(&inputs.commitment);
    client.verify(&wallet, &inputs);

    assert!(client.revoke_verification(&wallet));
    assert!(!client.is_verified(&wallet));
    assert!(client.verification(&wallet).is_none());
    assert!(!client.revoke_verification(&wallet));
}

#[test]
fn pause_blocks_verification_until_unpaused() {
    let (env, contract_id, _) = setup();
    let client = ZkVerifierClient::new(&env, &contract_id);
    let wallet = Address::generate(&env);
    let inputs = inputs(&env, 1, 2);
    client.register_commitment(&inputs.commitment);
    client.pause();

    assert!(client.try_verify(&wallet, &inputs).is_err());
    client.unpause();
    client.verify(&wallet, &inputs);
    assert!(client.is_verified(&wallet));
}
