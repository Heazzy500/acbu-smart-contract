#![cfg(test)]

use super::*;
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, IntoVal, Vec};
use shared::ContractError;

// Helper function to create a random BytesN<32>
fn random_bytesn(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0; 32]) // For simplicity in tests, use a fixed array
}

// Helper function to create a random Address
fn random_address(env: &Env) -> Address {
    Address::random(&env)
}

#[test]
fn test_initialize() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ZkVerifier);
    let client = ZkVerifierClient::new(&env, &contract_id);

    let admin = Address::random(&env);
    client.initialize(&admin);

    assert_eq!(client.admin(), admin);
    assert!(!client.paused());
}

#[test]
#[should_panic(expected = "ContractError::Unauthorized")]
fn test_initialize_already_initialized_panics() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ZkVerifier);
    let client = ZkVerifierClient::new(&env, &contract_id);

    let admin = Address::random(&env);
    client.initialize(&admin);
    client.initialize(&Address::random(&env)); // Should panic
}

#[test]
fn test_pause_unpause() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ZkVerifier);
    let client = ZkVerifierClient::new(&env, &contract_id);

    let admin = Address::random(&env);
    client.initialize(&admin);

    admin.set_auth(true);
    client.pause();
    assert!(client.paused());

    client.unpause();
    assert!(!client.paused());
    admin.set_auth(false);
}

#[test]
#[should_panic(expected = "ContractError::Unauthorized")]
fn test_pause_unauthorized_panics() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ZkVerifier);
    let client = ZkVerifierClient::new(&env, &contract_id);

    client.initialize(&Address::random(&env));
    client.pause(); // Unauthorized
}

#[test]
fn test_register_commitment() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ZkVerifier);
    let client = ZkVerifierClient::new(&env, &contract_id);

    let admin = Address::random(&env);
    client.initialize(&admin);

    let commitment = random_bytesn(&env);

    admin.set_auth(true);
    client.register_commitment(&commitment);
    admin.set_auth(false);

    assert!(client.is_attested(&commitment));
}

#[test]
#[should_panic(expected = "ContractError::CommitmentAlreadyAttested")]
fn test_register_commitment_already_attested_panics() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ZkVerifier);
    let client = ZkVerifierClient::new(&env, &contract_id);

    let admin = Address::random(&env);
    client.initialize(&admin);

    let commitment = random_bytesn(&env);

    admin.set_auth(true);
    client.register_commitment(&commitment);
    client.register_commitment(&commitment); // Should panic
    admin.set_auth(false);
}

#[test]
fn test_verify() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ZkVerifier);
    let client = ZkVerifierClient::new(&env, &contract_id);

    let admin = Address::random(&env);
    client.initialize(&admin);

    let wallet = Address::random(&env);
    let nullifier = random_bytesn(&env);
    let commitment = random_bytesn(&env);
    let public_inputs = Vec::from_array(&env, [0u128; 5]); // Valid length

    admin.set_auth(true);
    client.register_commitment(&commitment);
    admin.set_auth(false);

    wallet.set_auth(true);
    client.verify(&wallet, &nullifier, &commitment, &public_inputs);
    wallet.set_auth(false);

    assert!(client.is_verified(&wallet));
    assert!(client.is_nullifier_spent(&commitment, &nullifier));
}

#[test]
#[should_panic(expected = "ContractError::InvalidPublicInputsLength")]
fn test_verify_invalid_public_inputs_length_panics() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ZkVerifier);
    let client = ZkVerifierClient::new(&env, &contract_id);

    let admin = Address::random(&env);
    client.initialize(&admin);

    let wallet = Address::random(&env);
    let nullifier = random_bytesn(&env);
    let commitment = random_bytesn(&env);
    let public_inputs = Vec::from_array(&env, [0u128; 4]); // Invalid length

    admin.set_auth(true);
    client.register_commitment(&commitment);
    admin.set_auth(false);

    wallet.set_auth(true);
    client.verify(&wallet, &nullifier, &commitment, &public_inputs); // Should panic
    wallet.set_auth(false);
}

#[test]
#[should_panic(expected = "ContractError::CommitmentNotAttested")]
fn test_verify_commitment_not_attested_panics() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ZkVerifier);
    let client = ZkVerifierClient::new(&env, &contract_id);

    client.initialize(&Address::random(&env));

    let wallet = Address::random(&env);
    let nullifier = random_bytesn(&env);
    let commitment = random_bytesn(&env);
    let public_inputs = Vec::from_array(&env, [0u128; 5]);

    wallet.set_auth(true);
    client.verify(&wallet, &nullifier, &commitment, &public_inputs); // Should panic
    wallet.set_auth(false);
}

#[test]
#[should_panic(expected = "ContractError::NullifierAlreadySpent")] // For nullifier reuse
fn test_verify_nullifier_reused_panics() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ZkVerifier);
    let client = ZkVerifierClient::new(&env, &contract_id);

    let admin = Address::random(&env);
    client.initialize(&admin);

    let wallet1 = Address::random(&env);
    let nullifier = random_bytesn(&env);
    let commitment1 = random_bytesn(&env);
    let public_inputs = Vec::from_array(&env, [0u128; 5]);

    admin.set_auth(true);
    client.register_commitment(&commitment1);
    admin.set_auth(false);

    wallet1.set_auth(true);
    client.verify(&wallet1, &nullifier, &commitment1, &public_inputs);
    wallet1.set_auth(false);

    // Try to use the same nullifier for a different wallet
    let wallet2 = Address::random(&env);
    let commitment2 = random_bytesn(&env);

    admin.set_auth(true);
    client.register_commitment(&commitment2);
    admin.set_auth(false);

    wallet2.set_auth(true);
    client.verify(&wallet2, &nullifier, &commitment2, &public_inputs); // Should panic
    wallet2.set_auth(false);
}

#[test]
fn test_is_verified() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ZkVerifier);
    let client = ZkVerifierClient::new(&env, &contract_id);

    let admin = Address::random(&env);
    client.initialize(&admin);

    let wallet = Address::random(&env);
    let nullifier = random_bytesn(&env);
    let commitment = random_bytesn(&env);
    let public_inputs = Vec::from_array(&env, [0u128; 5]);

    admin.set_auth(true);
    client.register_commitment(&commitment);
    admin.set_auth(false);

    wallet.set_auth(true);
    client.verify(&wallet, &nullifier, &commitment, &public_inputs);
    wallet.set_auth(false);

    assert!(client.is_verified(&wallet));

    let unverified_wallet = Address::random(&env);
    assert!(!client.is_verified(&unverified_wallet));
}

#[test]
fn test_is_nullifier_spent() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ZkVerifier);
    let client = ZkVerifierClient::new(&env, &contract_id);

    let admin = Address::random(&env);
    client.initialize(&admin);

    let wallet = Address::random(&env);
    let nullifier = random_bytesn(&env);
    let commitment = random_bytesn(&env);
    let public_inputs = Vec::from_array(&env, [0u128; 5]);

    admin.set_auth(true);
    client.register_commitment(&commitment);
    admin.set_auth(false);

    wallet.set_auth(true);
    client.verify(&wallet, &nullifier, &commitment, &public_inputs);
    wallet.set_auth(false);

    assert!(client.is_nullifier_spent(&commitment, &nullifier));

    let unspent_nullifier = random_bytesn(&env);
    assert!(!client.is_nullifier_spent(&commitment, &unspent_nullifier));
}
