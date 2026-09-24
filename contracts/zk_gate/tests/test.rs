#![cfg(test)]

use super::*;
use soroban_sdk::{testutils::Address as _, testutils::MockAuth, Address, Env, IntoVal, Symbol, Vec};

// Helper to mock a contract call to the verifier
fn mock_verifier_call(env: &Env, verifier_contract_id: &Address, is_verified: bool) {
    env.mock_all_contracts();
    env.mock_contract_call_from_address(
        verifier_contract_id,
        &Symbol::new(env, "is_v"),
        Vec::from_array(env, [Address::random(env).into_val(env)]),
        is_verified.into_val(env),
    );
}

#[test]
fn test_constructor() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ZkGate);
    let client = ZkGateClient::new(&env, &contract_id);

    let owner = Address::random(&env);
    owner.set_auth(true);
    client.__constructor(&owner);
    owner.set_auth(false);

    assert_eq!(client.owner(), owner);
    assert_eq!(client.get_vrf(), None);
}

#[test]
#[should_panic(expected = "ZkGateError::AlreadyInitialized")]
fn test_constructor_already_initialized_panics() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ZkGate);
    let client = ZkGateClient::new(&env, &contract_id);

    let owner = Address::random(&env);
    owner.set_auth(true);
    client.__constructor(&owner);
    client.__constructor(&Address::random(&env)); // Should panic
    owner.set_auth(false);
}

#[test]
fn test_set_vrf() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ZkGate);
    let client = ZkGateClient::new(&env, &contract_id);

    let owner = Address::random(&env);
    client.__constructor(&owner);

    let vrf = Address::random(&env);

    owner.set_auth(true);
    client.set_vrf(&owner, &vrf);
    owner.set_auth(false);

    assert_eq!(client.get_vrf(), Some(vrf));
}

#[test]
#[should_panic(expected = "ZkGateError::Unauthorized")]
fn test_set_vrf_unauthorized_panics() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ZkGate);
    let client = ZkGateClient::new(&env, &contract_id);

    client.__constructor(&Address::random(&env));

    let vrf = Address::random(&env);

    client.set_vrf(&Address::random(&env), &vrf); // Unauthorized
}

#[test]
#[should_panic(expected = "ZkGateError::InvalidVrf")]
fn test_set_vrf_self_contract_panics() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ZkGate);
    let client = ZkGateClient::new(&env, &contract_id);

    let owner = Address::random(&env);
    client.__constructor(&owner);

    owner.set_auth(true);
    client.set_vrf(&owner, &contract_id); // Cannot set self as VRF
    owner.set_auth(false);
}

#[test]
fn test_get_vrf() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ZkGate);
    let client = ZkGateClient::new(&env, &contract_id);

    client.__constructor(&Address::random(&env));

    assert_eq!(client.get_vrf(), None);

    let owner = client.owner();
    let vrf = Address::random(&env);

    owner.set_auth(true);
    client.set_vrf(&owner, &vrf);
    owner.set_auth(false);

    assert_eq!(client.get_vrf(), Some(vrf));
}

#[test]
fn test_chk_verified() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ZkGate);
    let client = ZkGateClient::new(&env, &contract_id);

    let owner = Address::random(&env);
    client.__constructor(&owner);

    let verifier_address = Address::random(&env);

    owner.set_auth(true);
    client.set_vrf(&owner, &verifier_address);
    owner.set_auth(false);

    // Mock the verifier contract to return true
    env.mock_all_contracts();
    env.mock_contract_call_from_address(
        &verifier_address,
        &Symbol::new(&env, "is_v"),
        Vec::from_array(&env, [Address::random(&env).into_val(&env)]),
        true.into_val(&env),
    );

    let account = Address::random(&env);
    assert!(client.chk(&account));
}

#[test]
fn test_chk_not_verified() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ZkGate);
    let client = ZkGateClient::new(&env, &contract_id);

    let owner = Address::random(&env);
    client.__constructor(&owner);

    let verifier_address = Address::random(&env);

    owner.set_auth(true);
    client.set_vrf(&owner, &verifier_address);
    owner.set_auth(false);

    // Mock the verifier contract to return false
    env.mock_all_contracts();
    env.mock_contract_call_from_address(
        &verifier_address,
        &Symbol::new(&env, "is_v"),
        Vec::from_array(&env, [Address::random(&env).into_val(&env)]),
        false.into_val(&env),
    );

    let account = Address::random(&env);
    assert!(!client.chk(&account));
}

#[test]
fn test_chk_no_vrf_configured() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ZkGate);
    let client = ZkGateClient::new(&env, &contract_id);

    client.__constructor(&Address::random(&env));
    // No VRF configured

    let account = Address::random(&env);
    assert!(!client.chk(&account));
}

#[test]
fn test_chk_self_vrf_is_false() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ZkGate);
    let client = ZkGateClient::new(&env, &contract_id);

    let owner = Address::random(&env);
    client.__constructor(&owner);

    // Set VRF to self (should be disallowed by set_vrf, but for test, simulate)
    owner.set_auth(true);
    // We cannot use set_vrf directly here to set to self because it panics.
    // Instead, we directly set the storage for testing the chk function's guard.
    env.storage().instance().set(&DataKey::Vrf, &contract_id);
    owner.set_auth(false);

    let account = Address::random(&env);
    assert!(!client.chk(&account));
}
