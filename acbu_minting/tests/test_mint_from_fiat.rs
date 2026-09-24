#![cfg(test)]

use acbu_minting::{MintingContract, MintingContractClient};
use shared::{CurrencyCode, DECIMALS};
use soroban_env_host::budget::AsBudget;
use soroban_sdk::testutils::StellarAssetContract;
use soroban_sdk::xdr::{
    AlphaNum4, AssetCode4, LedgerEntry, LedgerEntryData, LedgerEntryExt, LedgerKey,
    LedgerKeyTrustLine, ScAddress, TrustLineAsset, TrustLineEntry, TrustLineEntryExt,
    TrustLineFlags,
};
use soroban_sdk::{testutils::Address as _, Address, Env, String as SorobanString};
use std::rc::Rc;

// --- Mocks (reuse from test.rs) ---

mod oracle_mock {
    use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, Vec};

    use shared::CurrencyCode;
    use super::DECIMALS;

    #[contract]
    pub struct MockOracle;

    #[contractimpl]
    impl MockOracle {
        pub fn get_acbu_usd_rate(_env: Env) -> i128 {
            DECIMALS
        }

        pub fn get_acbu_usd_rate_with_timestamp(env: Env) -> (i128, u64) {
            (DECIMALS, env.ledger().timestamp())
        }

        pub fn get_currencies(env: Env) -> Vec<CurrencyCode> {
            let mut v = Vec::new(&env);
            v.push_back(CurrencyCode::new(&env, "NGN"));
            v
        }

        pub fn get_basket_weight(_env: Env, _c: CurrencyCode) -> i128 {
            10_000
        }

        pub fn get_rate(_env: Env, _c: CurrencyCode) -> i128 {
            DECIMALS
        }

        pub fn get_rate_with_timestamp(env: Env, _c: CurrencyCode) -> (i128, u64) {
            (DECIMALS, env.ledger().timestamp())
        }

        pub fn get_s_token_address(env: Env, _c: CurrencyCode) -> Address {
            env.storage()
                .instance()
                .get(&symbol_short!("STK"))
                .expect("seed_stoken not called in test")
        }

        pub fn seed_stoken(env: Env, stoken: Address) {
            env.storage().instance().set(&symbol_short!("STK"), &stoken);
        }
    }
}

mod reserve_mock {
    use soroban_sdk::{contract, contractimpl, Env};

    #[contract]
    pub struct MockReserveTracker;

    #[contractimpl]
    impl MockReserveTracker {
        pub fn is_reserve_sufficient(_env: Env, _supply: i128) -> bool {
            true
        }
    }
}

fn oracle_mock_client<'a>(env: &'a Env, oracle: &'a Address) -> oracle_mock::MockOracleClient<'a> {
    oracle_mock::MockOracleClient::new(env, oracle)
}

fn setup_test(
    env: &Env,
) -> (
    Address,
    Address,
    Address,
    Address,
    Address,
    MintingContractClient,
) {
    let admin = Address::generate(env);
    let oracle = env.register_contract(None, oracle_mock::MockOracle);
    let reserve_tracker = env.register_contract(None, reserve_mock::MockReserveTracker);

    let contract_id = env.register_contract(None, MintingContract);
    let acbu_sac = env.register_stellar_asset_contract_v2(contract_id.clone());
    let acbu_token = acbu_sac.address();

    let usdc_sac = env.register_stellar_asset_contract_v2(admin.clone());
    let usdc_token = usdc_sac.address();

    let client = MintingContractClient::new(env, &contract_id);

    // C-058 recipients are ed25519 accounts; SAC mint needs their trustline.
    establish_trustline(env, &account(env), &acbu_sac);
    establish_trustline(env, &account(env), &usdc_sac);

    (
        admin,
        oracle,
        reserve_tracker,
        acbu_token,
        usdc_token,
        client,
    )
}

/// C-058 requires ed25519-account recipients, but the SAC rejects mints to
/// accounts without a trustline (host `TrustlineMissingError`). Test-only:
/// create the trustline directly in host storage.
fn establish_trustline(env: &Env, holder: &Address, sac: &StellarAssetContract) {
    let holder_account = match ScAddress::from(holder.clone()) {
        ScAddress::Account(id) => id,
        _ => panic!("holder must be an account address"),
    };
    let issuer_account = match ScAddress::from(sac.issuer().address()) {
        ScAddress::Account(id) => id,
        _ => panic!("issuer must be an account address"),
    };
    let asset = TrustLineAsset::CreditAlphanum4(AlphaNum4 {
        asset_code: AssetCode4([b'a', b'a', b'a', 0]),
        issuer: issuer_account,
    });
    let key = Rc::new(LedgerKey::Trustline(LedgerKeyTrustLine {
        account_id: holder_account.clone(),
        asset: asset.clone(),
    }));
    let entry = Rc::new(LedgerEntry {
        last_modified_ledger_seq: 0,
        data: LedgerEntryData::Trustline(TrustLineEntry {
            account_id: holder_account,
            asset,
            balance: 0,
            limit: i64::MAX,
            flags: TrustLineFlags::AuthorizedFlag as u32,
            ext: TrustLineEntryExt::V0,
        }),
        ext: LedgerEntryExt::V0,
    });
    env.host()
        .with_mut_storage(|storage| {
            storage.put(&key, &entry, None, AsBudget::as_budget(env.host()))
        })
        .unwrap();
}

fn init_mint_client(
    env: &Env,
    client: &MintingContractClient,
    admin: &Address,
    oracle: &Address,
    reserve_tracker: &Address,
    acbu_token: &Address,
    usdc_token: &Address,
    vault: &Address,
    treasury: &Address,
    fee_rate: i128,
    fee_single: i128,
) {
    let config = acbu_minting::MintingConfig {
        admin: admin.clone(),
        oracle: oracle.clone(),
        reserve_tracker: reserve_tracker.clone(),
        acbu_token: acbu_token.clone(),
        usdc_token: usdc_token.clone(),
        vault: vault.clone(),
        treasury: treasury.clone(),
        fee_rate_bps: fee_rate,
        fee_single_bps: fee_single,
        // initialize rejects admin == operator (#5024); every test calls
        // set_operator right after init, so a placeholder is sufficient.
        operator: Address::generate(env),
    };
    client.initialize(&config);
}

// --- Tests for mint_from_fiat: Access Control and Validation ---

/// C-058 requires recipients to be ed25519 accounts (`G...`), but
/// `Address::generate` yields contract addresses (`C...`) in SDK 21.
fn account(env: &Env) -> Address {
    Address::from_string(&SorobanString::from_str(
        env,
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    ))
}

#[test]
fn test_mint_from_fiat_success() {
    let env = Env::default();
    env.mock_all_auths();

    let (admin, oracle, reserve_tracker, acbu_token_id, usdc_token_id, client) = setup_test(&env);
    let operator = Address::generate(&env);
    let recipient = account(&env);
    let mint_addr = client.address.clone();

    let stoken_id = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    let stoken_sac = soroban_sdk::token::StellarAssetClient::new(&env, &stoken_id);
    stoken_sac.mint(&mint_addr, &(100 * DECIMALS));
    oracle_mock_client(&env, &oracle).seed_stoken(&stoken_id);

    init_mint_client(
        &env,
        &client,
        &admin,
        &oracle,
        &reserve_tracker,
        &acbu_token_id,
        &usdc_token_id,
        &admin,
        &admin,
        50,
        100,
    );

    client.set_operator(&operator);

    let fiat_amount = 50 * DECIMALS;
    let fintech_tx_id = SorobanString::from_str(&env, "fintech_tx_001");
    let acbu = client.mint_from_fiat(
        &operator,
        &recipient,
        &CurrencyCode::new(&env, "NGN"),
        &fiat_amount,
        &fintech_tx_id,
    );

    assert!(acbu > 0);
    let acbu_client = soroban_sdk::token::Client::new(&env, &acbu_token_id);
    assert_eq!(acbu_client.balance(&recipient), acbu, "acbu_client.balance(&recipient) should equal acbu");
    // AC-009 (#732): total supply must include the treasury fee mint.
    let expected_fee = shared::calculate_fee(50 * DECIMALS, 50).unwrap();
    assert!(expected_fee > 0, "fee must be positive for this scenario");
    assert_eq!(
        client.get_total_supply(),
        acbu + expected_fee,
        "client.get_total_supply() should include the treasury fee mint"
    );
    // The treasury received the fee as newly minted ACBU.
    assert_eq!(
        acbu_client.balance(&admin),
        expected_fee,
        "acbu_client.balance(&admin) should equal expected_fee"
    );
}

#[test]
#[should_panic(expected = "#5007")]
fn test_mint_from_fiat_unauthorized_caller() {
    let env = Env::default();
    env.mock_all_auths();

    let (admin, oracle, reserve_tracker, acbu_token_id, usdc_token_id, client) = setup_test(&env);
    let operator = Address::generate(&env);
    let recipient = account(&env);
    let attacker = Address::generate(&env);
    let mint_addr = client.address.clone();

    let stoken_id = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    let stoken_sac = soroban_sdk::token::StellarAssetClient::new(&env, &stoken_id);
    stoken_sac.mint(&mint_addr, &(100 * DECIMALS));
    oracle_mock_client(&env, &oracle).seed_stoken(&stoken_id);

    init_mint_client(
        &env,
        &client,
        &admin,
        &oracle,
        &reserve_tracker,
        &acbu_token_id,
        &usdc_token_id,
        &admin,
        &admin,
        50,
        100,
    );

    client.set_operator(&operator);

    let fiat_amount = 50 * DECIMALS;
    let fintech_tx_id = SorobanString::from_str(&env, "fintech_tx_001");

    // Attacker tries to call mint_from_fiat - should fail
    client.mint_from_fiat(
        &attacker,
        &recipient,
        &CurrencyCode::new(&env, "NGN"),
        &fiat_amount,
        &fintech_tx_id,
    );
}

#[test]
#[should_panic(expected = "#5007")]
fn test_mint_from_fiat_recipient_self_mint() {
    let env = Env::default();
    env.mock_all_auths();

    let (admin, oracle, reserve_tracker, acbu_token_id, usdc_token_id, client) = setup_test(&env);
    let operator = Address::generate(&env);
    let recipient = account(&env);
    let mint_addr = client.address.clone();

    let stoken_id = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    let stoken_sac = soroban_sdk::token::StellarAssetClient::new(&env, &stoken_id);
    stoken_sac.mint(&mint_addr, &(100 * DECIMALS));
    oracle_mock_client(&env, &oracle).seed_stoken(&stoken_id);

    init_mint_client(
        &env,
        &client,
        &admin,
        &oracle,
        &reserve_tracker,
        &acbu_token_id,
        &usdc_token_id,
        &admin,
        &admin,
        50,
        100,
    );

    client.set_operator(&operator);

    let fiat_amount = 50 * DECIMALS;
    let fintech_tx_id = SorobanString::from_str(&env, "fintech_tx_001");

    // Recipient tries to call as themselves - should fail because only operator can call
    client.mint_from_fiat(
        &recipient,
        &recipient,
        &CurrencyCode::new(&env, "NGN"),
        &fiat_amount,
        &fintech_tx_id,
    );
}

#[test]
#[should_panic(expected = "#5014")]
fn test_mint_from_fiat_empty_tx_id() {
    let env = Env::default();
    env.mock_all_auths();

    let (admin, oracle, reserve_tracker, acbu_token_id, usdc_token_id, client) = setup_test(&env);
    let operator = Address::generate(&env);
    let recipient = account(&env);
    let mint_addr = client.address.clone();

    let stoken_id = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    let stoken_sac = soroban_sdk::token::StellarAssetClient::new(&env, &stoken_id);
    stoken_sac.mint(&mint_addr, &(100 * DECIMALS));
    oracle_mock_client(&env, &oracle).seed_stoken(&stoken_id);

    init_mint_client(
        &env,
        &client,
        &admin,
        &oracle,
        &reserve_tracker,
        &acbu_token_id,
        &usdc_token_id,
        &admin,
        &admin,
        50,
        100,
    );

    client.set_operator(&operator);

    let fiat_amount = 50 * DECIMALS;
    let fintech_tx_id = SorobanString::from_str(&env, "");

    // Call with empty fintech_tx_id - should fail
    client.mint_from_fiat(
        &operator,
        &recipient,
        &CurrencyCode::new(&env, "NGN"),
        &fiat_amount,
        &fintech_tx_id,
    );
}

#[test]
#[should_panic(expected = "#5008")]
fn test_mint_from_fiat_duplicate_tx_id() {
    let env = Env::default();
    env.mock_all_auths();

    let (admin, oracle, reserve_tracker, acbu_token_id, usdc_token_id, client) = setup_test(&env);
    let operator = Address::generate(&env);
    let recipient = account(&env);
    let mint_addr = client.address.clone();

    let stoken_id = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    let stoken_sac = soroban_sdk::token::StellarAssetClient::new(&env, &stoken_id);
    stoken_sac.mint(&mint_addr, &(500 * DECIMALS));
    oracle_mock_client(&env, &oracle).seed_stoken(&stoken_id);

    init_mint_client(
        &env,
        &client,
        &admin,
        &oracle,
        &reserve_tracker,
        &acbu_token_id,
        &usdc_token_id,
        &admin,
        &admin,
        50,
        100,
    );

    client.set_operator(&operator);

    let fiat_amount = 50 * DECIMALS;
    let fintech_tx_id = SorobanString::from_str(&env, "fintech_tx_duplicate");

    // First call succeeds
    client.mint_from_fiat(
        &operator,
        &recipient,
        &CurrencyCode::new(&env, "NGN"),
        &fiat_amount,
        &fintech_tx_id.clone(),
    );

    // Second call with same tx_id should fail
    client.mint_from_fiat(
        &operator,
        &recipient,
        &CurrencyCode::new(&env, "NGN"),
        &fiat_amount,
        &fintech_tx_id,
    );
}

#[test]
#[should_panic(expected = "#5003")]
fn test_mint_from_fiat_below_min_amount() {
    let env = Env::default();
    env.mock_all_auths();

    let (admin, oracle, reserve_tracker, acbu_token_id, usdc_token_id, client) = setup_test(&env);
    let operator = Address::generate(&env);
    let recipient = account(&env);
    let mint_addr = client.address.clone();

    let stoken_id = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    let stoken_sac = soroban_sdk::token::StellarAssetClient::new(&env, &stoken_id);
    stoken_sac.mint(&mint_addr, &(100 * DECIMALS));
    oracle_mock_client(&env, &oracle).seed_stoken(&stoken_id);

    init_mint_client(
        &env,
        &client,
        &admin,
        &oracle,
        &reserve_tracker,
        &acbu_token_id,
        &usdc_token_id,
        &admin,
        &admin,
        50,
        100,
    );

    client.set_operator(&operator);

    // Mint amount is too small (less than MIN_MINT_AMOUNT)
    let fiat_amount = 1; // Way too small
    let fintech_tx_id = SorobanString::from_str(&env, "fintech_tx_small");

    client.mint_from_fiat(
        &operator,
        &recipient,
        &CurrencyCode::new(&env, "NGN"),
        &fiat_amount,
        &fintech_tx_id,
    );
}

#[test]
#[should_panic(expected = "#5003")]
fn test_mint_from_fiat_above_max_amount() {
    let env = Env::default();
    env.mock_all_auths();

    let (admin, oracle, reserve_tracker, acbu_token_id, usdc_token_id, client) = setup_test(&env);
    let operator = Address::generate(&env);
    let recipient = account(&env);
    let mint_addr = client.address.clone();

    let stoken_id = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    let stoken_sac = soroban_sdk::token::StellarAssetClient::new(&env, &stoken_id);
    stoken_sac.mint(&mint_addr, &(100_000 * DECIMALS));
    oracle_mock_client(&env, &oracle).seed_stoken(&stoken_id);

    init_mint_client(
        &env,
        &client,
        &admin,
        &oracle,
        &reserve_tracker,
        &acbu_token_id,
        &usdc_token_id,
        &admin,
        &admin,
        50,
        100,
    );

    client.set_operator(&operator);

    // Mint amount exceeds MAX_MINT_AMOUNT
    let fiat_amount = 1_000_000_000_000_000;
    let fintech_tx_id = SorobanString::from_str(&env, "fintech_tx_large");

    client.mint_from_fiat(
        &operator,
        &recipient,
        &CurrencyCode::new(&env, "NGN"),
        &fiat_amount,
        &fintech_tx_id,
    );
}

#[test]
fn test_mint_from_fiat_admin_not_default_operator() {
    let env = Env::default();
    env.mock_all_auths();

    let (admin, oracle, reserve_tracker, acbu_token_id, usdc_token_id, client) = setup_test(&env);
    let operator = Address::generate(&env);
    let recipient = account(&env);
    let mint_addr = client.address.clone();

    let stoken_id = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    let stoken_sac = soroban_sdk::token::StellarAssetClient::new(&env, &stoken_id);
    stoken_sac.mint(&mint_addr, &(100 * DECIMALS));
    oracle_mock_client(&env, &oracle).seed_stoken(&stoken_id);

    init_mint_client(
        &env,
        &client,
        &admin,
        &oracle,
        &reserve_tracker,
        &acbu_token_id,
        &usdc_token_id,
        &admin,
        &admin,
        50,
        100,
    );

    // Set custom operator (not admin)
    client.set_operator(&operator);

    let fiat_amount = 50 * DECIMALS;
    let fintech_tx_id = SorobanString::from_str(&env, "fintech_tx_custom_op");

    // Custom operator should succeed
    let acbu = client.mint_from_fiat(
        &operator,
        &recipient,
        &CurrencyCode::new(&env, "NGN"),
        &fiat_amount,
        &fintech_tx_id,
    );
    assert!(acbu > 0);
}

#[test]
#[should_panic(expected = "#5007")]
fn test_mint_from_fiat_admin_when_operator_set() {
    let env = Env::default();
    env.mock_all_auths();

    let (admin, oracle, reserve_tracker, acbu_token_id, usdc_token_id, client) = setup_test(&env);
    let operator = Address::generate(&env);
    let recipient = account(&env);
    let mint_addr = client.address.clone();

    let stoken_id = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    let stoken_sac = soroban_sdk::token::StellarAssetClient::new(&env, &stoken_id);
    stoken_sac.mint(&mint_addr, &(100 * DECIMALS));
    oracle_mock_client(&env, &oracle).seed_stoken(&stoken_id);

    init_mint_client(
        &env,
        &client,
        &admin,
        &oracle,
        &reserve_tracker,
        &acbu_token_id,
        &usdc_token_id,
        &admin,
        &admin,
        50,
        100,
    );

    // Set custom operator (different from admin)
    client.set_operator(&operator);

    let fiat_amount = 50 * DECIMALS;
    let fintech_tx_id = SorobanString::from_str(&env, "fintech_tx_admin_tries");

    // Admin tries to call but is not the operator anymore - should fail
    client.mint_from_fiat(
        &admin,
        &recipient,
        &CurrencyCode::new(&env, "NGN"),
        &fiat_amount,
        &fintech_tx_id,
    );
}

#[test]
fn test_mint_from_usdc_routes_fee_to_treasury() {
    let env = Env::default();
    env.mock_all_auths();

    let (admin, oracle, reserve_tracker, acbu_token_id, usdc_token_id, client) = setup_test(&env);
    let user = account(&env);
    let treasury = Address::generate(&env);
    let vault = Address::generate(&env);

    let fee_rate = 300i128; // 3%
    let fee_single = 100i128;

    init_mint_client(
        &env,
        &client,
        &admin,
        &oracle,
        &reserve_tracker,
        &acbu_token_id,
        &usdc_token_id,
        &vault,
        &treasury,
        fee_rate,
        fee_single,
    );

    let usdc_sac = soroban_sdk::token::StellarAssetClient::new(&env, &usdc_token_id);
    let usdc_client = soroban_sdk::token::Client::new(&env, &usdc_token_id);
    let acbu_client = soroban_sdk::token::Client::new(&env, &acbu_token_id);

    let mint_amount = 50 * DECIMALS;
    usdc_sac.mint(&user, &mint_amount);

    let expected_fee = shared::calculate_fee(mint_amount, fee_rate).unwrap(); // 15_000_000
    let expected_acbu = mint_amount - expected_fee; // 485_000_000

    let minted = client.mint_from_usdc(&user, &mint_amount, &user, &None);

    assert_eq!(minted, expected_acbu, "minted should equal expected_acbu");
    assert_eq!(acbu_client.balance(&user), expected_acbu, "user should receive acbu after fee");
    // Verify ACBU fee was routed to treasury
    assert_eq!(acbu_client.balance(&treasury), expected_fee, "treasury should receive the ACBU fee");
    // Verify contract retains total deposited USDC as reserve backing
    assert_eq!(usdc_client.balance(&client.address), mint_amount, "contract should hold total USDC as reserve backing");
}
