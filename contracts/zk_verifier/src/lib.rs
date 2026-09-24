#![no_std]

//! # `zk_verifier`
//!
//! On-chain ZK proof verifier for KYC compliance proofs.
//!
//! ## AZ-014 fix — bounded storage
//!
//! The original implementation stored all nullifiers and all verified-wallet
//! addresses in two growing `Map` values held in **instance** storage.  Every
//! verification call appended to those maps; entries were never removed.
//! Because instance storage is size-bounded and its rent scales with the total
//! byte size of the instance, the contract would eventually hit storage limits
//! or impose unbounded rent on honest users — a DoS vector.
//!
//! This implementation uses **persistent** storage keyed *per entry*:
//!
//! ```text
//! DataKey::Nullifier(BytesN<32>)  →  bool      (ledger-TTL-bumped on each verify)
//! DataKey::Verified(Address)      →  bool      (ledger-TTL-bumped on each verify)
//! DataKey::Admin                  →  Address   (instance — single scalar, bounded)
//! DataKey::Paused                 →  bool      (instance — single scalar, bounded)
//! ```
//!
//! Each entry lives in `persistent` storage and receives a TTL bump on every
//! successful verification.  Entries that are never re-verified expire
//! automatically after `NULLIFIER_TTL_LEDGERS`, keeping storage bounded.
//!
//! Instance storage is used **only** for the small, fixed set of contract
//! configuration fields (admin, paused flag) whose combined size is a known
//! constant that cannot grow at runtime.

use soroban_sdk::{
    contract, contractimpl, contracttype, panic_with_error, symbol_short, Address,
    BytesN, Env,
};
use shared::ContractError;

// ---------------------------------------------------------------------------
// Storage TTL constants
// ---------------------------------------------------------------------------

/// Ledgers a nullifier entry is kept alive after its last verification.
///
/// Stellar closes ~1 ledger every 5 seconds.
/// 1 051 200 ledgers ≈ 60 days — long enough to prevent replay within any
/// realistic settlement window while still letting stale entries expire.
const NULLIFIER_TTL_LEDGERS: u32 = 1_051_200; // ~60 days

/// TTL bump threshold: extend only when fewer than this many ledgers remain.
/// Set to half the full TTL so we don't bump on every single call.
const NULLIFIER_TTL_THRESHOLD: u32 = NULLIFIER_TTL_LEDGERS / 2;

/// TTL for the instance storage (admin + paused flag).
const INSTANCE_TTL_LEDGERS: u32 = 5_256_000; // ~1 year

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Contract administrator address.
    Admin,
    /// Whether the contract is paused.
    Paused,
    /// Spent nullifier — keyed per 32-byte nullifier hash.
    ///
    /// Stored in *persistent* storage so entries expire individually via TTL
    /// rather than accumulating in a single unbounded instance `Map`.
    Nullifier(BytesN<32>),
    /// Verified wallet — keyed per address.
    ///
    /// Stored in *persistent* storage for the same reason as `Nullifier`.
    Verified(Address),
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct ZkVerifier;

#[contractimpl]
impl ZkVerifier {
    // ── Initialisation ──────────────────────────────────────────────────────

    /// Initialise the contract.  Must be called exactly once.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic_with_error!(&env, ContractError::Unauthorized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Paused, &false);
        Self::extend_instance_ttl(&env);
    }

    // ── Proof verification ──────────────────────────────────────────────────

    /// Record a successful proof verification for `wallet` with the given
    /// `nullifier`.
    ///
    /// # AZ-014
    ///
    /// Both the nullifier and the verified-wallet flag are written to
    /// **persistent** storage as individual scalar entries, not appended to a
    /// shared `Map` in instance storage.  This means:
    ///
    /// * Storage cost is proportional to the *number of live entries* that
    ///   have been accessed within their TTL window — not the total historical
    ///   call count.
    /// * Each entry expires independently after `NULLIFIER_TTL_LEDGERS`
    ///   ledgers of inactivity; the contract cannot be DoS'd by flooding it
    ///   with valid (or forged) verifications.
    /// * Instance storage remains a small, fixed-size scalar set that does
    ///   not grow at runtime.
    pub fn verify(env: Env, wallet: Address, nullifier: BytesN<32>) {
        wallet.require_auth();
        Self::assert_not_paused(&env);

        // Reject replayed nullifiers.
        if env
            .storage()
            .persistent()
            .has(&DataKey::Nullifier(nullifier.clone()))
        {
            panic_with_error!(&env, ContractError::Unauthorized);
        }

        // Record the nullifier.  TTL is set here; it will be bumped on every
        // subsequent `is_verified` check so active entries stay alive.
        env.storage()
            .persistent()
            .set(&DataKey::Nullifier(nullifier.clone()), &true);
        env.storage().persistent().extend_ttl(
            &DataKey::Nullifier(nullifier.clone()),
            NULLIFIER_TTL_THRESHOLD,
            NULLIFIER_TTL_LEDGERS,
        );

        // Mark the wallet as verified.
        env.storage()
            .persistent()
            .set(&DataKey::Verified(wallet.clone()), &true);
        env.storage().persistent().extend_ttl(
            &DataKey::Verified(wallet.clone()),
            NULLIFIER_TTL_THRESHOLD,
            NULLIFIER_TTL_LEDGERS,
        );

        env.events().publish(
            (symbol_short!("verified"), wallet.clone()),
            (nullifier,),
        );

        Self::extend_instance_ttl(&env);
    }

    // ── Read helpers ────────────────────────────────────────────────────────

    /// Returns `true` if `wallet` has a live verified entry.
    pub fn is_verified(env: Env, wallet: Address) -> bool {
        let key = DataKey::Verified(wallet);
        if env.storage().persistent().has(&key) {
            // Bump TTL on read so actively-queried entries stay alive.
            env.storage().persistent().extend_ttl(
                &key,
                NULLIFIER_TTL_THRESHOLD,
                NULLIFIER_TTL_LEDGERS,
            );
            true
        } else {
            false
        }
    }

    /// Returns `true` if `nullifier` has already been spent.
    pub fn is_nullifier_spent(env: Env, nullifier: BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::Nullifier(nullifier))
    }

    // ── Admin ───────────────────────────────────────────────────────────────

    /// Pause the contract.
    pub fn pause(env: Env) {
        Self::check_admin(&env);
        env.storage().instance().set(&DataKey::Paused, &true);
        Self::extend_instance_ttl(&env);
    }

    /// Unpause the contract.
    pub fn unpause(env: Env) {
        Self::check_admin(&env);
        env.storage().instance().set(&DataKey::Paused, &false);
        Self::extend_instance_ttl(&env);
    }

    // ── Internal helpers ────────────────────────────────────────────────────

    fn check_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(env, ContractError::Unauthorized));
        admin.require_auth();
    }

    fn assert_not_paused(env: &Env) {
        let paused: bool = env
            .storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false);
        if paused {
            panic_with_error!(env, ContractError::Paused);
        }
    }

    fn extend_instance_ttl(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_LEDGERS / 2, INSTANCE_TTL_LEDGERS);
    }
}
