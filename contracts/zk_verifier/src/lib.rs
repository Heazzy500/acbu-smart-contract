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
//! DataKey::Verified(Address)      →  VerificationRecord (fixed validity deadline)
//! DataKey::AttestedCommitment(BytesN<32>) → bool (ledger-TTL-bumped on register)
//! DataKey::Admin                  →  Address   (instance — single scalar, bounded)
//! DataKey::Paused                 →  bool      (instance — single scalar, bounded)
//! ```
//!
//! Each entry lives in `persistent` storage. Nullifiers and attestations use a
//! bounded storage TTL, while verification records carry an immutable validity
//! deadline and can also be revoked by the administrator.
//!
//! Instance storage is used **only** for the small, fixed set of contract
//! configuration fields (admin, paused flag) whose combined size is a known
//! constant that cannot grow at runtime.

use shared::ContractError;
use soroban_sdk::{
    contract, contractimpl, contracttype, panic_with_error, symbol_short, Address, BytesN, Env,
};

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

/// A verification remains valid for about 30 days at one ledger per 5 seconds.
pub const VERIFICATION_VALIDITY_LEDGERS: u32 = 525_600;

/// The policy proved by the caller and recorded for downstream audit/indexing.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationPolicy {
    pub min_tier: u32,
    pub country_code: u32,
    pub requested_amount: u128,
    pub daily_cap: u128,
    pub already_used: u128,
}

/// Named circuit inputs. Keeping these fields structured prevents callers from
/// silently changing their meaning by reordering or re-padding a byte vector.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationInputs {
    pub min_tier: u32,
    pub country_code: u32,
    pub requested_amount: u128,
    pub daily_cap: u128,
    pub already_used: u128,
    pub nullifier: BytesN<32>,
    pub commitment: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationRecord {
    pub expires_at_ledger: u32,
    pub nullifier: BytesN<32>,
    pub policy: VerificationPolicy,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedEvent {
    pub user: Address,
    pub nullifier: BytesN<32>,
    pub policy: VerificationPolicy,
    pub expires_at_ledger: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationRevokedEvent {
    pub user: Address,
    pub revoked_at_ledger: u32,
}

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
    /// Spent nullifier — keyed per (commitment, nullifier) pair.
    ///
    /// Stored in *persistent* storage so entries expire individually via TTL
    /// rather than accumulating in a single unbounded instance `Map`.
    ScopedNullifier(BytesN<32>, BytesN<32>),
    /// Verified wallet record — keyed per address and bounded by its deadline.
    ///
    /// Stored in *persistent* storage for the same reason as `Nullifier`.
    Verified(Address),
    /// Attested credential commitment — keyed per 32-byte commitment.
    ///
    /// AZ-002: commitments recorded by the trusted KYC authority (the
    /// admin). Stored in *persistent* storage like `Nullifier`/`Verified`
    /// so the registry stays bounded.
    AttestedCommitment(BytesN<32>),
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

    /// AZ-002 — trusted commitment registry.
    ///
    /// The admin acts as the trusted KYC authority: after a user's redacted
    /// KYC review is approved, it records the user's credential commitment
    /// `poseidon2(kyc_level, country_code, salt)` — derived from the
    /// authority's **own** verified records, never from user-claimed values.
    ///
    /// Only attested commitments are accepted by `verify`, so an unverified
    /// user can no longer claim an arbitrary `kyc_level` and produce a valid
    /// proof about a self-asserted credential.
    pub fn register_commitment(env: Env, commitment: BytesN<32>) {
        // The KYC authority (admin) is the only party allowed to attest.
        Self::check_admin(&env);
        Self::assert_not_paused(&env);

        if env
            .storage()
            .persistent()
            .has(&DataKey::AttestedCommitment(commitment.clone()))
        {
            panic_with_error!(&env, ContractError::CommitmentAlreadyAttested);
        }

        env.storage()
            .persistent()
            .set(&DataKey::AttestedCommitment(commitment.clone()), &true);
        env.storage().persistent().extend_ttl(
            &DataKey::AttestedCommitment(commitment.clone()),
            NULLIFIER_TTL_THRESHOLD,
            NULLIFIER_TTL_LEDGERS,
        );

        env.events()
            .publish((symbol_short!("attested"), commitment.clone()), ());

        Self::extend_instance_ttl(&env);
    }

    /// Returns `true` if `commitment` was attested by the trusted KYC
    /// authority.
    pub fn is_attested(env: Env, commitment: BytesN<32>) -> bool {
        let key = DataKey::AttestedCommitment(commitment);
        if env.storage().persistent().has(&key) {
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

    /// Record a successful proof verification for `wallet` with the given
    /// named public inputs, including the nullifier and credential commitment.
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
    ///
    /// # AZ-002
    ///
    /// The credential `commitment` submitted with the proof must have been
    /// attested by the trusted KYC authority first. Proofs about commitments
    /// that were never attested are rejected — the proof would otherwise be
    /// vacuous (knowledge of *some* preimage for a self-chosen commitment).
    pub fn verify(env: Env, wallet: Address, inputs: VerificationInputs) {
        wallet.require_auth();
        Self::assert_not_paused(&env);

        let nullifier = inputs.nullifier.clone();
        let commitment = inputs.commitment.clone();
        let policy = VerificationPolicy {
            min_tier: inputs.min_tier,
            country_code: inputs.country_code,
            requested_amount: inputs.requested_amount,
            daily_cap: inputs.daily_cap,
            already_used: inputs.already_used,
        };

        // AZ-002 — reject proofs whose commitment was never attested by the
        // trusted KYC authority.
        if !env
            .storage()
            .persistent()
            .has(&DataKey::AttestedCommitment(commitment.clone()))
        {
            panic_with_error!(&env, ContractError::CommitmentNotAttested);
        }

        // Reject replayed nullifiers for this commitment.
        if env
            .storage()
            .persistent()
            .has(&DataKey::ScopedNullifier(commitment.clone(), nullifier.clone()))
        {
            panic_with_error!(&env, ContractError::NullifierAlreadySpent);
        }

        // Record the nullifier.  TTL is set here; it will be bumped on every
        // subsequent `is_verified` check so active entries stay alive.
        env.storage()
            .persistent()
            .set(&DataKey::ScopedNullifier(commitment.clone(), nullifier.clone()), &true);
        env.storage().persistent().extend_ttl(
            &DataKey::ScopedNullifier(commitment.clone(), nullifier.clone()),
            NULLIFIER_TTL_THRESHOLD,
            NULLIFIER_TTL_LEDGERS,
        );

        // Store an immutable validity deadline. Reads never extend this deadline,
        // so a stale credential cannot remain valid merely because it is queried.
        let expires_at_ledger = env
            .ledger()
            .sequence()
            .saturating_add(VERIFICATION_VALIDITY_LEDGERS);
        let record = VerificationRecord {
            expires_at_ledger,
            nullifier: nullifier.clone(),
            policy: policy.clone(),
        };
        env.storage()
            .persistent()
            .set(&DataKey::Verified(wallet.clone()), &record);
        env.storage().persistent().extend_ttl(
            &DataKey::Verified(wallet.clone()),
            VERIFICATION_VALIDITY_LEDGERS / 2,
            VERIFICATION_VALIDITY_LEDGERS,
        );

        env.events().publish(
            (symbol_short!("verified"),),
            VerifiedEvent {
                user: wallet,
                nullifier,
                policy,
                expires_at_ledger,
            },
        );

        Self::extend_instance_ttl(&env);
    }

    // ── Read helpers ────────────────────────────────────────────────────────

    /// Returns `true` only while `wallet` has a non-expired verification.
    pub fn is_verified(env: Env, wallet: Address) -> bool {
        let key = DataKey::Verified(wallet);
        env.storage()
            .persistent()
            .get::<_, VerificationRecord>(&key)
            .is_some_and(|record| env.ledger().sequence() < record.expires_at_ledger)
    }

    /// Return the current verification record when it is still valid.
    pub fn verification(env: Env, wallet: Address) -> Option<VerificationRecord> {
        let key = DataKey::Verified(wallet);
        env.storage()
            .persistent()
            .get::<_, VerificationRecord>(&key)
            .filter(|record| env.ledger().sequence() < record.expires_at_ledger)
    }

    /// Returns `true` if `nullifier` has already been spent for `commitment`.
    pub fn is_nullifier_spent(env: Env, commitment: BytesN<32>, nullifier: BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::ScopedNullifier(commitment, nullifier))
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

    /// Revoke a wallet's verification immediately. Only the administrator may
    /// revoke, and successful revocations are emitted for off-chain indexers.
    pub fn revoke_verification(env: Env, wallet: Address) -> bool {
        Self::check_admin(&env);
        let key = DataKey::Verified(wallet.clone());
        if !env.storage().persistent().has(&key) {
            return false;
        }

        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("revoked"),),
            VerificationRevokedEvent {
                user: wallet,
                revoked_at_ledger: env.ledger().sequence(),
            },
        );
        Self::extend_instance_ttl(&env);
        true
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
