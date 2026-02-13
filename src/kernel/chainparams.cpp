// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) 2026-present The Bitcoin Moola Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <crypto/hex_base.h>
#include <hash.h>
#include <kernel/messagestartchars.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/log.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <map>
#include <span>
#include <utility>
#include <vector>

using namespace util::hex_literals;

static CBlock CreateGenesisBlock(const char* pszTimestamp,
                                 const CScript& genesisOutputScript,
                                 uint32_t nTime,
                                 uint32_t nNonce,
                                 uint32_t nBits,
                                 int32_t nVersion,
                                 const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.version = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);

    txNew.vin[0].scriptSig = CScript()
        << 486604799
        << CScriptNum(4)
        << std::vector<unsigned char>(
               (const unsigned char*)pszTimestamp,
               (const unsigned char*)pszTimestamp + std::strlen(pszTimestamp));

    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

// A shared script is fine for learning; timestamp+time+nonce differentiate the genesis.
static CScript MoolaGenesisScript()
{
    // Keep a valid pubkey-like blob; it doesn't matter for your assignment (coinbase is unspendable in genesis anyway).
    return CScript()
        << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"_hex
        << OP_CHECKSIG;
}

/**
 * MAIN network: Bitcoin Moola (isolated)
 */
class CMainParams : public CChainParams {
public:
    CMainParams()
    {
        m_chain_type = ChainType::MAIN;

        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();

        // Keep Bitcoin-like consensus unless your assignment requires changes.
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.MinBIP9WarningHeight = 0;

        consensus.powLimit = uint256{"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 1815;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].period = 2016;

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].threshold = 1815;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].period = 2016;

        // Remove Bitcoin chain assumptions:
        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        // Unique network magic (NOT Bitcoin)
        pchMessageStart[0] = 0x9c;
        pchMessageStart[1] = 0x52;
        pchMessageStart[2] = 0x11;
        pchMessageStart[3] = 0xa7;

        // Your chosen port style:
        nDefaultPort = 29333;

        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        // New MAIN genesis (NOT Bitcoin)
        const char* pszTimestamp = "Bitcoin Moola mainnet genesis";
        const uint32_t nTime = 1770960000;        // 2026-02-13-ish
        const uint32_t nBits = 0x207fffff;        // easy
        const uint32_t nNonce = 1;

        genesis = CreateGenesisBlock(pszTimestamp, MoolaGenesisScript(), nTime, nNonce, nBits, 1, 100 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        // Do NOT assert Bitcoin hashes. (Your chain is new.)
        // assert(consensus.hashGenesisBlock == uint256{"..."});
        // assert(genesis.hashMerkleRoot == uint256{"..."});

        // Never connect to Bitcoin seeds:
        vFixedSeeds.clear();
        vSeeds.clear();

        // Address formats (NOT Bitcoin)
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 50);  // 'M' style (arbitrary)
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 55);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1, 178);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x9a, 0x1c, 0xfe};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x9a, 0x18, 0x94};

        bech32_hrp = "mool";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        // Remove Bitcoin assumeutxo/tx stats assumptions (these are Bitcoin-specific).
        m_assumeutxo_data.clear();
        chainTxData = ChainTxData{0, 0, 0};

        // Keep headers sync params but make it harmless for a fresh chain.
        m_headers_sync_params = HeadersSyncParams{
            .commitment_period = 300,
            .redownload_buffer_size = 3000,
        };
    }
};

/**
 * TESTNET network: Bitcoin Moola testnet (isolated)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams()
    {
        m_chain_type = ChainType::TESTNET;

        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();

        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.MinBIP9WarningHeight = 0;

        consensus.powLimit = uint256{"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 1512;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].period = 2016;

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].threshold = 1512;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].period = 2016;

        // Remove Bitcoin assumptions:
        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        // Unique magic (NOT Bitcoin)
        pchMessageStart[0] = 0x6d;
        pchMessageStart[1] = 0xf3;
        pchMessageStart[2] = 0x42;
        pchMessageStart[3] = 0x19;

        // Your chosen port
        nDefaultPort = 29333; // If you want different from mainnet, change to 29334/29335, etc.

        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        // New TESTNET genesis (NOT Bitcoin)
        const char* pszTimestamp = "Bitcoin Moola testnet genesis";
        const uint32_t nTime = 1770960001;
        const uint32_t nBits = 0x207fffff;
        const uint32_t nNonce = 2;

        genesis = CreateGenesisBlock(pszTimestamp, MoolaGenesisScript(), nTime, nNonce, nBits, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        // Never connect to Bitcoin seeds:
        vFixedSeeds.clear();
        vSeeds.clear();

        // Address formats (NOT Bitcoin)
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 65);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 70);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1, 225);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0xB2, 0x47, 0x46};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0xB2, 0x43, 0x0C};

        bech32_hrp = "moolt";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        m_assumeutxo_data.clear();
        chainTxData = ChainTxData{0, 0, 0};

        m_headers_sync_params = HeadersSyncParams{
            .commitment_period = 300,
            .redownload_buffer_size = 3000,
        };
    }
};

/**
 * TESTNET4 network: Bitcoin Moola testnet4 (isolated)
 */
class CTestNet4Params : public CChainParams {
public:
    CTestNet4Params()
    {
        m_chain_type = ChainType::TESTNET4;

        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();

        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.MinBIP9WarningHeight = 0;

        consensus.powLimit = uint256{"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 1512;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].period = 2016;

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].threshold = 1512;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].period = 2016;

        // Remove Bitcoin assumptions:
        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        // Unique magic (NOT Bitcoin)
        pchMessageStart[0] = 0x91;
        pchMessageStart[1] = 0xd8;
        pchMessageStart[2] = 0x33;
        pchMessageStart[3] = 0xf0;

        // Your chosen port
        nDefaultPort = 29444;

        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        // New TESTNET4 genesis (NOT Bitcoin)
        const char* pszTimestamp = "Bitcoin Moola testnet4 genesis";
        const uint32_t nTime = 1770960002;
        const uint32_t nBits = 0x207fffff;
        const uint32_t nNonce = 3;

        genesis = CreateGenesisBlock(pszTimestamp, MoolaGenesisScript(), nTime, nNonce, nBits, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        // Never connect to Bitcoin seeds:
        vFixedSeeds.clear();
        vSeeds.clear();

        // Address formats (NOT Bitcoin)
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 75);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 80);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1, 230);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0xB2, 0x58, 0x66};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0xB2, 0x54, 0x2C};

        bech32_hrp = "mool4";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        m_assumeutxo_data.clear();
        chainTxData = ChainTxData{0, 0, 0};

        m_headers_sync_params = HeadersSyncParams{
            .commitment_period = 300,
            .redownload_buffer_size = 3000,
        };
    }
};

/**
 * Signet: keep it isolated (no seeds). Message start is computed from challenge in upstream design.
 */
class SigNetParams : public CChainParams {
public:
    explicit SigNetParams(const SigNetOptions& options)
    {
        std::vector<uint8_t> bin;
        vFixedSeeds.clear();
        vSeeds.clear();

        // If no challenge specified, keep upstream default challenge bytes but DO NOT add seeds.
        if (!options.challenge) {
            bin = "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae"_hex_v_u8;
        } else {
            bin = *options.challenge;
            LogInfo("Signet with challenge %s", HexStr(bin));
        }

        if (options.seeds) {
            // You can allow custom seeds if you explicitly pass -signetseednode,
            // but we keep default empty so it won't touch Bitcoin infra.
            vSeeds = *options.seeds;
        }

        m_chain_type = ChainType::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());

        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;

        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.MinBIP9WarningHeight = 0;

        consensus.powLimit = uint256{"00000377ae000000000000000000000000000000000000000000000000000000"};

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 1815;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].period = 2016;

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].threshold = 1815;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].period = 2016;

        // Remove Bitcoin assumptions:
        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        // message start is sha256d(challenge) first 4 bytes
        HashWriter h{};
        h << consensus.signet_challenge;
        uint256 hash = h.GetHash();
        std::copy_n(hash.begin(), 4, pchMessageStart.begin());

        nDefaultPort = 29336; // keep unique
        nPruneAfterHeight = 1000;

        // New signet genesis (NOT Bitcoin's)
        const char* pszTimestamp = "Bitcoin Moola signet genesis";
        const uint32_t nTime = 1770960003;
        const uint32_t nBits = 0x207fffff;
        const uint32_t nNonce = 4;

        genesis = CreateGenesisBlock(pszTimestamp, MoolaGenesisScript(), nTime, nNonce, nBits, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 85);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 90);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1, 235);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0xB2, 0x69, 0x76};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0xB2, 0x65, 0x3C};

        bech32_hrp = "mools";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        m_assumeutxo_data.clear();
        chainTxData = ChainTxData{0, 0, 0};

        m_headers_sync_params = HeadersSyncParams{
            .commitment_period = 300,
            .redownload_buffer_size = 3000,
        };
    }
};

/**
 * Regression test: keep isolated. You already used regtest successfully.
 */
class CRegTestParams : public CChainParams
{
public:
    explicit CRegTestParams(const RegTestOptions& opts)
    {
        m_chain_type = ChainType::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();

        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0;

        consensus.powLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = opts.enforce_bip94;
        consensus.fPowNoRetargeting = true;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].period = 144;

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].threshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].period = 144;

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        // Unique regtest magic (NOT Bitcoin regtest)
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xdb;

        nDefaultPort = 29444;
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;

        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        for (const auto& [dep, height] : opts.activation_heights) {
            switch (dep) {
            case Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT:   consensus.SegwitHeight = int{height}; break;
            case Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB: consensus.BIP34Height = int{height}; break;
            case Consensus::BuriedDeployment::DEPLOYMENT_DERSIG:   consensus.BIP66Height = int{height}; break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CLTV:     consensus.BIP65Height = int{height}; break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CSV:      consensus.CSVHeight = int{height}; break;
            }
        }

        for (const auto& [deployment_pos, version_bits_params] : opts.version_bits_parameters) {
            consensus.vDeployments[deployment_pos].nStartTime = version_bits_params.start_time;
            consensus.vDeployments[deployment_pos].nTimeout = version_bits_params.timeout;
            consensus.vDeployments[deployment_pos].min_activation_height = version_bits_params.min_activation_height;
        }

        // New regtest genesis (NOT Bitcoin regtest)
        const char* pszTimestamp = "Bitcoin Moola regtest genesis";
        const uint32_t nTime = 1770960004;
        const uint32_t nBits = 0x207fffff;
        const uint32_t nNonce = 5;

        genesis = CreateGenesisBlock(pszTimestamp, MoolaGenesisScript(), nTime, nNonce, nBits, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        // No seeds.
        vFixedSeeds.clear();
        vSeeds.clear();

        fDefaultConsistencyChecks = true;
        m_is_mockable_chain = true;

        m_assumeutxo_data.clear();
        chainTxData = ChainTxData{0, 0, 0.001};

        // Address formats (NOT Bitcoin regtest)
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0xB2, 0x7A, 0x86};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0xB2, 0x76, 0x4C};

        bech32_hrp = "moolr";

        m_headers_sync_params = HeadersSyncParams{
            .commitment_period = 300,
            .redownload_buffer_size = 3000,
        };
    }
};

std::unique_ptr<const CChainParams> CChainParams::SigNet(const SigNetOptions& options)
{
    return std::make_unique<const SigNetParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::RegTest(const RegTestOptions& options)
{
    return std::make_unique<const CRegTestParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::Main()
{
    return std::make_unique<const CMainParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet()
{
    return std::make_unique<const CTestNetParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet4()
{
    return std::make_unique<const CTestNet4Params>();
}

std::vector<int> CChainParams::GetAvailableSnapshotHeights() const
{
    std::vector<int> heights;
    heights.reserve(m_assumeutxo_data.size());

    for (const auto& data : m_assumeutxo_data) {
        heights.emplace_back(data.height);
    }
    return heights;
}

std::optional<ChainType> GetNetworkForMagic(const MessageStartChars& message)
{
    const auto mainnet_msg = CChainParams::Main()->MessageStart();
    const auto testnet_msg = CChainParams::TestNet()->MessageStart();
    const auto testnet4_msg = CChainParams::TestNet4()->MessageStart();
    const auto regtest_msg = CChainParams::RegTest({})->MessageStart();
    const auto signet_msg = CChainParams::SigNet({})->MessageStart();

    if (std::ranges::equal(message, mainnet_msg)) {
        return ChainType::MAIN;
    } else if (std::ranges::equal(message, testnet_msg)) {
        return ChainType::TESTNET;
    } else if (std::ranges::equal(message, testnet4_msg)) {
        return ChainType::TESTNET4;
    } else if (std::ranges::equal(message, regtest_msg)) {
        return ChainType::REGTEST;
    } else if (std::ranges::equal(message, signet_msg)) {
        return ChainType::SIGNET;
    }
    return std::nullopt;
}
