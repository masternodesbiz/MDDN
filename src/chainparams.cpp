// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2020 The PIVX developers
// Copyright (c) 2021-2022 The DECENOMY Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "chainparamsseeds.h"
#include "consensus/merkle.h"
#include "util.h"
#include "utilstrencodings.h"

#include <boost/assign/list_of.hpp>

#include <assert.h>

#define DISABLED 0x7FFFFFFE;

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.nVersion = nVersion;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of the genesis coinbase cannot
 * be spent as it did not originally exist in the database.
 *
 * CBlock(hash=00000ffd590b14, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=e0028e, nTime=1390095618, nBits=1e0ffff0, nNonce=28917698, vtx=1)
 *   CTransaction(hash=e0028e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0xA9037BAC7050C479B121CF)
 *   vMerkleTree: e0028e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Modden July 2022";
    const CScript genesisOutputScript = CScript() << ParseHex("04e209a299d9b1483b42c1e827975054b276188cb1b86943ebf9673a955b4bfb466d6ef5167539deac570ebb9df4eb5b256a9dd2a5a9bd44399e16d9bf6fae46c2") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

static Checkpoints::MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
    (0, uint256S("0x00000ef20371800a04939c0eea309ba510c69c2114496de3796215ddf6d30a54"))
    (1, uint256S("0x000005ccfa68087e719a4d63b9bdfee330dfe1554e56f94472a2b775e7e05db2"))
    (16, uint256S("0x00000ca294331cb5378a0dfd750ed8c14450cc4ada5bb2c286d088f5f93a7a77"))
    (50, uint256S("0x0000082dabae542c8b0d89b1d2983f858523744c98141d579144dee9a7f3e103"))
    (101, uint256S("0x000000accccbb82bba04745607679ee9760a12b8a122a90b0219476152eceb99"))
    (116, uint256S("0x0000030f06b47d740f62503398bbc9f81527cee5b077a90be1be91ec0f50922b"))
    (200, uint256S("0x0000044a8f22a15898341f1faa0ea7bc5478953dbf86db382fa8c811679fe312"))
    (500, uint256S("0x0000062c200a9a34a3a165dbdaf3e19c3b7fe565c634b871cbb1980cda69a57a"))
    (1001, uint256S("0xfed229d2b98541da14d14f845fde4a2b612a2dcb374632e1d2c5642f2dfb69d7"))
    (1312, uint256S("0x71803a61c73d9265663b8ca9bb8e957557c475459da1b0a41d203b8999edcb08"))
    (1517, uint256S("0x07716c6e32154f15185e1ba639fabfd857ef04a61e26a0856381f8d67e6b61f0"))
    (1625, uint256S("0xe1b3194b1429d491d7901a6c6d290d9f535488bf8c0cef05cdc86fd3b9af498b"))
    (1960, uint256S("0x65383631dc33d313c8612e6ad9287cc1920ef53f1917c41cb1141f16ec76d502"))
    (10000, uint256S("0x2516190fcc7e83a998f988336cb82a59be6d0126e6661a7ab91c02b9966236dc"))
    (20000, uint256S("0xcdb79d04b0201e8e47ab0a3230455e8ca8e199d4a3862d7e9e6c8c07ca992e88"))
    (30000, uint256S("0xad5e9be70ad1a84f33f6e00aa148adfa273c2fef7400d558ebf139cd91fe0250"))
    (40000, uint256S("0x409e53528fd5dfac0dbe923d61d75144ff6f6239c429e7db69f9d3aef0a5693a"))
    (50000, uint256S("0xdb3fa3f2eba899784bbb1ad977da9929dce60f113715cbe7f882ef7b8dc1de14"))
    (56845, uint256S("0xf999b936434fda6c6323ef47469fd64d8c54faf7fbc32fb621ba91d0c253a52b"))
    (70000, uint256S("0x04ef273a02372ae9adf006f9811ddcd1a35c133c45e3b8cbbaa6692b9457aafe"))
    (80000, uint256S("0xb4c0c5e7246ba4e1996d69d59544a46c94e5e1fb9ff0a0ef701a02429f03d443"))
    (90000, uint256S("0x1ee00d1140b1ddbfa82358f02c40d4036e3ccd394f9189d247d03aabe3576df8"))
    (100000, uint256S("0x78e9d26fc95d83917bcce1f84f698fd694fca5004acaaf64a7b5b1254fe1c7ff"))
    (110000, uint256S("0x09e55cbb893b57cf626b697bc148ac20d9782e1e55f1dfb41cdf53a13325efd4"))
    (120000, uint256S("0xf75c840042bf094fc3de8b92d89fe322b3e1adde62614ef0dd7bb4def67fdd74"))
    (130000, uint256S("0x19e8a1141943b183ba4e3905f91b4eef6770bf15cf146a5349eb26aad392851d"))
    (140000, uint256S("0xc60669aa81156f4e3a5e8bcbbe9de54de7f59e7093ef425490d6d404822659f2"))
    (150000, uint256S("0xb0250bc1efb2875f1aefc9bf62512ef37f26ea93a721ab2a654a79bde881f7cd"))
    (160000, uint256S("0x8cc4bfbdb853a9fe3a627ba3add04dce4f57e5a25f90680ec9546590786bebaf"))
    (170000, uint256S("0xc4fb259cb4bbcdbc24cc45964101b416ae2c12b893c7b691dbce84f4e2d24b44"))
    (180000, uint256S("0xf66883dd99e1fed08497632e022ec899eeebcbb9d372fb30fa4b98d5e672ff9a"))
    (190000, uint256S("0x1318421e5b212504b3be9275aaf561b32e7f64103bc5a3748e857a79bb5a9f7c"))
    (200000, uint256S("0xbeae1be2e1fb18e0b3a1a539e903265ffc9b179892983b22a6b3d9c65c36794b"))
    (210000, uint256S("0xa7975f25d9d9a28fb2228d67ecd2703c340c0c8306eab99d2dc4182c0cb2dc6f"))
    (220000, uint256S("0xad3e3b1a391edd3e3dac179733f43ce3ffda62217a9f2d20849de35636e507bf"))
    (230000, uint256S("0x96a8bcece4b56990f3d8e6b01ba17c3e8033c4d4088adeabf792de890a454678"))
    (240000, uint256S("0x2387e035a832e9b8a4af02c5a33654ef4740d496e1112f9ff825fdde288415fc"))
    (250000, uint256S("0x629b556382607a67198f33fe5662c70a40e78c0147127be51804a88e66d2c171"))
    (260000, uint256S("0x0fbf388b131895fa1ac2e83cc320e6cf471644537ff5e86d577892a78509ee48"))
    (270000, uint256S("0x5f637b2e4d68e84332e26a56745db822c8470404fb24cb16d919977ff59f4621"))
    (280000, uint256S("0x702e8cba971b6751aa9a94b5ae99e00ef7f55039ac72fab006caf63e1b8ccb55"))
    (290000, uint256S("0x36be760b3d5cbf1039768489d9497ff629d662cb2e7605086d4cdcbf7dee56ae"))
    (300000, uint256S("0x6d4aadf71c41b5f2030a1c945ad062aff0055d48916477b134a835ac6d8c0378"))
    (310000, uint256S("0xef853ae704220815281bccce759f7e5f41577a2e0424c6f65417179ef3ae3732"))
    (320000, uint256S("0x9c0496f4f3ed87877a6467db0b2fc16c55b4817c52f98a0885620efde5b55930"))
    (330000, uint256S("0xeaca988487cb9ab14f645dc7097b83c2e3cec2e665904d842e3cfbff68601ee6"))
    (340000, uint256S("0x8049ae111d10c7475d5af5a81440897138cf90b8c9e2b3a3fc734d67c69e42e4"))
    (350000, uint256S("0x36cbcd6e3954e43cd7a7d2c9f952765ada926de9b6065ef8dfb4b577759b71f8"))
    (360000, uint256S("0xb9b3263f714a0882be5c542bb426a7adb4cd566f11f0c8a6231458c59d89eaa8"))
    (370000, uint256S("0xc8d283ef7c8486c5b679197b9e8893fdde2041a9fe4ddbf276323f131daf8906"))
    (380000, uint256S("0x56f8d40dfdfb77e1d843cb2566379ec14bc32381f871864feb91c56e611f0ec2"))
    (390000, uint256S("0x07911c1188459e9b415b056914d847a9cdfe413a7a0c948944f6736bb98c800c"))
    (400000, uint256S("0x57d6d479326adba72c26c0c6712ff78d35f7725343b7d1b313f11bf1e96c2f2f"))
    (410000, uint256S("0x63957edfe78965705ba08e2605afd0c0f8fa797620d0aad93c241dc357d02fa4"));

    static const Checkpoints::CCheckpointData data = {
    &mapCheckpoints,
    1660450425, // * UNIX timestamp of last checkpoint block
    118128,          // * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the UpdateTip debug.log lines)
    1.000        // * estimated number of transactions per day after checkpoint
};

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
    boost::assign::map_list_of
    (0, uint256S("0x000003c75888e7183cab1f252acccf35778af65199bfbbff4700377c21669040"));

static const Checkpoints::CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
    1656793445,
    0,
    0.000
    };

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
    boost::assign::map_list_of(0, uint256S("0x000008beabf48112d3cdeec6fa076f051656ea5be0d5765370fe429bec04d001"));

static const Checkpoints::CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
    1656793446,
    0,
    0.000
    };

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";

        // // This is used inorder to mine the genesis block. Once found, we can use the nonce and block hash found to create a valid genesis block
        // /////////////////////////////////////////////////////////////////

        // uint32_t nGenesisTime = 1612360301; // 2021-02-03T13:51:41+00:00

        // arith_uint256 test;
        // bool fNegative;
        // bool fOverflow;
        // test.SetCompact(0x1e0ffff0, &fNegative, &fOverflow);
        // std::cout << "Test threshold: " << test.GetHex() << "\n\n";

        // int genesisNonce = 0;
        // uint256 TempHashHolding = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
        // uint256 BestBlockHash = uint256S("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // for (int i=0;i<40000000;i++) {
        //     genesis = CreateGenesisBlock(nGenesisTime, i, 0x1e0ffff0, 1, 0 * COIN);
        //     //genesis.hashPrevBlock = TempHashHolding;
        //     consensus.hashGenesisBlock = genesis.GetHash();

        //     arith_uint256 BestBlockHashArith = UintToArith256(BestBlockHash);
        //     if (UintToArith256(consensus.hashGenesisBlock) < BestBlockHashArith) {
        //         BestBlockHash = consensus.hashGenesisBlock;
        //         std::cout << BestBlockHash.GetHex() << " Nonce: " << i << "\n";
        //         std::cout << "   PrevBlockHash: " << genesis.hashPrevBlock.GetHex() << "\n";
        //     }

        //     TempHashHolding = consensus.hashGenesisBlock;

        //     if (BestBlockHashArith < test) {
        //         genesisNonce = i - 1;
        //         break;
        //     }
        //     //std::cout << consensus.hashGenesisBlock.GetHex() << "\n";
        // }
        // std::cout << "\n";
        // std::cout << "\n";
        // std::cout << "\n";

        // std::cout << "hashGenesisBlock to 0x" << BestBlockHash.GetHex() << std::endl;
        // std::cout << "Genesis Nonce to " << genesisNonce << std::endl;
        // std::cout << "Genesis Merkle 0x" << genesis.hashMerkleRoot.GetHex() << std::endl;

        // exit(0);

        // /////////////////////////////////////////////////////////////////

        genesis = CreateGenesisBlock(1656793447, 947130, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000ef20371800a04939c0eea309ba510c69c2114496de3796215ddf6d30a54"));
        assert(genesis.hashMerkleRoot == uint256S("0xf6013c5cd370397fbdc06890e4afbc4614a651b432f7d7b6dfb4f8afd15ed5e2"));

        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.powLimit   = ~UINT256_ZERO >> 20;   
        consensus.posLimitV1 = ~UINT256_ZERO >> 24;
        consensus.posLimitV2 = ~UINT256_ZERO >> 20;
        consensus.nCoinbaseMaturity = 100;
        consensus.nFutureTimeDriftPoW = 7200;
        consensus.nFutureTimeDriftPoS = 180;
        consensus.nMaxMoneyOut = 101103990 * COIN;
        consensus.nPoolMaxTransactions = 3;
        consensus.nStakeMinAge = 60 * 60; // 1h
        consensus.nStakeMinDepth = 100;
        consensus.nStakeMinDepthV2 = 600;
        consensus.nTargetTimespan = 40 * 60;
        consensus.nTargetTimespanV2 = 30 * 60;
        consensus.nTargetSpacing = 1 * 60;
        consensus.nTimeSlotLength = 15;

        // spork keys
        consensus.strSporkPubKey = "020eb4246169b82f096ce6e9b4c0c66a98a8a9792e20603fbc0c20a6c5a52f3acc";
        consensus.strSporkPubKeyOld = "027d96f4ce20d72bcbaaa78447dbc287db7e32ebcfe740c0d3601d79de9ed8a8cb";
        consensus.nTime_EnforceNewSporkKey = 0;
        consensus.nTime_RejectOldSporkKey = 0;

        // burn addresses
        consensus.mBurnAddresses = {

           { "MCTk4Q1vnhZ253YFDAxYQnURQFWgMeanTf", 57728 },

        };

        // Network upgrades
        consensus.vUpgrades[Consensus::BASE_NETWORK].nActivationHeight                   = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight              = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_POS].nActivationHeight                    = 1001;
        consensus.vUpgrades[Consensus::UPGRADE_POS_V2].nActivationHeight                 = 1441;
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].nActivationHeight                  = 1441;
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MODIFIER_V2].nActivationHeight      = 1541;
        consensus.vUpgrades[Consensus::UPGRADE_TIME_PROTOCOL_V2].nActivationHeight       = 1641;
        consensus.vUpgrades[Consensus::UPGRADE_P2PKH_BLOCK_SIGNATURES].nActivationHeight = 1741;
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MIN_DEPTH_V2].nActivationHeight     = 5001;
        consensus.vUpgrades[Consensus::UPGRADE_MASTERNODE_RANK_V2].nActivationHeight     = 115000;

        consensus.vUpgrades[Consensus::UPGRADE_POS].hashActivationBlock                    = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_POS_V2].hashActivationBlock                 = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].hashActivationBlock                  = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MODIFIER_V2].hashActivationBlock      = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_TIME_PROTOCOL_V2].hashActivationBlock       = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_P2PKH_BLOCK_SIGNATURES].hashActivationBlock = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MIN_DEPTH_V2].hashActivationBlock     = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_MASTERNODE_RANK_V2].hashActivationBlock     = uint256S("0x0");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0xb2;
        pchMessageStart[1] = 0xf1;
        pchMessageStart[2] = 0xe0;
        pchMessageStart[3] = 0xb9;
        nDefaultPort = 8668;

        vSeeds.push_back(CDNSSeedData("seed01", "seed01.modden.io"));
        vSeeds.push_back(CDNSSeedData("seed02", "seed02.modden.io"));
        vSeeds.push_back(CDNSSeedData("seed03", "seed03.modden.io"));
        vSeeds.push_back(CDNSSeedData("seed04", "seed04.modden.io"));
        vSeeds.push_back(CDNSSeedData("seed05", "seed05.modden.io"));
        vSeeds.push_back(CDNSSeedData("seed06", "seed06.modden.io"));
        vSeeds.push_back(CDNSSeedData("seed07", "seed07.modden.io"));
        vSeeds.push_back(CDNSSeedData("seed08", "seed08.modden.io"));
        vSeeds.push_back(CDNSSeedData("seed09", "seed09.modden.io"));
        vSeeds.push_back(CDNSSeedData("seed10", "seed10.modden.io"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 50); // M
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 51); // M
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 231);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x02)(0x2D)(0x25)(0x33).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x02)(0x21)(0x31)(0x2B).convert_to_container<std::vector<unsigned char> >();
        // BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x03)(0x99).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));
        //convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main)); // added
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }

};
static CMainParams mainParams;

/**
 * Testnet (v1)
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";

        genesis = CreateGenesisBlock(1454124731, 2402015, 0x1e0ffff0, 1, 250 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        //assert(consensus.hashGenesisBlock == uint256S("0x0000041e482b9b9691d98eefb48473405c0b8ec31b76df3797c74a78680ef818"));
        //assert(genesis.hashMerkleRoot == uint256S("0x1b2ef6e2f28be914103a277377ae7729dcd125dfeb8bf97bd5964ba72b6dc39b"));

        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.powLimit   = ~UINT256_ZERO >> 20;   // modden starting difficulty is 1 / 2^12
        consensus.posLimitV1 = ~UINT256_ZERO >> 24;
        consensus.posLimitV2 = ~UINT256_ZERO >> 20;
        consensus.nCoinbaseMaturity = 15;
        consensus.nFutureTimeDriftPoW = 7200;
        consensus.nFutureTimeDriftPoS = 180;
        consensus.nMaxMoneyOut = 43199500 * COIN;
        consensus.nPoolMaxTransactions = 2;
        consensus.nStakeMinAge = 60 * 60;
        consensus.nStakeMinDepth = 100;
        consensus.nStakeMinDepthV2 = 200;
        consensus.nTargetTimespan = 40 * 60;
        consensus.nTargetTimespanV2 = 30 * 60;
        consensus.nTargetSpacing = 1 * 60;
        consensus.nTimeSlotLength = 15;

        // spork keys
        consensus.strSporkPubKey = "03ef91259425a39d0deba6190caebd9326800e6dbc140a41472bb2663d19680fcc";
        consensus.strSporkPubKeyOld = "";
        consensus.nTime_EnforceNewSporkKey = 0;
        consensus.nTime_RejectOldSporkKey = 0;

        // Network upgrades
        consensus.vUpgrades[Consensus::BASE_NETWORK].nActivationHeight                      = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight                 = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_POS].nActivationHeight                       = 201;
        consensus.vUpgrades[Consensus::UPGRADE_POS_V2].nActivationHeight                    = 1441;
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].nActivationHeight                     = 1441;
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MODIFIER_V2].nActivationHeight         = 1541;
        consensus.vUpgrades[Consensus::UPGRADE_TIME_PROTOCOL_V2].nActivationHeight          = 1641;
        consensus.vUpgrades[Consensus::UPGRADE_P2PKH_BLOCK_SIGNATURES].nActivationHeight    = 1741;
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MIN_DEPTH_V2].nActivationHeight        = 1841;

        consensus.vUpgrades[Consensus::UPGRADE_POS].hashActivationBlock                     = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_POS_V2].hashActivationBlock                  = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].hashActivationBlock                   = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MODIFIER_V2].hashActivationBlock       = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_TIME_PROTOCOL_V2].hashActivationBlock        = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_P2PKH_BLOCK_SIGNATURES].hashActivationBlock  = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MIN_DEPTH_V2].hashActivationBlock      = uint256S("0x0");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */

        pchMessageStart[0] = 0xb7;
        pchMessageStart[1] = 0x8b;
        pchMessageStart[2] = 0x4c;
        pchMessageStart[3] = 0xd3;
        nDefaultPort = __PORT_TESTNET__;

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.push_back(CDNSSeedData("tseeder", "tseeder.modden.net__", true));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 139); // Testnet modden addresses start with 'x' or 'y'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 19);  // Testnet modden script addresses start with '8' or '9'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);     // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        // Testnet modden BIP32 pubkeys start with 'DRKV'
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x3a)(0x80)(0x61)(0xa0).convert_to_container<std::vector<unsigned char> >();
        // Testnet modden BIP32 prvkeys start with 'DRKP'
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x3a)(0x80)(0x58)(0x37).convert_to_container<std::vector<unsigned char> >();
        // Testnet modden BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";

        genesis = CreateGenesisBlock(1454124731, 2402015, 0x1e0ffff0, 1, 250 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        //assert(consensus.hashGenesisBlock == uint256S("0x0000041e482b9b9691d98eefb48473405c0b8ec31b76df3797c74a78680ef818"));
        //assert(genesis.hashMerkleRoot == uint256S("0x1b2ef6e2f28be914103a277377ae7729dcd125dfeb8bf97bd5964ba72b6dc39b"));

        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.powLimit   = ~UINT256_ZERO >> 20;   // modden starting difficulty is 1 / 2^12
        consensus.posLimitV1 = ~UINT256_ZERO >> 24;
        consensus.posLimitV2 = ~UINT256_ZERO >> 20;
        consensus.nCoinbaseMaturity = 100;
        consensus.nFutureTimeDriftPoW = 7200;
        consensus.nFutureTimeDriftPoS = 180;
        consensus.nMaxMoneyOut = 43199500 * COIN;
        consensus.nPoolMaxTransactions = 2;
        consensus.nStakeMinAge = 0;
        consensus.nStakeMinDepth = 2;
        consensus.nTargetTimespan = 40 * 60;
        consensus.nTargetTimespanV2 = 30 * 60;
        consensus.nTargetSpacing = 1 * 60;
        consensus.nTimeSlotLength = 15;

        /* Spork Key for RegTest:
        WIF private key: 932HEevBSujW2ud7RfB1YF91AFygbBRQj3de3LyaCRqNzKKgWXi
        private key hex: bd4960dcbd9e7f2223f24e7164ecb6f1fe96fc3a416f5d3a830ba5720c84b8ca
        Address: yCvUVd72w7xpimf981m114FSFbmAmne7j9
        */
        consensus.strSporkPubKey = "043969b1b0e6f327de37f297a015d37e2235eaaeeb3933deecd8162c075cee0207b13537618bde640879606001a8136091c62ec272dd0133424a178704e6e75bb7";
        consensus.strSporkPubKeyOld = "";
        consensus.nTime_EnforceNewSporkKey = 0;
        consensus.nTime_RejectOldSporkKey = 0;

        // Network upgrades
        consensus.vUpgrades[Consensus::BASE_NETWORK].nActivationHeight =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
                Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_POS].nActivationHeight           = 251;
        consensus.vUpgrades[Consensus::UPGRADE_POS_V2].nActivationHeight        = 251;
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].nActivationHeight         =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MODIFIER_V2].nActivationHeight          = 251;
        consensus.vUpgrades[Consensus::UPGRADE_TIME_PROTOCOL_V2].nActivationHeight          =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_P2PKH_BLOCK_SIGNATURES].nActivationHeight       = 300;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */

        pchMessageStart[0] = 0xa1;
        pchMessageStart[1] = 0xcf;
        pchMessageStart[2] = 0x7e;
        pchMessageStart[3] = 0xac;
        nDefaultPort = __PORT_REGTEST__;

        vFixedSeeds.clear(); //! Testnet mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Testnet mode doesn't have any DNS seeds.
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }

    void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
    {
        assert(idx > Consensus::BASE_NETWORK && idx < Consensus::MAX_NETWORK_UPGRADES);
        consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
    }
};
static CRegTestParams regTestParams;

static CChainParams* pCurrentParams = 0;

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    regTestParams.UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}
