#include <array>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include /*cryptopp*/ <ecp.h>
#include /*cryptopp*/ <oids.h>

#include <snarkfront.hpp>

#include <kapital/AddressKey.hpp>
#include <kapital/Coin.hpp>
#include <kapital/EncryptedCoin.hpp>
#include <kapital/ProvePour.hpp>
#include <kapital/PourZKP.hpp>
#include <kapital/SignatureKey.hpp>
#include <kapital/Variable.hpp>
#include <kapital/VerifyPour.hpp>

using namespace kapital;
using namespace snarkfront;
using namespace std;

void printUsage(const char* exeName) {
    cerr << "Usage: " << exeName << " -p <pairing> -d <number>" << endl
         << "Options:" << endl
         << "  -p <pairing>  Elliptic curve pairing: BN128, Edwards" << endl
         << "  -d <number>   Merkle tree authentication path length: 1, 2,.., 64" << endl;

    exit(EXIT_FAILURE);
}

template <typename T>
bool rndtripOK(const T& a) {
    stringstream ss;
    ss << a;
    T b;
    ss >> b;
    return b.valid();
}

string okStr(const bool b) {
    return b ? "ok" : "fail";
}

template <typename T>
void hexDump(const T& a) {
    stringstream ss;
    ss << a;
    vector<uint8_t> v;
    for (const auto& c : ss.str()) v.push_back(c);
    HexDumper dump(cout);
    dump.print(v);
}

////////////////////////////////////////////////////////////////////////////////
// round trip tests
//
template <typename FIELD>
bool roundtripTests(const CryptoPP::OID& oid) {
    const SecretAddr<FIELD> sk(oid);
    const bool rndtrip_sk = rndtripOK(sk);
    cout << "secret key:" << endl;
    hexDump(sk);
    cout << "roundtrip is " << okStr(rndtrip_sk) << endl << endl;

    const PublicAddr<FIELD> pk(sk);
    const bool rndtrip_pk = rndtripOK(pk);
    cout << "public key:" << endl;
    hexDump(pk);
    cout << "roundtrip is " << okStr(rndtrip_pk) << endl << endl;

    const Coin<FIELD> coin(pk);
    const bool rndtrip_coin = rndtripOK(coin);
    cout << "coin:" << endl;
    hexDump(coin);
    cout << "roundtrip is " << okStr(rndtrip_coin) << endl << endl;

    const EncryptedCoin<FIELD> encCoin(coin);
    cout << "encrypted coin:" << endl;
    hexDump(encCoin);
    stringstream ss;
    ss << encCoin;
    EncryptedCoin<FIELD> encCoin2;
    ss >> encCoin2;

    const Coin<FIELD> recvCoin = encCoin2.decrypt(sk, pk);
    const bool good_recvCoin =
        recvCoin.valid() &&
        recvCoin.addr().destHash() == coin.addr().destHash() &&
        recvCoin.rho() == coin.rho() &&
        recvCoin.r() == coin.r();
    cout << "received decrypted coin is "<< okStr(good_recvCoin) << endl << endl;

    const SecretSig<FIELD> ssk(oid);
    const string message = "abc";
    const auto signature = ssk(message);
    cout << "signature of " << message << ":" << endl;
    hexDump(signature);

    const PublicSig<FIELD> spk(ssk);
    const bool valid_spk = spk.valid();
    cout << "signature public key is " << okStr(valid_spk) << endl
         << "hash signature:" << endl;
    hexDump(hashSig(spk));
    const bool
        verify_spk = spk(signature, message),
        rndtrip_spk = rndtripOK(spk);
    cout << "verify returns " << okStr(verify_spk) << endl
         << "roundtrip is " << okStr(rndtrip_spk) << endl << endl;

    return
        rndtrip_sk &&
        rndtrip_pk &&
        rndtrip_coin &&
        good_recvCoin &&
        valid_spk &&
        verify_spk &&
        rndtrip_spk;
}

////////////////////////////////////////////////////////////////////////////////
// simple payment test (no contingency)
//
template <typename FIELD, typename PAIRING>
bool paymentTest(const CryptoPP::OID& oid, const size_t merkleDepth) {
    cout << "payment test" << endl;

    // addresses
    const AddrPair<FIELD>
        old_addr1(oid), old_addr2(oid),
        new_addr1(oid), new_addr2(oid);

    // check validity of addresses
    const bool addrOk =
        old_addr1.valid() && old_addr2.valid() &&
        new_addr1.valid() && new_addr2.valid();
    cout << "coin addresses: " << okStr(addrOk) << endl;
    if (!addrOk) return false;

    // coins
    Coin<FIELD>
        old_coin1(old_addr1), old_coin2(old_addr2),
        new_coin1(new_addr1), new_coin2(new_addr2);

    // payment amounts
    Int<PAIRING>
        old_amt1(old_coin1, 50), old_amt2(old_coin2, 50),
        new_amt1(new_coin1, 5), new_amt2(new_coin2, 94),
        pub_amt(1);

    // Merkle tree authentication paths
    MerkleBundle_SHA256<size_t> bundle(merkleDepth);
    const size_t
        path_idx1 = bundle.addLeaf(old_coin1.commitment_cm(), true),
        path_idx2 = bundle.addLeaf(old_coin2.commitment_cm(), true);

    //
    // proving side
    //

    // pour transaction
    ProvePour<FIELD> pourTX(oid, bundle.rootHash());
    pourTX.from(old_coin1, bundle.authPath()[path_idx1], old_addr1);
    pourTX.from(old_coin2, bundle.authPath()[path_idx2], old_addr2);
    pourTX.to(new_coin1);
    pourTX.to(new_coin2);

    { // zero knowledge proof
        reset<PAIRING>();

        // public amount
        pub_amt.bless();

        // cryptographic aspect
        PourZKP<PAIRING> proof(pourTX);

        // consistent amounts
        old_amt1.bless(proof.oldValue(0));
        old_amt2.bless(proof.oldValue(1));
        new_amt1.bless(proof.newValue(0));
        new_amt2.bless(proof.newValue(1));

        // conservation of money
        assert_true(*old_amt1 + *old_amt2 == *new_amt1 + *new_amt2 + *pub_amt);
    }

    // generate key pair and proof, then check verification
    cout << "variable count " << variable_count<PAIRING>() << endl;
    GenericProgressBar progress(cerr, 50);
    cerr << "generate key pair";
    const auto zkKey = keypair<PAIRING>(progress);
    cerr << endl;
    const auto zkInput = input<PAIRING>();
    cerr << "generate proof";
    const auto zkProof = proof(zkKey.pk(), progress);
    cerr << endl
         << "verify proof: " << okStr(verify(zkKey.vk(), zkInput, zkProof))
         << endl << endl;

    // sign proof
    pourTX.sign(zkProof, "Hello World!");

    stringstream ss;
    ss << pub_amt << pourTX;

    //
    // verification side
    //

    VerifyPour<FIELD> pourTX2;
    Int<PAIRING> pub_amt2;
    const bool inOk = pub_amt2.marshal_in(ss) && pourTX2.marshal_in(ss);
    cout << "demarshal payment: " << okStr(inOk) << endl;

    bool sigOk;

    { // zero knowledge proof
        reset<PAIRING>();

        // public amount
        pub_amt2.bless();

        // cryptographic aspect
        PourZKP<PAIRING> proof(pourTX2);

        sigOk = pourTX2.verifySignature(proof);
        cout << "verify signature: " << okStr(sigOk) << endl;
    }

    const bool proofOk = pourTX2.verifyProof(zkKey.vk());
    cout << "verify proof: " << okStr(proofOk) << endl;

    const bool snOk =
        old_coin1.serial_number(old_addr1) == pourTX2.serial_number()[0] &&
        old_coin2.serial_number(old_addr2) == pourTX2.serial_number()[1];
    cout << "verify serial numbers: " << okStr(snOk) << endl;

    const bool infoOk = ("Hello World!" == pourTX2.txInfo());
    cout << "verify transaction info: " << okStr(infoOk) << endl;

    const auto
        recv_coin1 = pourTX2.encryptedCoin()[0].decrypt(new_addr1),
        recv_coin2 = pourTX2.encryptedCoin()[1].decrypt(new_addr2);
    const bool recvOk = recv_coin1.valid() && recv_coin2.valid();
    cout << "verify receive coins: " << okStr(recvOk) << endl;

    size_t idx1 = 0, idx2 = 0;
    Int<PAIRING> recv_amt1(recv_coin1, idx1), recv_amt2(recv_coin2, idx2);
    const bool amtOk =
        new_amt1() == recv_amt1() &&
        new_amt2() == recv_amt2() &&
        pub_amt() == pub_amt2();
    cout << "verify amounts: " << okStr(amtOk) << endl << endl;

    return inOk && sigOk && proofOk && snOk && infoOk && recvOk && amtOk;
}

////////////////////////////////////////////////////////////////////////////////
// refund test (offsetting contingent payments with locking time and hash)
//
template <typename FIELD, typename PAIRING>
bool refundTestA(const CryptoPP::OID& oid, const size_t merkleDepth) {
    cout << "refund test A" << endl;

    // addresses
    const AddrPair<FIELD>
        old_addr1(oid), old_addr2(oid),
        new_addr1(oid), new_addr2(oid);

    // check validity of addresses
    const bool addrOk =
        old_addr1.valid() && old_addr2.valid() &&
        new_addr1.valid() && new_addr2.valid();
    cout << "coin addresses: " << okStr(addrOk) << endl;
    if (!addrOk) return false;

    // coins
    Coin<FIELD>
        old_coin1(old_addr1), old_coin2(old_addr2),
        new_coin1(new_addr1), new_coin2(new_addr2);

    // new_coin1 and refund_coin have same address
    auto refund_coin = new_coin1.refund();

    // payment amounts
    Int<PAIRING>
        old_amt1(old_coin1, 50), old_amt2(old_coin2, 50),
        new_amt1(new_coin1, 5), new_amt2(new_coin2, 94),
        refund_amt(refund_coin, 5),
        pub_amt(1);

    // locking hash digest
    const array<uint32_t, 16> lock_msg = random_array(lock_msg);
    HashDig<PAIRING> refund_lock(new_coin1, H(lock_msg));

    // locking time (refund maturity)
    const auto now = time(nullptr);
    Int<PAIRING> refund_time(refund_coin, now + 100);

    // Only the refund coin is locked. The unlocked coins are a
    // different type. A transaction can pour the locked refund coin
    // into an unlocked coin. This implies leaking information by the
    // various types of coins and transactions. The tradeoff between
    // performance and privacy is unavoidable. Fewer types of coin and
    // transactions (ideally just one) leaks the least information but
    // is inflexible and the most expensive.

    // Merkle tree authentication paths
    MerkleBundle_SHA256<size_t> bundle(merkleDepth);
    const size_t
        path_idx1 = bundle.addLeaf(old_coin1.commitment_cm(), true),
        path_idx2 = bundle.addLeaf(old_coin2.commitment_cm(), true);

    //
    // proving side
    //

    // pour transaction
    ProvePour<FIELD> pourTX(oid, bundle.rootHash());
    pourTX.from(old_coin1, bundle.authPath()[path_idx1], old_addr1);
    pourTX.from(old_coin2, bundle.authPath()[path_idx2], old_addr2);
    pourTX.to(new_coin1);
    pourTX.to(new_coin2);
    pourTX.to(refund_coin);

    { // zero knowledge proof
        reset<PAIRING>();

        // public inputs
        pub_amt.bless();

        // cryptographic aspect
        PourZKP<PAIRING> proof(pourTX);

        // consistency
        old_amt1.bless(proof.oldValue(0));
        old_amt2.bless(proof.oldValue(1));
        new_amt1.bless(proof.newValue(0));
        new_amt2.bless(proof.newValue(1));
        refund_amt.bless(proof.newValue(2));
        refund_lock.bless(proof.newValue(0)); // new coin 1 is hash locked
        refund_time.bless(proof.newValue(2)); // refund coin is time locked

        // conservation of money
        assert_true(*old_amt1 + *old_amt2 == *new_amt1 + *new_amt2 + *pub_amt);
        assert_true(*new_amt1 == *refund_amt);
    }

    // generate key pair and proof, then check verification
    cout << "variable count " << variable_count<PAIRING>() << endl;
    GenericProgressBar progress(cerr, 50);
    cerr << "generate key pair";
    const auto zkKey = keypair<PAIRING>(progress);
    cerr << endl;
    const auto zkInput = input<PAIRING>();
    cerr << "generate proof";
    const auto zkProof = proof(zkKey.pk(), progress);
    cerr << endl
         << "verify proof: " << okStr(verify(zkKey.vk(), zkInput, zkProof))
         << endl << endl;

    // sign proof
    pourTX.sign(zkProof, "Hello World!");

    stringstream ss;
    ss << pub_amt << pourTX;

    //
    // verification side
    //

    VerifyPour<FIELD> pourTX2;
    Int<PAIRING> pub_amt2;
    const bool inOk = pub_amt2.marshal_in(ss) && pourTX2.marshal_in(ss);
    cout << "demarshal payment: " << okStr(inOk) << endl;

    bool sigOk;

    { // zero knowledge proof
        reset<PAIRING>();

        // public amount
        pub_amt2.bless();

        // cryptographic aspect
        PourZKP<PAIRING> proof(pourTX2);

        sigOk = pourTX2.verifySignature(proof);
        cout << "verify signature: " << okStr(sigOk) << endl;
    }

    const bool proofOk = pourTX2.verifyProof(zkKey.vk());
    cout << "verify proof: " << okStr(proofOk) << endl;

    const bool infoOk = ("Hello World!" == pourTX2.txInfo());
    cout << "verify transaction info: " << okStr(infoOk) << endl;

    const auto
        recv_coin1 = pourTX2.encryptedCoin()[0].decrypt(new_addr1),
        recv_coin2 = pourTX2.encryptedCoin()[1].decrypt(new_addr2),
        recv_coin3 = pourTX2.encryptedCoin()[2].decrypt(new_addr1);
    const bool recvOk =
        recv_coin1.valid() &&
        recv_coin2.valid() &&
        recv_coin3.valid();
    cout << "verify receive coins: " << okStr(recvOk) << endl;

    const bool snOk =
        old_coin1.serial_number(old_addr1) == pourTX2.serial_number()[0] &&
        old_coin2.serial_number(old_addr2) == pourTX2.serial_number()[1] &&
        recv_coin3.serial_number(new_addr1) == recv_coin1.serial_number(new_addr1);
    cout << "verify serial numbers: " << okStr(snOk) << endl;

    size_t idx1 = 0, idx2 = 0, idx3 = 0;
    Int<PAIRING>
        recv_amt1(recv_coin1, idx1),
        recv_amt2(recv_coin2, idx2),
        recv_amt3(recv_coin3, idx3);
    const bool amtOk =
        new_amt1() == recv_amt1() &&
        new_amt2() == recv_amt2() &&
        refund_amt() == recv_amt3() &&
        pub_amt() == pub_amt2();
    cout << "verify amounts: " << okStr(amtOk) << endl << endl;

    return inOk && sigOk && proofOk && snOk && infoOk && recvOk && amtOk;
}

////////////////////////////////////////////////////////////////////////////////
// refund test (spend hash locked coin)
//
template <typename FIELD, typename PAIRING>
bool refundTestB(const CryptoPP::OID& oid, const size_t merkleDepth) {
    cout << "refund test B" << endl;

    // addresses
    const AddrPair<FIELD> old_addr(oid), new_addr(oid);

    // check validity of addresses
    const bool addrOk = old_addr.valid() && new_addr.valid();
    cout << "coin addresses: " << okStr(addrOk) << endl;
    if (!addrOk) return false;

    // coins
    Coin<FIELD> old_coin(old_addr), new_coin(new_addr);

    // payment amounts
    Int<PAIRING> old_amt(old_coin, 5), new_amt(new_coin, 4), pub_amt(1);

    // locking hash digest
    const array<uint32_t, 16> lock_msg = random_array(lock_msg);
    HashDig<PAIRING> refund_lock(old_coin, H(lock_msg));
    HashMsg<PAIRING> refund_key(lock_msg);

    // Merkle tree authentication paths
    MerkleBundle_SHA256<size_t> bundle(merkleDepth);
    const size_t path_idx = bundle.addLeaf(old_coin.commitment_cm(), true);

    //
    // proving side
    //

    // pour transaction
    ProvePour<FIELD> pourTX(oid, bundle.rootHash());
    pourTX.from(old_coin, bundle.authPath()[path_idx], old_addr);
    pourTX.to(new_coin);

    { // zero knowledge proof
        reset<PAIRING>();

        // public inputs
        pub_amt.bless();

        // cryptographic aspect
        PourZKP<PAIRING> proof(pourTX);

        // hidden witness
        refund_key.bless();

        // consistency
        old_amt.bless(proof.oldValue(0));
        new_amt.bless(proof.newValue(0));
        refund_lock.bless(proof.oldValue(0));

        // hash lock
        assert_true(*refund_lock == H(*refund_key));

        // conservation of money
        assert_true(*old_amt == *new_amt + *pub_amt);
    }

    // generate key pair and proof, then check verification
    cout << "variable count " << variable_count<PAIRING>() << endl;
    GenericProgressBar progress(cerr, 50);
    cerr << "generate key pair";
    const auto zkKey = keypair<PAIRING>(progress);
    cerr << endl;
    const auto zkInput = input<PAIRING>();
    cerr << "generate proof";
    const auto zkProof = proof(zkKey.pk(), progress);
    cerr << endl
         << "verify proof: " << okStr(verify(zkKey.vk(), zkInput, zkProof))
         << endl << endl;

    // sign proof
    pourTX.sign(zkProof, "Hello World!");

    stringstream ss;
    ss << pub_amt << pourTX;

    //
    // verification side
    //

    VerifyPour<FIELD> pourTX2;
    Int<PAIRING> pub_amt2;
    const bool inOk = pub_amt2.marshal_in(ss) && pourTX2.marshal_in(ss);
    cout << "demarshal payment: " << okStr(inOk) << endl;

    bool sigOk;

    { // zero knowledge proof
        reset<PAIRING>();

        // public amount
        pub_amt2.bless();

        // cryptographic aspect
        PourZKP<PAIRING> proof(pourTX2);

        sigOk = pourTX2.verifySignature(proof);
        cout << "verify signature: " << okStr(sigOk) << endl;
    }

    const bool proofOk = pourTX2.verifyProof(zkKey.vk());
    cout << "verify proof: " << okStr(proofOk) << endl;

    const bool infoOk = ("Hello World!" == pourTX2.txInfo());
    cout << "verify transaction info: " << okStr(infoOk) << endl;

    const auto recv_coin = pourTX2.encryptedCoin()[0].decrypt(new_addr);
    const bool recvOk = recv_coin.valid();
    cout << "verify receive coin: " << okStr(recvOk) << endl;

    const bool snOk = old_coin.serial_number(old_addr) == pourTX2.serial_number()[0];
    cout << "verify serial number: " << okStr(snOk) << endl;

    size_t idx = 0;
    Int<PAIRING> recv_amt(recv_coin, idx);
    const bool amtOk = new_amt() == recv_amt() && pub_amt() == pub_amt2();
    cout << "verify amounts: " << okStr(amtOk) << endl << endl;

    return inOk && sigOk && proofOk && snOk && infoOk && recvOk && amtOk;
}

////////////////////////////////////////////////////////////////////////////////
// refund test (spend time locked coin)
//
template <typename FIELD, typename PAIRING>
bool refundTestC(const CryptoPP::OID& oid, const size_t merkleDepth) {
    cout << "refund test C" << endl;

    // addresses
    const AddrPair<FIELD> old_addr(oid), new_addr(oid);

    // check validity of addresses
    const bool addrOk = old_addr.valid() && new_addr.valid();
    cout << "coin addresses: " << okStr(addrOk) << endl;
    if (!addrOk) return false;

    // coins
    Coin<FIELD> old_coin(old_addr), new_coin(new_addr);

    // payment amounts
    Int<PAIRING> old_amt(old_coin, 5), new_amt(new_coin, 4), pub_amt(1);

    // locking time (refund maturity)
    const auto now = time(nullptr);
    Int<PAIRING>
        refund_time(old_coin, now - 100),
        current_time(now),
        diff_time(100);

    // Merkle tree authentication paths
    MerkleBundle_SHA256<size_t> bundle(merkleDepth);
    const size_t path_idx = bundle.addLeaf(old_coin.commitment_cm(), true);

    //
    // proving side
    //

    // pour transaction
    ProvePour<FIELD> pourTX(oid, bundle.rootHash());
    pourTX.from(old_coin, bundle.authPath()[path_idx], old_addr);
    pourTX.to(new_coin);

    { // zero knowledge proof
        reset<PAIRING>();

        // public inputs
        pub_amt.bless();
        current_time.bless();

        // cryptographic aspect
        PourZKP<PAIRING> proof(pourTX);

        // hidden witness
        diff_time.bless();

        // consistency
        old_amt.bless(proof.oldValue(0));
        new_amt.bless(proof.newValue(0));
        refund_time.bless(proof.oldValue(0));

        // time lock
        assert_true(*refund_time + *diff_time == *current_time);

        // conservation of money
        assert_true(*old_amt == *new_amt + *pub_amt);
    }

    // generate key pair and proof, then check verification
    cout << "variable count " << variable_count<PAIRING>() << endl;
    GenericProgressBar progress(cerr, 50);
    cerr << "generate key pair";
    const auto zkKey = keypair<PAIRING>(progress);
    cerr << endl;
    const auto zkInput = input<PAIRING>();
    cerr << "generate proof";
    const auto zkProof = proof(zkKey.pk(), progress);
    cerr << endl
         << "verify proof: " << okStr(verify(zkKey.vk(), zkInput, zkProof))
         << endl << endl;

    // sign proof
    pourTX.sign(zkProof, "Hello World!");

    stringstream ss;
    ss << pub_amt << current_time << pourTX;

    //
    // verification side
    //

    VerifyPour<FIELD> pourTX2;
    Int<PAIRING> pub_amt2, current_time2;
    const bool inOk =
        pub_amt2.marshal_in(ss) &&
        current_time2.marshal_in(ss) &&
        pourTX2.marshal_in(ss);
    cout << "demarshal payment: " << okStr(inOk) << endl;

    bool sigOk;

    { // zero knowledge proof
        reset<PAIRING>();

        // public amount
        pub_amt2.bless();
        current_time2.bless();

        // cryptographic aspect
        PourZKP<PAIRING> proof(pourTX2);

        sigOk = pourTX2.verifySignature(proof);
        cout << "verify signature: " << okStr(sigOk) << endl;
    }

    const bool proofOk = pourTX2.verifyProof(zkKey.vk());
    cout << "verify proof: " << okStr(proofOk) << endl;

    const bool infoOk = ("Hello World!" == pourTX2.txInfo());
    cout << "verify transaction info: " << okStr(infoOk) << endl;

    const auto recv_coin = pourTX2.encryptedCoin()[0].decrypt(new_addr);
    const bool recvOk = recv_coin.valid();
    cout << "verify receive coin: " << okStr(recvOk) << endl;

    const bool snOk = old_coin.serial_number(old_addr) == pourTX2.serial_number()[0];
    cout << "verify serial number: " << okStr(snOk) << endl;

    size_t idx = 0;
    Int<PAIRING> recv_amt(recv_coin, idx);
    const bool amtOk = new_amt() == recv_amt() && pub_amt() == pub_amt2();
    cout << "verify amounts: " << okStr(amtOk) << endl << endl;

    return inOk && sigOk && proofOk && snOk && infoOk && recvOk && amtOk;
}

////////////////////////////////////////////////////////////////////////////////
// main
//
int main(int argc, char *argv[])
{
    Getopt cmdLine(argc, argv, "p", "d", "");
    if (!cmdLine || cmdLine.empty()) printUsage(argv[0]);

    const string pairing = cmdLine.getString('p');
    if (!validPairingName(pairing)) {
        cerr << "error: Elliptic curve pairing "
             << pairing
             << " is not BN128 or Edwards"
             << endl;
        exit(EXIT_FAILURE);
    }

    const size_t merkleDepth = cmdLine.getNumber('d');
    if (0 == merkleDepth || 64 < merkleDepth) {
        cerr << "error: Merkle tree authentication path length "
             << merkleDepth
             << " is not between 1 and 64 inclusive"
             << endl;
        exit(EXIT_FAILURE);
    }

    const auto oid = CryptoPP::ASN1::secp256k1();

    // basic tests
    const bool roundtripOk = roundtripTests<CryptoPP::ECP>(oid);

    bool paymentOk, refundA_Ok, refundB_Ok, refundC_Ok;
    if (pairingBN128(pairing)) {
        cout << "Barreto-Naehrig 128 bits" << endl
             << "Merkle tree depth is " << merkleDepth << endl << endl;

        init_BN128();

        // zero knowledge pour transaction
        paymentOk = paymentTest<CryptoPP::ECP, BN128_PAIRING>(oid, merkleDepth);
        refundA_Ok = refundTestA<CryptoPP::ECP, BN128_PAIRING>(oid, merkleDepth);
        refundB_Ok = refundTestB<CryptoPP::ECP, BN128_PAIRING>(oid, merkleDepth);
        refundC_Ok = refundTestC<CryptoPP::ECP, BN128_PAIRING>(oid, merkleDepth);

    } else if (pairingEdwards(pairing)) {
        cout << "Edwards 80 bits" << endl
             << "Merkle tree depth is " << merkleDepth << endl << endl;

        init_Edwards();

        // zero knowledge pour transaction
        paymentOk = paymentTest<CryptoPP::ECP, EDWARDS_PAIRING>(oid, merkleDepth);
        refundA_Ok = refundTestA<CryptoPP::ECP, EDWARDS_PAIRING>(oid, merkleDepth);
        refundB_Ok = refundTestB<CryptoPP::ECP, EDWARDS_PAIRING>(oid, merkleDepth);
        refundC_Ok = refundTestC<CryptoPP::ECP, EDWARDS_PAIRING>(oid, merkleDepth);
    }

    cout << "roundtrip tests: " << okStr(roundtripOk) << endl
         << "payment test: " << okStr(paymentOk) << endl
         << "refund test A: " << okStr(refundA_Ok) << endl
         << "refund test B: " << okStr(refundB_Ok) << endl
         << "refund test C: " << okStr(refundC_Ok) << endl;

    const bool allOk =
        roundtripOk &&
        paymentOk &&
        refundA_Ok &&
        refundB_Ok &&
        refundC_Ok;

    if (!allOk) {
        cerr << "FAIL" << endl;
        exit(EXIT_FAILURE);

    } else {
        cerr << "PASS" << endl;
        return EXIT_SUCCESS;
    }
}
