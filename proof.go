package pproof

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/ltcmweb/ltcd/chaincfg"
	"github.com/ltcmweb/ltcd/chaincfg/chainhash"
	"github.com/ltcmweb/ltcd/ltcutil"
	"github.com/ltcmweb/ltcd/ltcutil/mweb"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/ltcd/wire"
	"lukechampine.com/blake3"
)

type PaymentProof struct {
	Output    []byte
	OutputId  string
	Address   string
	Value     uint64
	Nonce     [16]byte
	Signature mw.Signature
}

func MakeProof(address string, value uint64, senderKey *mw.SecretKey,
	rangeProofHash chainhash.Hash) (*PaymentProof, error) {

	addr, err := ltcutil.DecodeAddress(address, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	recipient := &mweb.Recipient{
		Address: addr.(*ltcutil.AddressMweb).StealthAddress(),
		Value:   value,
	}

	output, _, _ := mweb.CreateOutput(recipient, senderKey)
	output.RangeProofHash = rangeProofHash

	h := blake3.New(32, nil)
	h.Write(output.Commitment[:])
	h.Write(output.SenderPubKey[:])
	h.Write(output.ReceiverPubKey[:])
	h.Write(output.Message.Hash()[:])
	h.Write(output.RangeProofHash[:])
	output.Signature = mw.Sign(senderKey, h.Sum(nil))

	var buf bytes.Buffer
	output.Serialize(&buf)

	nonce := mw.Hashed(mw.HashTagNonce, senderKey[:])[:16]

	return &PaymentProof{
		Output:    buf.Bytes(),
		OutputId:  hex.EncodeToString(output.Hash()[:]),
		Address:   address,
		Value:     value,
		Nonce:     [16]byte(nonce),
		Signature: mw.Sign(senderKey, nonce),
	}, nil
}

func (pp *PaymentProof) Verify() error {
	// Deserialize the output
	var output wire.MwebOutput
	err := output.Deserialize(bytes.NewReader(pp.Output))
	if err != nil {
		return err
	}

	// Verify the output id
	if hex.EncodeToString(output.Hash()[:]) != pp.OutputId {
		return errors.New("output id mismatch")
	}

	// Construct the stealth address
	addr, err := ltcutil.DecodeAddress(pp.Address, &chaincfg.MainNetParams)
	if err != nil {
		return err
	}
	sa := addr.(*ltcutil.AddressMweb).StealthAddress()

	// Calculate the send key: s = HASH32(T_send||Ai||Bi||v||n)
	h := blake3.New(32, nil)
	binary.Write(h, binary.LittleEndian, mw.HashTagSendKey)
	h.Write(sa.A()[:])
	h.Write(sa.B()[:])
	binary.Write(h, binary.LittleEndian, pp.Value)
	h.Write(pp.Nonce[:])
	s := (*mw.SecretKey)(h.Sum(nil))

	// Calculate the shared secret: t = HASH32(T_derive||s*Ai)
	sA := sa.A().Mul(s)
	t := (*mw.SecretKey)(mw.Hashed(mw.HashTagDerive, sA[:]))

	// Verify the output's commitment: C ?= v*H + SWITCH(v, HASH32(T_blind||t))
	mask := mw.OutputMaskFromShared(t)
	blind := mw.BlindSwitch(mask.Blind, pp.Value)
	C := mw.NewCommitment(blind, pp.Value)
	if *C != output.Commitment {
		return errors.New("commitment mismatch")
	}

	// Verify the output's public key: Ko ?= Bi * HASH32(T_outkey||t)
	Ko := sa.B().Mul((*mw.SecretKey)(mw.Hashed(mw.HashTagOutKey, t[:])))
	if *Ko != output.ReceiverPubKey {
		return errors.New("receiver pubkey mismatch")
	}

	// Verify the output's key exchange public key: Ke ?= s*Bi
	Ke := sa.B().Mul(s)
	if *Ke != output.Message.KeyExchangePubKey {
		return errors.New("key exchange pubkey mismatch")
	}

	// Verify the encrypted value: v' ?= v ^ HASH8(T_vmask||t)
	mv := mask.MaskValue(pp.Value)
	if mv != output.Message.MaskedValue {
		return errors.New("masked value mismatch")
	}

	// Verify the encrypted nonce: n' ?= n ^ HASH8(T_nmask||t)
	mn := mask.MaskNonce(new(big.Int).SetBytes(pp.Nonce[:]))
	if mn.Cmp(&output.Message.MaskedNonce) != 0 {
		return errors.New("masked nonce mismatch")
	}

	// Verify the sender key signature
	if !pp.Signature.Verify(&output.SenderPubKey, pp.Nonce[:]) {
		return errors.New("sender key signature invalid")
	}

	return nil
}
