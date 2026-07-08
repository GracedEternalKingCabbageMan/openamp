package elements

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Sighash types.
const (
	SighashDefault      = 0x00
	SighashAll          = 0x01
	SighashNone         = 0x02
	SighashSingle       = 0x03
	SighashAnyoneCanPay = 0x80
)

// SpentOutput is the prevout data required by the taproot sighash.
type SpentOutput struct {
	Asset        []byte // commitment bytes (0x01+32 explicit)
	Value        []byte // commitment bytes (0x01+8BE explicit)
	ScriptPubKey []byte
}

// TaprootSighash computes the Elements taproot signature hash for a
// script-path spend of input `idx`, over leaf `script`. genesisHash is in
// internal byte order. Port of TaprootSignatureMsg from the Sequentia
// functional-test framework, explicit and ANYONECANPAY-free paths included.
func TaprootSighash(tx *Tx, spent []*SpentOutput, hashType byte, genesisHash [32]byte, idx int, script []byte) ([32]byte, error) {
	var out [32]byte
	if len(spent) != len(tx.In) {
		return out, fmt.Errorf("sighash: %d spent outputs for %d inputs", len(spent), len(tx.In))
	}
	if idx >= len(tx.In) {
		return out, fmt.Errorf("sighash: input %d out of range", idx)
	}
	outType := byte(SighashAll)
	if hashType != SighashDefault {
		outType = hashType & 3
	}
	inType := hashType & SighashAnyoneCanPay
	tx.NormalizeWitness()

	var ss bytes.Buffer
	ss.Write(genesisHash[:])
	ss.Write(genesisHash[:])
	ss.WriteByte(hashType)
	binary.Write(&ss, binary.LittleEndian, tx.Version)
	binary.Write(&ss, binary.LittleEndian, tx.LockTime)

	if inType != SighashAnyoneCanPay {
		var flagsBuf, prevoutsBuf, amountsBuf, spksBuf, seqBuf, issuanceBuf, proofsBuf bytes.Buffer
		for i, in := range tx.In {
			flagsBuf.WriteByte(outpointFlag(in))
			in.Prevout.Serialize(&prevoutsBuf)
			binary.Write(&seqBuf, binary.LittleEndian, in.Sequence)
			if in.Issuance.IsNull() {
				issuanceBuf.WriteByte(0x00)
			} else {
				in.Issuance.Serialize(&issuanceBuf)
			}
			tx.InWit[i].SerializeIssuanceProofs(&proofsBuf)
		}
		for _, u := range spent {
			amountsBuf.Write(u.Asset)
			amountsBuf.Write(u.Value)
			writeVarBytes(&spksBuf, u.ScriptPubKey)
		}
		writeSha(&ss, flagsBuf.Bytes())
		writeSha(&ss, prevoutsBuf.Bytes())
		writeSha(&ss, amountsBuf.Bytes())
		writeSha(&ss, spksBuf.Bytes())
		writeSha(&ss, seqBuf.Bytes())
		writeSha(&ss, issuanceBuf.Bytes())
		writeSha(&ss, proofsBuf.Bytes())
	}
	if outType == SighashAll {
		var outsBuf, outWitBuf bytes.Buffer
		for _, o := range tx.Out {
			o.Serialize(&outsBuf)
		}
		for _, ow := range tx.OutWit {
			ow.Serialize(&outWitBuf)
		}
		writeSha(&ss, outsBuf.Bytes())
		writeSha(&ss, outWitBuf.Bytes())
	}
	spendType := byte(2) // scriptpath, no annex
	ss.WriteByte(spendType)

	if inType == SighashAnyoneCanPay {
		in := tx.In[idx]
		ss.WriteByte(outpointFlag(in))
		in.Prevout.Serialize(&ss)
		ss.Write(spent[idx].Asset)
		ss.Write(spent[idx].Value)
		writeVarBytes(&ss, spent[idx].ScriptPubKey)
		binary.Write(&ss, binary.LittleEndian, in.Sequence)
		if in.Issuance.IsNull() {
			ss.WriteByte(0x00)
		} else {
			in.Issuance.Serialize(&ss)
			var proofs bytes.Buffer
			tx.InWit[idx].SerializeIssuanceProofs(&proofs)
			writeSha(&ss, proofs.Bytes())
		}
	} else {
		binary.Write(&ss, binary.LittleEndian, uint32(idx))
	}
	if outType == SighashSingle {
		if idx < len(tx.Out) {
			var ob, owb bytes.Buffer
			tx.Out[idx].Serialize(&ob)
			tx.OutWit[idx].Serialize(&owb)
			writeSha(&ss, ob.Bytes())
			writeSha(&ss, owb.Bytes())
		} else {
			return out, fmt.Errorf("sighash single: no matching output for input %d", idx)
		}
	}
	// script path extension
	leafHash := TapLeafHash(script)
	ss.Write(leafHash[:])
	ss.WriteByte(0x00) // key version
	var codesep [4]byte
	binary.LittleEndian.PutUint32(codesep[:], 0xffffffff) // -1: no OP_CODESEPARATOR
	ss.Write(codesep[:])

	return TaggedHash(TagTapSighash, ss.Bytes()), nil
}

func outpointFlag(in *TxIn) byte {
	var f byte
	if !in.Issuance.IsNull() {
		f |= 1 << 7
	}
	if in.IsPegin {
		f |= 1 << 6
	}
	return f
}

func writeSha(w *bytes.Buffer, b []byte) {
	h := sha256.Sum256(b)
	w.Write(h[:])
}
