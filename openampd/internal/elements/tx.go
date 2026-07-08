// Package elements implements the minimum of the Elements transaction
// format and taproot signature hash needed by openampd: explicit
// (unblinded) assets and values end to end, confidential fields carried
// opaquely through the codec. Byte-exactness is enforced by golden vectors
// generated from the Sequentia functional-test framework (whose own
// correctness the M0 proof established against consensus).
package elements

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	OutpointIssuanceFlag = uint32(1) << 31
	OutpointPeginFlag    = uint32(1) << 30
	OutpointIndexMask    = uint32(0x3fffffff)
)

var ErrTruncated = errors.New("elements: truncated serialization")

// OutPoint hash is in internal (little-endian) byte order.
type OutPoint struct {
	Hash [32]byte
	N    uint32
}

func (o *OutPoint) IsNull() bool {
	return o.Hash == [32]byte{} && o.N == 0xffffffff
}

func (o *OutPoint) Serialize(w *bytes.Buffer) {
	w.Write(o.Hash[:])
	binary.Write(w, binary.LittleEndian, o.N)
}

// AssetIssuance mirrors CAssetIssuance including Sequentia's denomination.
type AssetIssuance struct {
	Nonce         [32]byte
	Entropy       [32]byte
	Amount        []byte // confidential value commitment bytes
	InflationKeys []byte
	Denomination  uint64 // compact-size on the wire; 8 by default
}

func (ai *AssetIssuance) IsNull() bool {
	return ai == nil || (isNullValue(ai.Amount) && isNullValue(ai.InflationKeys))
}

func (ai *AssetIssuance) Serialize(w *bytes.Buffer) {
	w.Write(ai.Nonce[:])
	w.Write(ai.Entropy[:])
	w.Write(ai.Amount)
	w.Write(ai.InflationKeys)
	writeCompactSize(w, ai.Denomination)
}

type TxIn struct {
	Prevout   OutPoint
	ScriptSig []byte
	Sequence  uint32
	IsPegin   bool
	Issuance  *AssetIssuance
}

type TxOut struct {
	Asset        []byte // 0x01+32 explicit, 0x0a/0x0b+32 confidential, 0x00 null
	Value        []byte // 0x01+8BE explicit, 0x08/0x09+32 confidential, 0x00 null
	Nonce        []byte
	ScriptPubKey []byte
}

func (o *TxOut) IsFee() bool {
	return len(o.ScriptPubKey) == 0 && len(o.Asset) == 33 && o.Asset[0] == 1 &&
		len(o.Value) == 9 && o.Value[0] == 1
}

func (o *TxOut) Serialize(w *bytes.Buffer) {
	w.Write(o.Asset)
	w.Write(o.Value)
	w.Write(o.Nonce)
	writeVarBytes(w, o.ScriptPubKey)
}

type TxInWitness struct {
	IssuanceAmountRangeproof []byte
	InflationKeysRangeproof  []byte
	ScriptWitness            [][]byte
	PeginWitness             [][]byte
}

func (wt *TxInWitness) IsNull() bool {
	return wt == nil || (len(wt.IssuanceAmountRangeproof) == 0 && len(wt.InflationKeysRangeproof) == 0 &&
		len(wt.ScriptWitness) == 0 && len(wt.PeginWitness) == 0)
}

func (wt *TxInWitness) Serialize(w *bytes.Buffer) {
	writeVarBytes(w, wt.IssuanceAmountRangeproof)
	writeVarBytes(w, wt.InflationKeysRangeproof)
	writeWitnessStack(w, wt.ScriptWitness)
	writeWitnessStack(w, wt.PeginWitness)
}

func (wt *TxInWitness) SerializeIssuanceProofs(w *bytes.Buffer) {
	writeVarBytes(w, wt.IssuanceAmountRangeproof)
	writeVarBytes(w, wt.InflationKeysRangeproof)
}

type TxOutWitness struct {
	Surjection []byte
	Rangeproof []byte
}

func (wt *TxOutWitness) IsNull() bool {
	return wt == nil || (len(wt.Surjection) == 0 && len(wt.Rangeproof) == 0)
}

func (wt *TxOutWitness) Serialize(w *bytes.Buffer) {
	writeVarBytes(w, wt.Surjection)
	writeVarBytes(w, wt.Rangeproof)
}

type Tx struct {
	Version  int32
	LockTime uint32
	In       []*TxIn
	Out      []*TxOut
	InWit    []*TxInWitness
	OutWit   []*TxOutWitness
}

// NormalizeWitness pads the witness vectors to the input/output counts, as
// the consensus representation always carries one (possibly empty) witness
// per input and output.
func (tx *Tx) NormalizeWitness() {
	for len(tx.InWit) < len(tx.In) {
		tx.InWit = append(tx.InWit, &TxInWitness{})
	}
	for len(tx.OutWit) < len(tx.Out) {
		tx.OutWit = append(tx.OutWit, &TxOutWitness{})
	}
}

func (tx *Tx) hasWitness() bool {
	for _, w := range tx.InWit {
		if !w.IsNull() {
			return true
		}
	}
	for _, w := range tx.OutWit {
		if !w.IsNull() {
			return true
		}
	}
	return false
}

func (tx *Tx) Serialize() []byte {
	var w bytes.Buffer
	binary.Write(&w, binary.LittleEndian, tx.Version)
	flags := byte(0)
	if tx.hasWitness() {
		flags = 1
	}
	w.WriteByte(flags)
	writeCompactSize(&w, uint64(len(tx.In)))
	for _, in := range tx.In {
		serializeTxIn(&w, in)
	}
	writeCompactSize(&w, uint64(len(tx.Out)))
	for _, out := range tx.Out {
		out.Serialize(&w)
	}
	binary.Write(&w, binary.LittleEndian, tx.LockTime)
	if flags&1 != 0 {
		tx.NormalizeWitness()
		for _, iw := range tx.InWit {
			iw.Serialize(&w)
		}
		for _, ow := range tx.OutWit {
			ow.Serialize(&w)
		}
	}
	return w.Bytes()
}

func serializeTxIn(w *bytes.Buffer, in *TxIn) {
	n := in.Prevout.N
	if n != 0xffffffff {
		if !in.Issuance.IsNull() {
			n |= OutpointIssuanceFlag
		}
		if in.IsPegin {
			n |= OutpointPeginFlag
		}
	}
	w.Write(in.Prevout.Hash[:])
	binary.Write(w, binary.LittleEndian, n)
	writeVarBytes(w, in.ScriptSig)
	binary.Write(w, binary.LittleEndian, in.Sequence)
	if n != 0xffffffff && n&OutpointIssuanceFlag != 0 {
		in.Issuance.Serialize(w)
	}
}

func DeserializeTx(raw []byte) (*Tx, error) {
	r := bytes.NewReader(raw)
	tx := &Tx{}
	if err := binary.Read(r, binary.LittleEndian, &tx.Version); err != nil {
		return nil, ErrTruncated
	}
	flags, err := r.ReadByte()
	if err != nil {
		return nil, ErrTruncated
	}
	nIn, err := readCompactSize(r)
	if err != nil {
		return nil, err
	}
	for i := uint64(0); i < nIn; i++ {
		in, err := deserializeTxIn(r)
		if err != nil {
			return nil, err
		}
		tx.In = append(tx.In, in)
	}
	nOut, err := readCompactSize(r)
	if err != nil {
		return nil, err
	}
	for i := uint64(0); i < nOut; i++ {
		out, err := DeserializeTxOut(r)
		if err != nil {
			return nil, err
		}
		tx.Out = append(tx.Out, out)
	}
	if err := binary.Read(r, binary.LittleEndian, &tx.LockTime); err != nil {
		return nil, ErrTruncated
	}
	if flags&1 != 0 {
		for i := uint64(0); i < nIn; i++ {
			iw := &TxInWitness{}
			if iw.IssuanceAmountRangeproof, err = readVarBytes(r); err != nil {
				return nil, err
			}
			if iw.InflationKeysRangeproof, err = readVarBytes(r); err != nil {
				return nil, err
			}
			if iw.ScriptWitness, err = readWitnessStack(r); err != nil {
				return nil, err
			}
			if iw.PeginWitness, err = readWitnessStack(r); err != nil {
				return nil, err
			}
			tx.InWit = append(tx.InWit, iw)
		}
		for i := uint64(0); i < nOut; i++ {
			ow := &TxOutWitness{}
			if ow.Surjection, err = readVarBytes(r); err != nil {
				return nil, err
			}
			if ow.Rangeproof, err = readVarBytes(r); err != nil {
				return nil, err
			}
			tx.OutWit = append(tx.OutWit, ow)
		}
	}
	if flags > 1 {
		return nil, fmt.Errorf("elements: unknown tx flags %#x", flags)
	}
	if r.Len() != 0 {
		return nil, fmt.Errorf("elements: %d trailing bytes", r.Len())
	}
	return tx, nil
}

func deserializeTxIn(r *bytes.Reader) (*TxIn, error) {
	in := &TxIn{}
	if _, err := io.ReadFull(r, in.Prevout.Hash[:]); err != nil {
		return nil, ErrTruncated
	}
	if err := binary.Read(r, binary.LittleEndian, &in.Prevout.N); err != nil {
		return nil, ErrTruncated
	}
	hasIssuance := false
	if !(in.Prevout.Hash == [32]byte{} && in.Prevout.N == 0xffffffff) {
		if in.Prevout.N&OutpointIssuanceFlag != 0 {
			hasIssuance = true
		}
		if in.Prevout.N&OutpointPeginFlag != 0 {
			in.IsPegin = true
		}
		in.Prevout.N &= OutpointIndexMask
	}
	var err error
	if in.ScriptSig, err = readVarBytes(r); err != nil {
		return nil, err
	}
	if err = binary.Read(r, binary.LittleEndian, &in.Sequence); err != nil {
		return nil, ErrTruncated
	}
	if hasIssuance {
		ai := &AssetIssuance{}
		if _, err := io.ReadFull(r, ai.Nonce[:]); err != nil {
			return nil, ErrTruncated
		}
		if _, err := io.ReadFull(r, ai.Entropy[:]); err != nil {
			return nil, ErrTruncated
		}
		if ai.Amount, err = readConfValue(r); err != nil {
			return nil, err
		}
		if ai.InflationKeys, err = readConfValue(r); err != nil {
			return nil, err
		}
		if ai.Denomination, err = readCompactSize(r); err != nil {
			return nil, err
		}
		in.Issuance = ai
	}
	return in, nil
}

func DeserializeTxOut(r *bytes.Reader) (*TxOut, error) {
	out := &TxOut{}
	var err error
	if out.Asset, err = readConfAsset(r); err != nil {
		return nil, err
	}
	if out.Value, err = readConfValue(r); err != nil {
		return nil, err
	}
	if out.Nonce, err = readConfNonce(r); err != nil {
		return nil, err
	}
	if out.ScriptPubKey, err = readVarBytes(r); err != nil {
		return nil, err
	}
	return out, nil
}

// --- confidential field codecs -------------------------------------------

func isNullValue(v []byte) bool {
	return len(v) == 0 || (len(v) == 1 && v[0] == 0)
}

func readConfValue(r *bytes.Reader) ([]byte, error) {
	version, err := r.ReadByte()
	if err != nil {
		return nil, ErrTruncated
	}
	switch version {
	case 0:
		return []byte{0}, nil
	case 1, 0xff:
		return readPrefixed(r, version, 8)
	case 8, 9:
		return readPrefixed(r, version, 32)
	default:
		return nil, fmt.Errorf("elements: invalid value prefix %#x", version)
	}
}

func readConfAsset(r *bytes.Reader) ([]byte, error) {
	version, err := r.ReadByte()
	if err != nil {
		return nil, ErrTruncated
	}
	switch version {
	case 0:
		return []byte{0}, nil
	case 1, 0xff, 0x0a, 0x0b:
		return readPrefixed(r, version, 32)
	default:
		return nil, fmt.Errorf("elements: invalid asset prefix %#x", version)
	}
}

func readConfNonce(r *bytes.Reader) ([]byte, error) {
	version, err := r.ReadByte()
	if err != nil {
		return nil, ErrTruncated
	}
	switch version {
	case 0:
		return []byte{0}, nil
	case 1, 0xff, 2, 3:
		return readPrefixed(r, version, 32)
	default:
		return nil, fmt.Errorf("elements: invalid nonce prefix %#x", version)
	}
}

func readPrefixed(r *bytes.Reader, version byte, n int) ([]byte, error) {
	buf := make([]byte, n+1)
	buf[0] = version
	if _, err := io.ReadFull(r, buf[1:]); err != nil {
		return nil, ErrTruncated
	}
	return buf, nil
}

// ExplicitValue encodes an explicit amount commitment (0x01 + 8 bytes BE).
func ExplicitValue(sats uint64) []byte {
	v := make([]byte, 9)
	v[0] = 1
	binary.BigEndian.PutUint64(v[1:], sats)
	return v
}

// ExplicitValueAmount decodes an explicit amount, false if confidential/null.
func ExplicitValueAmount(v []byte) (uint64, bool) {
	if len(v) != 9 || v[0] != 1 {
		return 0, false
	}
	return binary.BigEndian.Uint64(v[1:]), true
}

// ExplicitAsset encodes an explicit asset commitment from a display-order
// (RPC hex) asset id.
func ExplicitAsset(displayID [32]byte) []byte {
	a := make([]byte, 33)
	a[0] = 1
	for i := 0; i < 32; i++ {
		a[1+i] = displayID[31-i]
	}
	return a
}

func NullNonce() []byte { return []byte{0} }

// --- compact size / var bytes ---------------------------------------------

func writeCompactSize(w *bytes.Buffer, n uint64) {
	switch {
	case n < 253:
		w.WriteByte(byte(n))
	case n < 0x10000:
		w.WriteByte(253)
		binary.Write(w, binary.LittleEndian, uint16(n))
	case n < 0x100000000:
		w.WriteByte(254)
		binary.Write(w, binary.LittleEndian, uint32(n))
	default:
		w.WriteByte(255)
		binary.Write(w, binary.LittleEndian, n)
	}
}

func readCompactSize(r *bytes.Reader) (uint64, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, ErrTruncated
	}
	switch b {
	case 253:
		var v uint16
		err = binary.Read(r, binary.LittleEndian, &v)
		return uint64(v), err
	case 254:
		var v uint32
		err = binary.Read(r, binary.LittleEndian, &v)
		return uint64(v), err
	case 255:
		var v uint64
		err = binary.Read(r, binary.LittleEndian, &v)
		return v, err
	default:
		return uint64(b), nil
	}
}

func writeVarBytes(w *bytes.Buffer, b []byte) {
	writeCompactSize(w, uint64(len(b)))
	w.Write(b)
}

func readVarBytes(r *bytes.Reader) ([]byte, error) {
	n, err := readCompactSize(r)
	if err != nil {
		return nil, err
	}
	if n > uint64(r.Len()) {
		return nil, ErrTruncated
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, ErrTruncated
	}
	return buf, nil
}

func writeWitnessStack(w *bytes.Buffer, stack [][]byte) {
	writeCompactSize(w, uint64(len(stack)))
	for _, item := range stack {
		writeVarBytes(w, item)
	}
}

func readWitnessStack(r *bytes.Reader) ([][]byte, error) {
	n, err := readCompactSize(r)
	if err != nil {
		return nil, err
	}
	stack := make([][]byte, 0, min(n, 1024))
	for i := uint64(0); i < n; i++ {
		item, err := readVarBytes(r)
		if err != nil {
			return nil, err
		}
		stack = append(stack, item)
	}
	return stack, nil
}
