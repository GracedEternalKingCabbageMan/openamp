// Package rpc is a minimal JSON-RPC client for elementsd.
package rpc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

type Client struct {
	url    string
	user   string
	pass   string
	http   *http.Client
	nextID atomic.Uint64
}

// New creates a client. auth is "user:pass" or "cookie:<path>".
func New(url, auth string) (*Client, error) {
	c := &Client{url: url, http: &http.Client{Timeout: 60 * time.Second}}
	if cookie, ok := strings.CutPrefix(auth, "cookie:"); ok {
		data, err := os.ReadFile(cookie)
		if err != nil {
			return nil, fmt.Errorf("rpc cookie: %w", err)
		}
		auth = strings.TrimSpace(string(data))
	}
	user, pass, ok := strings.Cut(auth, ":")
	if !ok {
		return nil, fmt.Errorf("rpc auth must be user:pass or cookie:<path>")
	}
	c.user, c.pass = user, pass
	return c, nil
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message) }

// IsRPCError reports whether err is a node-side error with the given substring.
func IsRPCError(err error, substr string) bool {
	var re *rpcError
	if ok := asRPCError(err, &re); !ok {
		return false
	}
	return strings.Contains(re.Message, substr)
}

func asRPCError(err error, target **rpcError) bool {
	for err != nil {
		if re, ok := err.(*rpcError); ok {
			*target = re
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func (c *Client) Call(result any, method string, params ...any) error {
	if params == nil {
		params = []any{}
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "1.0", "id": c.nextID.Add(1), "method": method, "params": params,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", c.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.user, c.pass)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("rpc %s: %w", method, err)
	}
	defer resp.Body.Close()
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("rpc %s: decode: %w (http %d)", method, err, resp.StatusCode)
	}
	if envelope.Error != nil {
		return fmt.Errorf("rpc %s: %w", method, envelope.Error)
	}
	if result != nil {
		if err := json.Unmarshal(envelope.Result, result); err != nil {
			return fmt.Errorf("rpc %s: result: %w", method, err)
		}
	}
	return nil
}

// --- typed helpers ---------------------------------------------------------

type TxOutResult struct {
	Confirmations int64   `json:"confirmations"`
	Value         float64 `json:"value"`
	Asset         string  `json:"asset"`
	ScriptPubKey  struct {
		Hex string `json:"hex"`
	} `json:"scriptPubKey"`
}

func (c *Client) GetTxOut(txid string, vout uint32, includeMempool bool) (*TxOutResult, error) {
	var res *TxOutResult
	if err := c.Call(&res, "gettxout", txid, vout, includeMempool); err != nil {
		return nil, err
	}
	return res, nil // nil result = spent/unknown
}

func (c *Client) GetBlockCount() (int64, error) {
	var n int64
	err := c.Call(&n, "getblockcount")
	return n, err
}

func (c *Client) GetBlockHash(height int64) (string, error) {
	var h string
	err := c.Call(&h, "getblockhash", height)
	return h, err
}

func (c *Client) GetBestBlockHash() (string, error) {
	var h string
	err := c.Call(&h, "getbestblockhash")
	return h, err
}

func (c *Client) SendRawTransaction(hexTx string) (string, error) {
	var txid string
	err := c.Call(&txid, "sendrawtransaction", hexTx)
	return txid, err
}

func (c *Client) TestMempoolAccept(hexTx string) (bool, string, error) {
	var res []struct {
		Allowed      bool   `json:"allowed"`
		RejectReason string `json:"reject-reason"`
	}
	if err := c.Call(&res, "testmempoolaccept", []string{hexTx}); err != nil {
		return false, "", err
	}
	if len(res) != 1 {
		return false, "", fmt.Errorf("testmempoolaccept: unexpected result")
	}
	return res[0].Allowed, res[0].RejectReason, nil
}

type SignRawResult struct {
	Hex      string `json:"hex"`
	Complete bool   `json:"complete"`
}

func (c *Client) SignRawTransactionWithWallet(hexTx string) (*SignRawResult, error) {
	var res SignRawResult
	err := c.Call(&res, "signrawtransactionwithwallet", hexTx)
	return &res, err
}

type Unspent struct {
	TxID         string  `json:"txid"`
	Vout         uint32  `json:"vout"`
	Amount       float64 `json:"amount"`
	Asset        string  `json:"asset"`
	ScriptPubKey string  `json:"scriptPubKey"`
	Spendable    bool    `json:"spendable"`
}

func (c *Client) ListUnspent(minConf int, asset string) ([]Unspent, error) {
	var res []Unspent
	query := map[string]any{}
	if asset != "" {
		query["asset"] = asset
	}
	err := c.Call(&res, "listunspent", minConf, 9999999, []string{}, true, query)
	return res, err
}

func (c *Client) GetNewAddress() (string, error) {
	var addr string
	err := c.Call(&addr, "getnewaddress")
	return addr, err
}

type AddressInfo struct {
	Unconfidential string `json:"unconfidential"`
	ScriptPubKey   string `json:"scriptPubKey"`
}

func (c *Client) GetAddressInfo(addr string) (*AddressInfo, error) {
	var res AddressInfo
	err := c.Call(&res, "getaddressinfo", addr)
	return &res, err
}

// ScanTxOutSet scans the UTXO set for raw scriptPubKeys.
type ScanUnspent struct {
	TxID         string  `json:"txid"`
	Vout         uint32  `json:"vout"`
	ScriptPubKey string  `json:"scriptPubKey"`
	Amount       float64 `json:"amount"`
	Asset        string  `json:"asset"`
	Height       int64   `json:"height"`
}

func (c *Client) ScanTxOutSet(spks []string) ([]ScanUnspent, error) {
	descs := make([]string, len(spks))
	for i, s := range spks {
		descs[i] = "raw(" + s + ")"
	}
	var res struct {
		Success  bool          `json:"success"`
		Unspents []ScanUnspent `json:"unspents"`
	}
	if err := c.Call(&res, "scantxoutset", "start", descs); err != nil {
		return nil, err
	}
	if !res.Success {
		return nil, fmt.Errorf("scantxoutset failed")
	}
	return res.Unspents, nil
}
