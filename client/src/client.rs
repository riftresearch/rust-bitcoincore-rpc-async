// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

// claude: you can access the rust-bitcoin crate via corepc_types::bitcoin
// claude: you can access the corepc-types for the rpc commands via corepc_types::v29
use corepc_types::bitcoin::address::NetworkUnchecked;
use corepc_types::bitcoin::block::Header;
use corepc_types::bitcoin::hex::DisplayHex;
use corepc_types::bitcoin::secp256k1::ecdsa::Signature;
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::iter::FromIterator;
use std::path::PathBuf;
use std::{fmt, result};

use corepc_types::v29 as json;
use jsonrpc_async as jsonrpc;
use serde::*;
use serde_json;

use async_trait::async_trait;
use corepc_types::bitcoin::hashes::hex::FromHex;
use corepc_types::bitcoin::{
    Address, Amount, Block, OutPoint, PrivateKey, PublicKey, Script, Transaction,
};
use log::Level::{Debug, Trace, Warn};
use log::{debug, log_enabled, trace};

use crate::error::*;
use crate::queryable;

/// Crate-specific Result type, shorthand for `std::result::Result` with our
/// crate-specific Error type;
pub type Result<T> = result::Result<T, Error>;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JsonOutPoint {
    pub txid: corepc_types::bitcoin::Txid,
    pub vout: u32,
}

impl From<OutPoint> for JsonOutPoint {
    fn from(o: OutPoint) -> JsonOutPoint {
        JsonOutPoint {
            txid: o.txid,
            vout: o.vout,
        }
    }
}

impl Into<OutPoint> for JsonOutPoint {
    fn into(self) -> OutPoint {
        OutPoint {
            txid: self.txid,
            vout: self.vout,
        }
    }
}

/// Shorthand for converting a variable into a serde_json::Value.
fn into_json<T>(val: T) -> Result<serde_json::Value>
where
    T: serde::ser::Serialize,
{
    Ok(serde_json::to_value(val)?)
}

/// Shorthand for converting an Option into an Option<serde_json::Value>.
fn opt_into_json<T>(opt: Option<T>) -> Result<serde_json::Value>
where
    T: serde::ser::Serialize,
{
    match opt {
        Some(val) => Ok(into_json(val)?),
        None => Ok(serde_json::Value::Null),
    }
}

/// Shorthand for `serde_json::Value::Null`.
fn null() -> serde_json::Value {
    serde_json::Value::Null
}

/// Shorthand for an empty serde_json::Value array.
fn empty_arr() -> serde_json::Value {
    serde_json::Value::Array(vec![])
}

/// Shorthand for an empty serde_json object.
fn empty_obj() -> serde_json::Value {
    serde_json::Value::Object(Default::default())
}

/// Handle default values in the argument list
///
/// Substitute `Value::Null`s with corresponding values from `defaults` table,
/// except when they are trailing, in which case just skip them altogether
/// in returned list.
///
/// Note, that `defaults` corresponds to the last elements of `args`.
///
/// ```norust
/// arg1 arg2 arg3 arg4
///           def1 def2
/// ```
///
/// Elements of `args` without corresponding `defaults` value, won't
/// be substituted, because they are required.
fn handle_defaults<'a, 'b>(
    args: &'a mut [serde_json::Value],
    defaults: &'b [serde_json::Value],
) -> &'a [serde_json::Value] {
    assert!(args.len() >= defaults.len());

    // Pass over the optional arguments in backwards order, filling in defaults after the first
    // non-null optional argument has been observed.
    let mut first_non_null_optional_idx = None;
    for i in 0..defaults.len() {
        let args_i = args.len() - 1 - i;
        let defaults_i = defaults.len() - 1 - i;
        if args[args_i] == serde_json::Value::Null {
            if first_non_null_optional_idx.is_some() {
                if defaults[defaults_i] == serde_json::Value::Null {
                    panic!("Missing `default` for argument idx {}", args_i);
                }
                args[args_i] = defaults[defaults_i].clone();
            }
        } else if first_non_null_optional_idx.is_none() {
            first_non_null_optional_idx = Some(args_i);
        }
    }

    let required_num = args.len() - defaults.len();

    if let Some(i) = first_non_null_optional_idx {
        &args[..i + 1]
    } else {
        &args[..required_num]
    }
}

/// Convert a possible-null result into an Option.
fn opt_result<T: for<'a> serde::de::Deserialize<'a>>(
    result: serde_json::Value,
) -> Result<Option<T>> {
    if result == serde_json::Value::Null {
        Ok(None)
    } else {
        Ok(serde_json::from_value(result)?)
    }
}

/// Used to pass raw txs into the API.
pub trait RawTx: Sized + Clone {
    fn raw_hex(self) -> String;
}

impl<'a> RawTx for &'a Transaction {
    fn raw_hex(self) -> String {
        corepc_types::bitcoin::consensus::encode::serialize(self).as_hex().to_string()
    }
}

impl<'a> RawTx for &'a [u8] {
    fn raw_hex(self) -> String {
        self.as_hex().to_string()
    }
}

impl<'a> RawTx for &'a Vec<u8> {
    fn raw_hex(self) -> String {
        self.as_hex().to_string()
    }
}

impl<'a> RawTx for &'a str {
    fn raw_hex(self) -> String {
        self.to_owned()
    }
}

impl RawTx for String {
    fn raw_hex(self) -> String {
        self
    }
}

/// The different authentication methods for the client.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum Auth {
    None,
    UserPass(String, String),
    CookieFile(PathBuf),
}

impl Auth {
    /// Convert into the arguments that jsonrpc::Client needs.
    fn get_user_pass(self) -> Result<Option<(String, String)>> {
        use std::io::Read;
        match self {
            Auth::None => Ok(None),
            Auth::UserPass(u, p) => Ok(Some((u, p))),
            Auth::CookieFile(path) => {
                let mut file = File::open(path)?;
                let mut contents = String::new();
                file.read_to_string(&mut contents)?;
                let mut split = contents.splitn(2, ":");
                let u = split.next().ok_or(Error::InvalidCookieFile)?.into();
                let p = split.next().ok_or(Error::InvalidCookieFile)?.into();
                Ok(Some((u, p)))
            }
        }
    }
}

#[async_trait]
pub trait RpcApi: Sized {
    /// Call a `cmd` rpc with given `args` list
    async fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T>;

    /// Query an object implementing `Querable` type
    async fn get_by_id<T: queryable::Queryable<Self>>(
        &self,
        id: &<T as queryable::Queryable<Self>>::Id,
    ) -> Result<T>
    where
        T: Sync + Send,
        <T as queryable::Queryable<Self>>::Id: Sync + Send,
    {
        T::query(&self, &id).await
    }

    async fn get_network_info(&self) -> Result<json::GetNetworkInfo> {
        self.call("getnetworkinfo", &[]).await
    }

    async fn version(&self) -> Result<usize> {
        #[derive(Deserialize)]
        struct Response {
            pub version: usize,
        }
        let res: Response = self.call("getnetworkinfo", &[]).await?;
        Ok(res.version)
    }

    async fn add_multisig_address_with_addresses(
        &self,
        nrequired: u32,
        addresses: &[Address<NetworkUnchecked>],
    ) -> Result<json::AddMultisigAddress> {
        self.call("addmultisigaddress", &[into_json(nrequired)?, into_json(addresses)?]).await
    }

    async fn load_wallet(&self, wallet: &str) -> Result<json::LoadWallet> {
        self.call("loadwallet", &[wallet.into()]).await
    }

    async fn unload_wallet(&self, wallet: Option<&str>) -> Result<()> {
        let mut args = [opt_into_json(wallet)?];
        self.call("unloadwallet", handle_defaults(&mut args, &[null()])).await
    }

    async fn create_wallet(
        &self,
        wallet: &str,
        disable_private_keys: Option<bool>,
        blank: Option<bool>,
        passphrase: Option<&str>,
        avoid_reuse: Option<bool>,
    ) -> Result<json::LoadWallet> {
        let mut args = [
            wallet.into(),
            opt_into_json(disable_private_keys)?,
            opt_into_json(blank)?,
            opt_into_json(passphrase)?,
            opt_into_json(avoid_reuse)?,
        ];
        self.call(
            "createwallet",
            handle_defaults(&mut args, &[false.into(), false.into(), into_json("")?, false.into()]),
        )
        .await
    }

    async fn list_wallets(&self) -> Result<Vec<String>> {
        self.call("listwallets", &[]).await
    }

    async fn get_wallet_info(&self) -> Result<json::GetWalletInfo> {
        self.call("getwalletinfo", &[]).await
    }

    async fn backup_wallet(&self, destination: Option<&str>) -> Result<()> {
        let mut args = [opt_into_json(destination)?];
        self.call("backupwallet", handle_defaults(&mut args, &[null()])).await
    }

    async fn dump_private_key(&self, address: &Address) -> Result<PrivateKey> {
        self.call("dumpprivkey", &[address.to_string().into()]).await
    }

    async fn encrypt_wallet(&self, passphrase: &str) -> Result<()> {
        self.call("encryptwallet", &[into_json(passphrase)?]).await
    }

    async fn get_difficulty(&self) -> Result<f64> {
        self.call("getdifficulty", &[]).await
    }

    async fn get_connection_count(&self) -> Result<usize> {
        self.call("getconnectioncount", &[]).await
    }

    async fn get_block(&self, hash: &corepc_types::bitcoin::BlockHash) -> Result<Block> {
        let hex: String = self.call("getblock", &[into_json(hash)?, 0.into()]).await?;
        let bytes: Vec<u8> = FromHex::from_hex(&hex)?;
        Ok(corepc_types::bitcoin::consensus::encode::deserialize(&bytes)?)
    }

    async fn get_block_hex(&self, hash: &corepc_types::bitcoin::BlockHash) -> Result<String> {
        self.call("getblock", &[into_json(hash)?, 0.into()]).await
    }

    async fn get_block_verbose_one(
        &self,
        hash: &corepc_types::bitcoin::BlockHash,
    ) -> Result<json::GetBlockVerboseOne> {
        self.call("getblock", &[into_json(hash)?, 1.into()]).await
    }
    //TODO(stevenroose) add getblock_txs

    async fn get_block_header(&self, hash: &corepc_types::bitcoin::BlockHash) -> Result<Header> {
        let hex: String = self.call("getblockheader", &[into_json(hash)?, false.into()]).await?;
        let bytes: Vec<u8> = FromHex::from_hex(&hex)?;
        Ok(corepc_types::bitcoin::consensus::encode::deserialize(&bytes)?)
    }

    async fn get_block_header_verbose(
        &self,
        hash: &corepc_types::bitcoin::BlockHash,
    ) -> Result<json::GetBlockHeaderVerbose> {
        self.call("getblockheader", &[into_json(hash)?, true.into()]).await
    }

    async fn get_mining_info(&self) -> Result<json::GetMiningInfo> {
        self.call("getmininginfo", &[]).await
    }

    /// Returns a data structure containing various state info regarding
    /// blockchain processing.
    async fn get_blockchain_info(&self) -> Result<json::GetBlockchainInfo> {
        self.call("getblockchaininfo", &[]).await
    }

    /// Returns the numbers of block in the longest chain.
    async fn get_block_count(&self) -> Result<u64> {
        self.call("getblockcount", &[]).await
    }

    /// Returns the hash of the best (tip) block in the longest blockchain.
    async fn get_best_block_hash(&self) -> Result<corepc_types::bitcoin::BlockHash> {
        self.call("getbestblockhash", &[]).await
    }

    /// Get block hash at a given height
    async fn get_block_hash(&self, height: u64) -> Result<corepc_types::bitcoin::BlockHash> {
        self.call("getblockhash", &[height.into()]).await
    }

    async fn get_raw_transaction(
        &self,
        txid: &corepc_types::bitcoin::Txid,
    ) -> Result<json::GetRawTransaction> {
        self.call("getrawtransaction", &[into_json(txid)?]).await
    }

    async fn get_raw_transaction_hex(
        &self,
        txid: &corepc_types::bitcoin::Txid,
        block_hash: Option<&corepc_types::bitcoin::BlockHash>,
    ) -> Result<String> {
        let mut args = [into_json(txid)?, into_json(false)?, opt_into_json(block_hash)?];
        self.call("getrawtransaction", handle_defaults(&mut args, &[null()])).await
    }

    async fn get_raw_transaction_verbose(
        &self,
        txid: &corepc_types::bitcoin::Txid,
    ) -> Result<json::GetRawTransactionVerbose> {
        self.call("getrawtransaction", &[into_json(txid)?, true.into()]).await
    }

    async fn get_block_filter(
        &self,
        block_hash: &corepc_types::bitcoin::BlockHash,
    ) -> Result<json::GetBlockFilter> {
        self.call("getblockfilter", &[into_json(block_hash)?]).await
    }

    async fn get_balance(
        &self,
        minconf: Option<usize>,
        include_watchonly: Option<bool>,
    ) -> Result<Amount> {
        let mut args = ["*".into(), opt_into_json(minconf)?, opt_into_json(include_watchonly)?];
        Ok(Amount::from_btc(
            self.call("getbalance", handle_defaults(&mut args, &[0.into(), null()])).await?,
        )?)
    }

    async fn get_balances(&self) -> Result<json::GetBalances> {
        Ok(self.call("getbalances", &[]).await?)
    }

    async fn get_received_by_address(
        &self,
        address: &Address,
        minconf: Option<u32>,
    ) -> Result<Amount> {
        let mut args = [address.to_string().into(), opt_into_json(minconf)?];
        Ok(Amount::from_btc(
            self.call("getreceivedbyaddress", handle_defaults(&mut args, &[null()])).await?,
        )?)
    }

    async fn get_transaction(
        &self,
        txid: &corepc_types::bitcoin::Txid,
        include_watchonly: Option<bool>,
    ) -> Result<json::GetTransaction> {
        let mut args = [into_json(txid)?, opt_into_json(include_watchonly)?];
        self.call("gettransaction", handle_defaults(&mut args, &[null()])).await
    }

    async fn list_transactions(
        &self,
        label: Option<&str>,
        count: Option<usize>,
        skip: Option<usize>,
        include_watchonly: Option<bool>,
    ) -> Result<Vec<json::ListTransactionsItem>> {
        let mut args = [
            label.unwrap_or("*").into(),
            opt_into_json(count)?,
            opt_into_json(skip)?,
            opt_into_json(include_watchonly)?,
        ];
        self.call("listtransactions", handle_defaults(&mut args, &[10.into(), 0.into(), null()]))
            .await
    }

    async fn list_since_block(
        &self,
        blockhash: Option<&corepc_types::bitcoin::BlockHash>,
        target_confirmations: Option<usize>,
        include_watchonly: Option<bool>,
        include_removed: Option<bool>,
    ) -> Result<json::ListSinceBlock> {
        let mut args = [
            opt_into_json(blockhash)?,
            opt_into_json(target_confirmations)?,
            opt_into_json(include_watchonly)?,
            opt_into_json(include_removed)?,
        ];
        self.call("listsinceblock", handle_defaults(&mut args, &[null()])).await
    }

    async fn get_tx_out(
        &self,
        txid: &corepc_types::bitcoin::Txid,
        vout: u32,
        include_mempool: Option<bool>,
    ) -> Result<Option<json::GetTxOut>> {
        let mut args = [into_json(txid)?, into_json(vout)?, opt_into_json(include_mempool)?];
        opt_result(self.call("gettxout", handle_defaults(&mut args, &[null()])).await?)
    }

    async fn get_tx_out_proof(
        &self,
        txids: &[corepc_types::bitcoin::Txid],
        block_hash: Option<&corepc_types::bitcoin::BlockHash>,
    ) -> Result<Vec<u8>> {
        let mut args = [into_json(txids)?, opt_into_json(block_hash)?];
        let hex: String = self.call("gettxoutproof", handle_defaults(&mut args, &[null()])).await?;
        Ok(FromHex::from_hex(&hex)?)
    }

    async fn import_public_key(
        &self,
        pubkey: &PublicKey,
        label: Option<&str>,
        rescan: Option<bool>,
    ) -> Result<()> {
        let mut args = [pubkey.to_string().into(), opt_into_json(label)?, opt_into_json(rescan)?];
        self.call("importpubkey", handle_defaults(&mut args, &[into_json("")?, null()])).await
    }

    async fn import_private_key(
        &self,
        privkey: &PrivateKey,
        label: Option<&str>,
        rescan: Option<bool>,
    ) -> Result<()> {
        let mut args = [privkey.to_string().into(), opt_into_json(label)?, opt_into_json(rescan)?];
        self.call("importprivkey", handle_defaults(&mut args, &[into_json("")?, null()])).await
    }

    async fn import_address(
        &self,
        address: &Address,
        label: Option<&str>,
        rescan: Option<bool>,
    ) -> Result<()> {
        let mut args = [address.to_string().into(), opt_into_json(label)?, opt_into_json(rescan)?];
        self.call("importaddress", handle_defaults(&mut args, &[into_json("")?, null()])).await
    }

    async fn import_address_script(
        &self,
        script: &Script,
        label: Option<&str>,
        rescan: Option<bool>,
        p2sh: Option<bool>,
    ) -> Result<()> {
        let mut args = [
            script.to_hex_string().into(),
            opt_into_json(label)?,
            opt_into_json(rescan)?,
            opt_into_json(p2sh)?,
        ];
        self.call(
            "importaddress",
            handle_defaults(&mut args, &[into_json("")?, true.into(), null()]),
        )
        .await
    }


    async fn set_label(&self, address: &Address, label: &str) -> Result<()> {
        self.call("setlabel", &[address.to_string().into(), label.into()]).await
    }

    async fn key_pool_refill(&self, new_size: Option<usize>) -> Result<()> {
        let mut args = [opt_into_json(new_size)?];
        self.call("keypoolrefill", handle_defaults(&mut args, &[null()])).await
    }

    async fn list_unspent(
        &self
    ) -> Result<Vec<json::ListUnspent>> {
        self.call("listunspent", &[]).await
    }

    /// To unlock, use [unlock_unspent].
    async fn lock_unspent(&self, outputs: &[OutPoint]) -> Result<bool> {
        let outputs: Vec<_> = outputs
            .into_iter()
            .map(|o| serde_json::to_value(JsonOutPoint::from(*o)).unwrap())
            .collect();
        self.call("lockunspent", &[false.into(), outputs.into()]).await
    }

    async fn unlock_unspent(&self, outputs: &[OutPoint]) -> Result<bool> {
        let outputs: Vec<_> = outputs
            .into_iter()
            .map(|o| serde_json::to_value(JsonOutPoint::from(*o)).unwrap())
            .collect();
        self.call("lockunspent", &[true.into(), outputs.into()]).await
    }

    async fn list_received_by_address(
        &self,
    ) -> Result<Vec<json::ListReceivedByAddress>> {
        self.call("listreceivedbyaddress", &[]).await
    }

    async fn create_raw_transaction_hex(
        &self,
        inputs: &[json::RawTransactionInput],
        outputs: &[json::RawTransactionOutput],
    ) -> Result<String> {
        let args = [
            into_json(inputs)?,
            into_json(outputs)?,
        ];
        self.call("createrawtransaction", &args).await
    }

    async fn create_raw_transaction(
        &self,
        inputs: &[json::RawTransactionInput],
        outputs: &[json::RawTransactionOutput],
    ) -> Result<Transaction> {
        let hex: String = self.create_raw_transaction_hex(inputs, outputs).await?;
        let bytes: Vec<u8> = FromHex::from_hex(&hex)?;
        Ok(corepc_types::bitcoin::consensus::encode::deserialize(&bytes)?)
    }

    async fn fund_raw_transaction<R: RawTx>(
        &self,
        tx: R,
    ) -> Result<json::FundRawTransaction>
    where
        R: Sync + Send,
    {
        let args = [tx.raw_hex().into()];
        self.call("fundrawtransaction", &args).await
    }


    async fn sign_raw_transaction_with_wallet<R: RawTx>(
        &self,
        tx: R,
    ) -> Result<json::SignRawTransaction>
    where
        R: Sync + Send,
    {
        let args = [tx.raw_hex().into()];
        self.call("signrawtransactionwithwallet", &args).await
    }

    async fn sign_raw_transaction_with_key<R: RawTx>(
        &self,
        tx: R,
        keys: &[PrivateKey],
    ) -> Result<json::SignRawTransaction>
    where
        R: Sync + Send,
    {
        let keys = keys.iter().map(|k| format!("{}", k)).collect::<Vec<String>>();

        let mut args = [
            tx.raw_hex().into(),
            into_json(keys)?,
        ];
        let defaults = [empty_arr(), null()];
        self.call("signrawtransactionwithkey", handle_defaults(&mut args, &defaults)).await
    }

    async fn test_mempool_accept<R: RawTx>(
        &self,
        rawtxs: &[R],
    ) -> Result<Vec<json::TestMempoolAccept>>
    where
        R: Sync + Send,
    {
        let hexes: Vec<serde_json::Value> =
            rawtxs.to_vec().into_iter().map(|r| r.raw_hex().into()).collect();
        self.call("testmempoolaccept", &[hexes.into()]).await
    }

    async fn stop(&self) -> Result<String> {
        self.call("stop", &[]).await
    }

    async fn verify_message(
        &self,
        address: &Address,
        signature: &Signature,
        message: &str,
    ) -> Result<bool> {
        let args = [address.to_string().into(), signature.to_string().into(), into_json(message)?];
        self.call("verifymessage", &args).await
    }

    /// Generate new address under own control
    async fn get_new_address(
        &self,
        label: Option<&str>,
        address_type: Option<corepc_types::bitcoin::AddressType>,
    ) -> Result<Address<NetworkUnchecked>> {
        match (label, address_type) {
            (Some(label), Some(ty)) =>
                self.call("getnewaddress", &[into_json(label)?, into_json(ty.to_string())?]).await,
            (Some(label), None) => self.call("getnewaddress", &[into_json(label)?]).await,
            (None, Some(ty)) => self.call("getnewaddress", &["".into(), into_json(ty.to_string())?]).await,
            (None, None) => self.call("getnewaddress", &[]).await,
        }
    }

    async fn get_address_info(&self, address: &Address) -> Result<json::GetAddressInfo> {
        self.call("getaddressinfo", &[address.to_string().into()]).await
    }

    /// Mine `block_num` blocks and pay coinbase to `address`
    ///
    /// Returns hashes of the generated blocks
    async fn generate_to_address(
        &self,
        block_num: u64,
        address: &Address,
    ) -> Result<Vec<corepc_types::bitcoin::BlockHash>> {
        self.call("generatetoaddress", &[block_num.into(), address.to_string().into()]).await
    }

    /// Mine up to block_num blocks immediately (before the RPC call returns)
    /// to an address in the wallet.
    async fn generate(
        &self,
        block_num: u64,
        maxtries: Option<u64>,
    ) -> Result<Vec<corepc_types::bitcoin::BlockHash>> {
        self.call("generate", &[block_num.into(), opt_into_json(maxtries)?]).await
    }

    /// Mark a block as invalid by `block_hash`
    async fn invalidate_block(&self, block_hash: &corepc_types::bitcoin::BlockHash) -> Result<()> {
        self.call("invalidateblock", &[into_json(block_hash)?]).await
    }

    /// Mark a block as valid by `block_hash`
    async fn reconsider_block(&self, block_hash: &corepc_types::bitcoin::BlockHash) -> Result<()> {
        self.call("reconsiderblock", &[into_json(block_hash)?]).await
    }

    /// Get txids of all transactions in a memory pool
    async fn get_raw_mempool(&self) -> Result<Vec<corepc_types::bitcoin::Txid>> {
        self.call("getrawmempool", &[]).await
    }

    /// Get mempool data for given transaction
    async fn get_mempool_entry(
        &self,
        txid: &corepc_types::bitcoin::Txid,
    ) -> Result<json::GetMempoolEntry> {
        self.call("getmempoolentry", &[into_json(txid)?]).await
    }

    async fn send_to_address(
        &self,
        address: &Address,
        amount: Amount,
    ) -> Result<json::SendToAddress> {
        self.call("sendtoaddress", &[address.to_string().into(), into_json(amount.to_btc())?]).await
    }

    /// Returns data about each connected network node as an array of
    /// [`PeerInfo`][]
    ///
    /// [`PeerInfo`]: net/struct.PeerInfo.html
    async fn get_peer_info(&self) -> Result<Vec<json::GetPeerInfo>> {
        self.call("getpeerinfo", &[]).await
    }

    /// Requests that a ping be sent to all other nodes, to measure ping
    /// time.
    ///
    /// Results provided in `getpeerinfo`, `pingtime` and `pingwait` fields
    /// are decimal seconds.
    ///
    /// Ping command is handled in queue with all other commands, so it
    /// measures processing backlog, not just network ping.
    async fn ping(&self) -> Result<()> {
        self.call("ping", &[]).await
    }

    async fn send_raw_transaction<R: RawTx>(&self, tx: R) -> Result<corepc_types::bitcoin::Txid>
    where
        R: Sync + Send,
    {
        self.call("sendrawtransaction", &[tx.raw_hex().into()]).await
    }

    async fn estimate_smart_fee(
        &self,
        blocks: u32,
    ) -> Result<json::EstimateSmartFee> {
        self.call("estimatesmartfee", &[into_json(blocks)?]).await
    }


    async fn wallet_create_funded_psbt(
        &self,
        inputs: &[json::WalletCreateFundedPsbt],
        outputs: &Vec<BTreeMap<Address, Amount>>,
    ) -> Result<json::WalletCreateFundedPsbt> {
        let args = [into_json(inputs)?, into_json(outputs)?];
        self.call("walletcreatefundedpsbt", &args).await
    }

    async fn get_descriptor_info(&self, desc: &str) -> Result<json::GetDescriptorInfo> {
        self.call("getdescriptorinfo", &[desc.to_string().into()]).await
    }

    async fn combine_psbt(&self, psbts: &[String]) -> Result<String> {
        self.call("combinepsbt", &[into_json(psbts)?]).await
    }

    async fn finalize_psbt(&self, psbt: &str, extract: Option<bool>) -> Result<json::FinalizePsbt> {
        let mut args = [into_json(psbt)?, opt_into_json(extract)?];
        self.call("finalizepsbt", handle_defaults(&mut args, &[true.into()])).await
    }

    async fn derive_addresses(
        &self,
        descriptor: &str,
        range: Option<[u32; 2]>,
    ) -> Result<Vec<Address<NetworkUnchecked>>> {
        let mut args = [into_json(descriptor)?, opt_into_json(range)?];
        self.call("deriveaddresses", handle_defaults(&mut args, &[null()])).await
    }

    async fn rescan_blockchain(
        &self,
        start_from: Option<usize>,
        stop_height: Option<usize>,
    ) -> Result<(usize, Option<usize>)> {
        let mut args = [opt_into_json(start_from)?, opt_into_json(stop_height)?];

        #[derive(Deserialize)]
        struct Response {
            pub start_height: usize,
            pub stop_height: Option<usize>,
        }
        let res: Response =
            self.call("rescanblockchain", handle_defaults(&mut args, &[0.into(), null()])).await?;
        Ok((res.start_height, res.stop_height))
    }

    /// Returns statistics about the unspent transaction output set.
    /// This call may take some time.
    async fn get_tx_out_set_info(&self) -> Result<json::GetTxOutSetInfo> {
        self.call("gettxoutsetinfo", &[]).await
    }

    /// Returns information about network traffic, including bytes in, bytes out,
    /// and current time.
    async fn get_net_totals(&self) -> Result<json::GetNetTotals> {
        self.call("getnettotals", &[]).await
    }

    /// Returns the estimated network hashes per second based on the last n blocks.
    async fn get_network_hash_ps(&self, nblocks: Option<u64>, height: Option<u64>) -> Result<f64> {
        let mut args = [opt_into_json(nblocks)?, opt_into_json(height)?];
        self.call("getnetworkhashps", handle_defaults(&mut args, &[null(), null()])).await
    }

    /// Returns the total uptime of the server in seconds
    async fn uptime(&self) -> Result<u64> {
        self.call("uptime", &[]).await
    }

}

/// Client implements a JSON-RPC client for the Bitcoin Core daemon or compatible APIs.
pub struct Client {
    client: jsonrpc::client::Client,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "bitcoincore_rpc::Client(jsonrpc::client::Client(last_nonce=?))",)
    }
}

impl Client {
    /// Creates a client to a bitcoind JSON-RPC server.
    ///
    /// Can only return [Err] when using cookie authentication.
    pub async fn new(url: String, auth: Auth) -> Result<Self> {
        let mut client = jsonrpc::simple_http::SimpleHttpTransport::builder()
            .url(&url)
            .await
            .map_err(|e| Error::JsonRpc(e.into()))?;
        if let Some((user, pass)) = auth.get_user_pass()? {
            client = client.auth(user, Some(pass));
        }

        Ok(Client {
            client: jsonrpc::client::Client::with_transport(client.build()),
        })
    }

    /// Create a new Client.
    pub fn from_jsonrpc(client: jsonrpc::client::Client) -> Client {
        Client {
            client: client,
        }
    }

    /// Get the underlying JSONRPC client.
    pub fn get_jsonrpc_client(&self) -> &jsonrpc::client::Client {
        &self.client
    }
}

#[async_trait]
impl RpcApi for Client {
    /// Call an `cmd` rpc with given `args` list
    async fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T> {
        let v_args: Vec<_> = args
            .iter()
            .map(serde_json::value::to_raw_value)
            .collect::<std::result::Result<_, serde_json::Error>>()?;
        let req = self.client.build_request(cmd, &v_args[..]);
        if log_enabled!(Debug) {
            debug!(target: "bitcoincore_rpc", "JSON-RPC request: {} {}", cmd, serde_json::Value::from(args));
        }

        let resp = self.client.send_request(req).await.map_err(Error::from);
        log_response(cmd, &resp);
        Ok(resp?.result()?)
    }
}

fn log_response(cmd: &str, resp: &Result<jsonrpc::Response>) {
    if log_enabled!(Warn) || log_enabled!(Debug) || log_enabled!(Trace) {
        match resp {
            Err(ref e) => {
                if log_enabled!(Debug) {
                    debug!(target: "bitcoincore_rpc", "JSON-RPC failed parsing reply of {}: {:?}", cmd, e);
                }
            }
            Ok(ref resp) => {
                if let Some(ref e) = resp.error {
                    if log_enabled!(Debug) {
                        debug!(target: "bitcoincore_rpc", "JSON-RPC error for {}: {:?}", cmd, e);
                    }
                } else if log_enabled!(Trace) {
                    let rawnull =
                        serde_json::value::to_raw_value(&serde_json::Value::Null).unwrap();
                    let result = resp.result.as_ref().unwrap_or(&rawnull);
                    trace!(target: "bitcoincore_rpc", "JSON-RPC response for {}: {}", cmd, result);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corepc_types::bitcoin;
    use serde_json;
    use tokio;

    #[tokio::test]
    async fn test_raw_tx() {
        use corepc_types::bitcoin::consensus::encode;
        let client = Client::new("http://localhost/".into(), Auth::None).await.unwrap();
        let tx: corepc_types::bitcoin::Transaction = encode::deserialize(&Vec::<u8>::from_hex("0200000001586bd02815cf5faabfec986a4e50d25dbee089bd2758621e61c5fab06c334af0000000006b483045022100e85425f6d7c589972ee061413bcf08dc8c8e589ce37b217535a42af924f0e4d602205c9ba9cb14ef15513c9d946fa1c4b797883e748e8c32171bdf6166583946e35c012103dae30a4d7870cd87b45dd53e6012f71318fdd059c1c2623b8cc73f8af287bb2dfeffffff021dc4260c010000001976a914f602e88b2b5901d8aab15ebe4a97cf92ec6e03b388ac00e1f505000000001976a914687ffeffe8cf4e4c038da46a9b1d37db385a472d88acfd211500").unwrap()).unwrap();

        assert!(client.send_raw_transaction(&tx).await.is_err());
        assert!(client.send_raw_transaction(&encode::serialize(&tx)).await.is_err());
        assert!(client.send_raw_transaction("deadbeef").await.is_err());
        assert!(client.send_raw_transaction("deadbeef".to_owned()).await.is_err());
    }

    fn test_handle_defaults_inner() -> Result<()> {
        {
            let mut args = [into_json(0)?, null(), null()];
            let defaults = [into_json(1)?, into_json(2)?];
            let res = [into_json(0)?];
            assert_eq!(handle_defaults(&mut args, &defaults), &res);
        }
        {
            let mut args = [into_json(0)?, into_json(1)?, null()];
            let defaults = [into_json(2)?];
            let res = [into_json(0)?, into_json(1)?];
            assert_eq!(handle_defaults(&mut args, &defaults), &res);
        }
        {
            let mut args = [into_json(0)?, null(), into_json(5)?];
            let defaults = [into_json(2)?, into_json(3)?];
            let res = [into_json(0)?, into_json(2)?, into_json(5)?];
            assert_eq!(handle_defaults(&mut args, &defaults), &res);
        }
        {
            let mut args = [into_json(0)?, null(), into_json(5)?, null()];
            let defaults = [into_json(2)?, into_json(3)?, into_json(4)?];
            let res = [into_json(0)?, into_json(2)?, into_json(5)?];
            assert_eq!(handle_defaults(&mut args, &defaults), &res);
        }
        {
            let mut args = [null(), null()];
            let defaults = [into_json(2)?, into_json(3)?];
            let res: [serde_json::Value; 0] = [];
            assert_eq!(handle_defaults(&mut args, &defaults), &res);
        }
        {
            let mut args = [null(), into_json(1)?];
            let defaults = [];
            let res = [null(), into_json(1)?];
            assert_eq!(handle_defaults(&mut args, &defaults), &res);
        }
        {
            let mut args = [];
            let defaults = [];
            let res: [serde_json::Value; 0] = [];
            assert_eq!(handle_defaults(&mut args, &defaults), &res);
        }
        {
            let mut args = [into_json(0)?];
            let defaults = [into_json(2)?];
            let res = [into_json(0)?];
            assert_eq!(handle_defaults(&mut args, &defaults), &res);
        }
        Ok(())
    }

    #[test]
    fn test_handle_defaults() {
        test_handle_defaults_inner().unwrap();
    }
}
