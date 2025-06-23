// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

use super::bitcoin;
use super::json;
use serde_json;

use crate::client::Result;
use crate::client::RpcApi;
use async_trait::async_trait;

/// A type that can be queried from Bitcoin Core.
#[async_trait]
pub trait Queryable<C: RpcApi>: Sized + Send + Sync {
    /// Type of the ID used to query the item.
    type Id;
    /// Query the item using `rpc` and convert to `Self`.
    async fn query(rpc: &C, id: &Self::Id) -> Result<Self>;
}

#[async_trait]
impl<C: RpcApi + std::marker::Sync> Queryable<C> for bitcoin::blockdata::block::Block {
    type Id = bitcoin::BlockHash;

    async fn query(rpc: &C, id: &Self::Id) -> Result<Self> {
        let rpc_name = "getblock";
        let hex: String = rpc.call(rpc_name, &[serde_json::to_value(id)?, 0.into()]).await?;
        let bytes: Vec<u8> = bitcoin::hashes::hex::FromHex::from_hex(&hex)?;
        Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
    }
}

#[async_trait]
impl<C: RpcApi + std::marker::Sync> Queryable<C> for bitcoin::blockdata::transaction::Transaction {
    type Id = bitcoin::Txid;

    async fn query(rpc: &C, id: &Self::Id) -> Result<Self> {
        let rpc_name = "getrawtransaction";
        let hex: String = rpc.call(rpc_name, &[serde_json::to_value(id)?]).await?;
        let bytes: Vec<u8> = bitcoin::hashes::hex::FromHex::from_hex(&hex)?;
        Ok(bitcoin::consensus::encode::deserialize(&bytes)?)
    }
}

#[async_trait]
impl<C: RpcApi + std::marker::Sync> Queryable<C> for Option<json::GetTxOut> {
    type Id = bitcoin::OutPoint;

    async fn query(rpc: &C, id: &Self::Id) -> Result<Self> {
        rpc.get_tx_out(&id.txid, id.vout, Some(true)).await
    }
}
