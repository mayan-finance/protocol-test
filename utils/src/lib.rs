pub use alloy;
pub use anyhow;
pub use tokio;

pub mod web3 {
    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        IERC20,
        "../assets/IERC20.json"
    );

    use std::str::FromStr;

    use alloy::{
        network::EthereumWallet,
        primitives::{Address, FixedBytes, TxHash, U256},
        providers::{
            fillers::{
                BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
                WalletFiller,
            }, Provider, ProviderBuilder, RootProvider
        },
        signers::local::PrivateKeySigner,
        sol,
    };

    pub type Web3Provider<'a> = FillProvider<
        JoinFill<
            JoinFill<
                alloy::providers::Identity,
                JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
            >,
            WalletFiller<&'a EthereumWallet>,
        >,
        RootProvider,
    >;

    pub fn get_wallet() -> anyhow::Result<(Address, EthereumWallet)> {
        let signer = PrivateKeySigner::from_str(&std::env::var("PRIVATE_KEY")?)?;
        let address = signer.address();
        let wallet = EthereumWallet::from(signer);
        Ok((address, wallet))
    }

    pub fn get_provider<'a, 'b>(
        wallet: &'a EthereumWallet,
        rpc_url: &'b str,
    ) -> anyhow::Result<Web3Provider<'a>> {
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .on_http(rpc_url.parse()?);
        Ok(provider)
    }

    pub async fn increase_allowence<'a>(
        provider: &Web3Provider<'a>,
        token_address: Address,
        spender: Address,
        amount: U256,
        timeout_seconds: u64,
    ) -> anyhow::Result<FixedBytes<32>> {
        let token = IERC20::new(token_address, provider.clone());

        let tx = token.approve(spender, amount).send().await?;
        let hash = tx.tx_hash();
        let tx_hash = TxHash::from_str(&tx.tx_hash().to_string())?;
        let start_time = std::time::Instant::now();

        let mut sleep_time = 1;
        loop {
            let receipt = provider.get_transaction_receipt(tx_hash).await?;
            if receipt.is_some() {
                return Ok(hash.clone());
            }
            if start_time.elapsed() > std::time::Duration::from_secs(timeout_seconds) {
                return Err(anyhow::anyhow!("Timeout"));
            }

            tokio::time::sleep(std::time::Duration::from_secs(sleep_time)).await;
            sleep_time *= 2;

            if sleep_time > 60 {
                sleep_time = 60;
            }
        }
    }
}

pub mod circle {
    use alloy::primitives::Bytes;
    use serde::Deserialize;

    #[derive(Debug, Clone, Deserialize)]
    pub struct CircleMessageV2 {
        pub attestation: Option<Bytes>,
        pub message: Option<Bytes>,
        pub event_nonce: Option<String>,
        pub cctp_version: Option<u8>,
        pub status: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct CircleMessageV2Response {
        pub messages: Option<Vec<CircleMessageV2>>,
        pub error: Option<String>,
    }

    pub async fn get_circle_message_v2(
        domain_id: u64,
        transaction_hash: String,
        timeout_seconds: u64,
    ) -> anyhow::Result<CircleMessageV2> {
        let start_time = std::time::Instant::now();
        let mut sleep_time = 1;
        loop {
            let circle_message_v2 =
                match _get_circle_message_v2(domain_id, transaction_hash.clone()).await {
                    Ok(circle_message_v2) => circle_message_v2,
                    Err(e) => {
                        println!("Error: {:?}", e);
                        tokio::time::sleep(std::time::Duration::from_secs(sleep_time)).await;
                        sleep_time *= 2;
                        continue;
                    }
                };
            if circle_message_v2.status == "complete" {
                return Ok(circle_message_v2);
            }
            if start_time.elapsed() > std::time::Duration::from_secs(timeout_seconds) {
                return Err(anyhow::anyhow!("Timeout"));
            }
            tokio::time::sleep(std::time::Duration::from_secs(sleep_time)).await;
            sleep_time *= 2;

            if sleep_time > 60 {
                sleep_time = 60;
            }
        }
    }

    async fn _get_circle_message_v2(
        domain_id: u64,
        transaction_hash: String,
    ) -> anyhow::Result<CircleMessageV2> {
        let url = format!(
            "https://iris-api.circle.com/v2/messages/{}?transactionHash={}",
            domain_id, transaction_hash
        );
        let response = reqwest::get(url).await?;
        let body = response.text().await?;
        let circle_message_v2_response: CircleMessageV2Response = serde_json::from_str(&body)?;
        if circle_message_v2_response.error.is_some() {
            return Err(anyhow::anyhow!(
                "Error: {:?}",
                circle_message_v2_response.error
            ));
        }
        Ok(circle_message_v2_response.messages.unwrap()[0].clone())
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct CircleMessageV1 {
        pub attestation: Option<Bytes>,
        pub message: Option<Bytes>,
        pub event_nonce: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct CircleMessageV1Response {
        pub messages: Option<Vec<CircleMessageV1>>,
        pub error: Option<String>,
    }

    pub async fn get_circle_message_v1(
        domain_id: u64,
        transaction_hash: String,
        timeout_seconds: u64,
    ) -> anyhow::Result<CircleMessageV1> {
        let start_time = std::time::Instant::now();
        let mut sleep_time = 1;
        loop {
            let circle_message_v1 = match _get_circle_message_v1(domain_id, transaction_hash.clone()).await {
                Ok(circle_message_v1) => circle_message_v1,
                Err(e) => {
                    println!("Error: {:?}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(sleep_time)).await;
                    sleep_time *= 2;
                    continue;
                }
            };
            let attestation_to_string = match circle_message_v1.attestation.clone() {
                Some(attestation) => attestation.to_string(),
                None => continue,
            };
            if attestation_to_string != "PENDING" && attestation_to_string.starts_with("0x") {
                return Ok(circle_message_v1);
            }
            if start_time.elapsed() > std::time::Duration::from_secs(timeout_seconds) {
                return Err(anyhow::anyhow!("Timeout"));
            }
            tokio::time::sleep(std::time::Duration::from_secs(sleep_time)).await;
            sleep_time *= 2;

            if sleep_time > 60 {
                sleep_time = 60;
            }
        }
    }

    async fn _get_circle_message_v1(
        domain_id: u64,
        transaction_hash: String,
    ) -> anyhow::Result<CircleMessageV1> {
        let url = format!(
            "https://iris-api.circle.com/v1/messages/{}/{}",
            domain_id, transaction_hash
        );
        let response = reqwest::get(url).await?;
        let body = response.text().await?;
        if body.contains("PENDING") {
            return Err(anyhow::anyhow!("Pending"));
        }
        let circle_message_v1_response: CircleMessageV1Response = serde_json::from_str(&body)?;
        if circle_message_v1_response.error.is_some() {
            return Err(anyhow::anyhow!(
                "Error: {:?}",
                circle_message_v1_response.error
            ));
        }
        Ok(circle_message_v1_response.messages.unwrap()[0].clone())
    }
}

pub mod wormhole {
    use alloy::primitives::Bytes;
    use serde::Deserialize;

    #[derive(Debug, Clone, Deserialize)]
    pub struct WormholeVaaResponse {
        pub data: Vec<WormholeVaa>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct WormholeVaaSequenceResponse {
        pub data: WormholeVaa,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct WormholeVaa {
        pub vaa: Option<String>, // base64 encoded

        #[serde(rename = "txHash")]
        pub tx_hash: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    struct Sequence {
        pub sequence: u64,
    }

    #[derive(Debug, Clone, Deserialize)]
    struct SequenceResponse {
        pub data: Vec<Sequence>,
    }

    pub async fn get_latest_sequence(domain_id: u64, emitter_address: String) -> anyhow::Result<u64> {
        let url = format!(
            "https://api.wormholescan.io/api/v1/vaas/{}/{}/",
            domain_id, emitter_address
        );
        let response = reqwest::get(url).await?;
        let body = response.text().await?;
        let sequence_response: SequenceResponse = serde_json::from_str(&body)?;
        if sequence_response.data.is_empty() {
            return Err(anyhow::anyhow!("No sequences found"));
        }
        Ok(sequence_response.data[0].sequence)
    }

    pub async fn get_vaa_by_sequence(domain_id: u64, emitter_address: String, sequence: u64) -> anyhow::Result<(Bytes, String)> {
        let url = format!(
            "https://api.wormholescan.io/api/v1/vaas/{}/{}/{}/",
            domain_id, emitter_address, sequence
        );
        let response = reqwest::get(url).await?;
        let body = response.text().await?;
        let wormhole_vaa_sequence_response: WormholeVaaSequenceResponse = serde_json::from_str(&body)?;
        let vaa_base64 = match &wormhole_vaa_sequence_response.data.vaa {
            Some(vaa) => vaa,
            None => return Err(anyhow::anyhow!("Vaa is not returned")),
        };
        if vaa_base64.is_empty() {
            return Err(anyhow::anyhow!("Vaa is empty"));
        }
        let vaa = base64::decode(&vaa_base64)?;
        Ok((vaa.try_into()?, wormhole_vaa_sequence_response.data.tx_hash.clone()))
    }

    pub async fn get_vaa(tx_hash: String, timeout_seconds: u64) -> anyhow::Result<Bytes> {
        let start_time = std::time::Instant::now();
        let mut sleep_time = 1;
        loop {
            match _get_vaa(tx_hash.clone()).await {
                Ok(vaa) => return Ok(vaa),
                Err(e) => {
                    println!("Error: {:?}", e);
                }
            };
            if start_time.elapsed() > std::time::Duration::from_secs(timeout_seconds) {
                return Err(anyhow::anyhow!("Timeout"));
            }
            tokio::time::sleep(std::time::Duration::from_secs(sleep_time)).await;
            sleep_time *= 2;

            if sleep_time > 60 {
                sleep_time = 60;
            }
        }
    }

    async fn _get_vaa(tx_hash: String) -> anyhow::Result<Bytes> {
        let url = format!(
            "https://api.wormholescan.io/api/v1/vaas/?txHash={}",
            tx_hash
        );
        let response = reqwest::get(url).await?;
        let body = response.text().await?;
        let wormhole_vaa_response: WormholeVaaResponse = serde_json::from_str(&body)?;
        if wormhole_vaa_response.data.is_empty() {
            return Err(anyhow::anyhow!("No VAAs found"));
        }
        let vaa_base64 = match &wormhole_vaa_response.data[0].vaa {
            Some(vaa) => vaa,
            None => return Err(anyhow::anyhow!("Vaa is not returned")),
        };
        if vaa_base64.is_empty() {
            return Err(anyhow::anyhow!("Vaa is empty"));
        }
        let vaa = base64::decode(&vaa_base64)?;
        Ok(vaa.try_into()?)
    }
}