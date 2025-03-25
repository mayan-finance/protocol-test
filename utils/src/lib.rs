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
        primitives::{Address, FixedBytes, U256},
        providers::{
            fillers::{
                BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
                WalletFiller,
            },
            ProviderBuilder, RootProvider,
        },
        signers::local::PrivateKeySigner,
        sol,
    };

    pub type Provider<'a> = FillProvider<
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
    ) -> anyhow::Result<Provider<'a>> {
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .on_http(rpc_url.parse()?);
        Ok(provider)
    }

    pub async fn increase_allowence<'a>(
        provider: &Provider<'a>,
        token_address: Address,
        spender: Address,
        amount: U256,
    ) -> anyhow::Result<FixedBytes<32>> {
        let token = IERC20::new(token_address, provider);

        let tx = token.approve(spender, amount).send().await?;
        let receipt = tx.watch().await?;
        Ok(receipt)
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
}
