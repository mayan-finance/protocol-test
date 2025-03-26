use utils::{
    alloy::{
        hex::FromHex, primitives::{address, Bytes, FixedBytes, U256}, providers::Provider, sol
    },
    anyhow,
    circle::{get_circle_message_v1, get_circle_message_v2},
    tokio,
    wormhole::get_vaa,
};
use ZeroXHub::HubPayloadBridge;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IERC20,
    "../assets/IERC20.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    FastMCTP,
    "../assets/FastMCTP.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    MayanCircle,
    "../assets/MayanCircle.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    ZeroXHub,
    "../assets/ZeroXHub.json"
);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // fast_mctp_test(false).await?;
    mayan_circle_test(true).await?;
    Ok(())
}

async fn mayan_circle_test(rescue: bool) -> anyhow::Result<()> {
    let (address, wallet) = utils::web3::get_wallet()?;
    println!("Wallet Address: {}", address);
    let mut bytes_address = [0u8; 32];
    bytes_address[12..].copy_from_slice(address.as_slice());

    let base_provider = utils::web3::get_provider(&wallet, "https://base.llamarpc.com")?;
    let avalanche_provider = utils::web3::get_provider(&wallet, "https://avalanche.drpc.org")?;
    let arbitrum_provider = utils::web3::get_provider(&wallet, "https://arbitrum.llamarpc.com")?;
    let polygon_provider = utils::web3::get_provider(&wallet, "https://polygon.llamarpc.com")?;

    println!(
        "Base Latest Block: {:?}\nAvalanche Latest Block: {:?}\nArbitrum Latest Block: {:?}\nPolygon Latest Block: {:?}",
        base_provider.get_block_number().await?,
        avalanche_provider.get_block_number().await?,
        arbitrum_provider.get_block_number().await?,
        polygon_provider.get_block_number().await?
    );

    let hub_address = address!("0x4d88799EAf9c49dCe7470cD3932363DeA350C8D1");
    let mut bytes_hub_address = [0u8; 32];
    bytes_hub_address[12..].copy_from_slice(hub_address.as_slice());
    let hub = ZeroXHub::new(hub_address.clone(), avalanche_provider);

    let fast_mctp_address = hub.fastMCTP().call().await?._0;
    let mayan_circle_address = hub.mayanCircle().call().await?._0;

    println!("FastMCTP Address: {:?}", fast_mctp_address);
    println!("MayanCircle Address: {:?}", mayan_circle_address);

    let value_u64 = 100000;
    let value = U256::from(value_u64);
    // let arb_usdc_address = address!("0xaf88d065e77c8cC2239327C5EDb3A432268e5831");
    let pol_usdc_address = address!("0x3c499c542cef5e3811e1192ce70d8cc03d5c3359");
    let tx = utils::web3::increase_allowence(
        &polygon_provider,
        pol_usdc_address,
        mayan_circle_address,
        value,
    )
    .await?;
    println!("Increased allowance: {:?}", tx);

    let hub_payload = hub
        .encodeHubPayloadBridge(HubPayloadBridge {
            hubPayloadType: 1, // bridge
            hubRelayerFee: 150,
            sourceAddress: bytes_address.try_into()?,
            destAddress: bytes_address.try_into()?,
            destDomain: 6, // base
            gasDrop: 0,
            redeemFee: 0,
            referrerAddress: bytes_address.try_into()?,
            referrerBps: 3,
            circleMaxFee: 145,
            minFinalityThreshold: 0,
        })
        .call()
        .await?
        ._0;

    let mayan_circle = MayanCircle::new(mayan_circle_address, polygon_provider);
    let cctp_avalanche_domain_id = 1;

    let tx = mayan_circle
        .bridgeWithFee(
            pol_usdc_address.clone(),
            value,
            0,
            0,
            bytes_hub_address.try_into()?,
            cctp_avalanche_domain_id,
            2,
            hub_payload.clone(),
        )
        .send()
        .await?;

    let receipt = tx.watch().await?;
    println!("MayanCircle Bridge Receipt: {:?}", receipt);

    let vaa = get_vaa(receipt.to_string(), 60 * 60).await?;
    println!("Vaa: {:?}", vaa);

    let cctp_pol_domain_id = 7;
    let circle_message_v1 =
        get_circle_message_v1(cctp_pol_domain_id as u64, receipt.to_string(), 60 * 60).await?;
    println!("Circle Message V1: {:?}", circle_message_v1.attestation.clone().unwrap());

    let mut pol_usdc_address_bytes = [0u8; 32];
    pol_usdc_address_bytes[12..].copy_from_slice(pol_usdc_address.as_slice());

    if !rescue {
        let tx = hub
            .processMayanCircleIncoming(
                hub_payload,
                circle_message_v1.message.unwrap(),
                circle_message_v1.attestation.unwrap(),
                vaa,
                value_u64,
                pol_usdc_address_bytes.try_into()?,
            )
            .send()
            .await?;
        let receipt = tx.watch().await?;
        println!("Hub Process MayanCircleIncoming Receipt: {:?}", receipt);
    } else {
        let tx = hub
            .rescueMayanCircle(
                hub_payload,
                circle_message_v1.message.unwrap(),
                circle_message_v1.attestation.unwrap(),
                vaa,
                value_u64,
                pol_usdc_address_bytes.try_into()?,
                0,
            )
            .send()
            .await?;
        let receipt = tx.watch().await?;
        println!("Hub Rescue MayanCircle Receipt: {:?}", receipt);
    }

    Ok(())
}

async fn fast_mctp_test(rescue: bool) -> anyhow::Result<()> {
    let (address, wallet) = utils::web3::get_wallet()?;
    println!("Wallet Address: {}", address);
    let mut bytes_address = [0u8; 32];
    bytes_address[12..].copy_from_slice(address.as_slice());

    let base_provider = utils::web3::get_provider(&wallet, "https://base.llamarpc.com")?;
    let avalanche_provider = utils::web3::get_provider(&wallet, "https://avalanche.drpc.org")?;
    let arbitrum_provider = utils::web3::get_provider(&wallet, "https://arbitrum.llamarpc.com")?;

    println!(
        "Base Latest Block: {:?}\nAvalanche Latest Block: {:?}\nArbitrum Latest Block: {:?}",
        base_provider.get_block_number().await?,
        avalanche_provider.get_block_number().await?,
        arbitrum_provider.get_block_number().await?
    );

    let hub_address = address!("0x4d88799EAf9c49dCe7470cD3932363DeA350C8D1");
    let mut bytes_hub_address = [0u8; 32];
    bytes_hub_address[12..].copy_from_slice(hub_address.as_slice());
    let hub = ZeroXHub::new(hub_address, avalanche_provider);

    let fast_mctp_address = hub.fastMCTP().call().await?._0;
    let mayan_circle_address = hub.mayanCircle().call().await?._0;

    println!("FastMCTP Address: {:?}", fast_mctp_address);
    println!("MayanCircle Address: {:?}", mayan_circle_address);

    let hub_payload = hub
        .encodeHubPayloadBridge(HubPayloadBridge {
            hubPayloadType: 1, // bridge
            hubRelayerFee: 150,
            sourceAddress: bytes_address.try_into()?,
            destAddress: bytes_address.try_into()?,
            destDomain: 3, // arbitrum
            gasDrop: 0,
            redeemFee: 0,
            referrerAddress: bytes_address.try_into()?,
            referrerBps: 3,
            circleMaxFee: 145,
            minFinalityThreshold: 0,
        })
        .call()
        .await?
        ._0;

    let fast_mctp = FastMCTP::new(fast_mctp_address.clone(), base_provider.clone());

    let value = U256::from(100000);
    let base_usdc_address = address!("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
    let tx = utils::web3::increase_allowence(
        &base_provider,
        base_usdc_address,
        fast_mctp_address,
        value,
    )
    .await?;
    println!("Increased allowance: {:?}", tx);

    let cctp_avalanche_domain_id = 1;

    let tx = fast_mctp
        .bridge(
            base_usdc_address,
            value,
            0,
            U256::from(100),
            0,
            bytes_hub_address.try_into()?,
            cctp_avalanche_domain_id,
            bytes_address.try_into()?,
            2,
            2,
            0,
            hub_payload.clone(),
        )
        .send()
        .await?;

    let receipt = tx.watch().await?;
    println!("FastMCTP Bridge Receipt: {:?}", receipt);

    let circle_message_v2 = get_circle_message_v2(6, receipt.to_string(), 5 * 60).await?;
    println!(
        "Circle Message V2 Attestation: {:?}",
        circle_message_v2.attestation
    );

    if !rescue {
        let tx = hub
            .processFastMCTPIncoming(
                hub_payload,
                circle_message_v2.message.unwrap(),
                circle_message_v2.attestation.unwrap(),
            )
            .send()
            .await?;
        let receipt = tx.watch().await?;
        println!("Hub Process FastMCTPIncoming Receipt: {:?}", receipt);
    } else {
        let tx = hub
            .rescueFastMCTP(
                hub_payload,
                circle_message_v2.message.unwrap(),
                circle_message_v2.attestation.unwrap(),
            )
            .send()
            .await?;
        let receipt = tx.watch().await?;
        println!("Hub Rescue FastMCTP Receipt: {:?}", receipt);
    }

    Ok(())
}
