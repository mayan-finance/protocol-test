use structopt::StructOpt;
use utils::{
    alloy::{
        hex::FromHex,
        primitives::{address, Address, Bytes, FixedBytes, U256},
        providers::Provider,
        sol,
    },
    circle::get_circle_message_v1,
    web3::{get_provider, get_wallet, increase_allowence},
    wormhole::get_vaa,
    *,
};
use ITokenRouter::OrderResponse;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    ITokenRouter,
    "../assets/IWormholeTokenRouter.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IERC20,
    "../assets/IERC20.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    MayanShuttle,
    "../assets/MayanShuttle.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IWormhole,
    "../assets/IWormhole.json"
);

#[derive(Debug, Clone, StructOpt)]
enum Opt {
    #[structopt(name = "bridge")]
    Bridge,

    #[structopt(name = "redeem")]
    Redeem {
        #[structopt(short, long)]
        encoded_vm: String,
        #[structopt(short, long)]
        cctp_message: String,
        #[structopt(short, long)]
        cctp_sender: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::from_args();

    match opt {
        Opt::Bridge => {
            let (address, wallet) = utils::web3::get_wallet()?;
            println!("Wallet Address: {}", address);
            let mut bytes_address = [0u8; 32];
            bytes_address[12..].copy_from_slice(address.as_slice());

            let avalanche_provider =
                utils::web3::get_provider(&wallet, "https://avalanche.drpc.org")?;

            println!(
                "Avalanche Latest Block: {:?}",
                avalanche_provider.get_block_number().await?
            );

            let mayan_shuttle_address = address!("0x0e689e83E1337037D9bF3A8691A06BD308c78484");
            let mayan_shuttle =
                MayanShuttle::new(mayan_shuttle_address, avalanche_provider.clone());
            let local_token = mayan_shuttle.localToken().call().await?._0;
            println!("Local Token: {:?}", local_token);
            println!("MayanShuttle Address: {:?}", mayan_shuttle_address);

            let value_u64 = 100000000;
            let value = U256::from(value_u64);
            let tx = utils::web3::increase_allowence(
                &avalanche_provider,
                local_token,
                mayan_shuttle_address,
                value,
                120,
            )
            .await?;
            println!("Increased allowance: {:?}", tx);

            let tx = mayan_shuttle
                .bridge(
                    value_u64,
                    0,
                    0,
                    bytes_address.try_into()?,
                    30,
                    bytes_address.try_into()?,
                    0,
                    1,
                    172000,
                    1753285701,
                    Bytes::from_hex("00")?,
                )
                .send()
                .await?;
            let receipt = tx.watch().await?;
            println!("MayanShuttle Bridge Receipt: {:?}", receipt);
        }
        Opt::Redeem {
            encoded_vm,
            cctp_message,
            cctp_sender,
        } => {
            let (address, wallet) = utils::web3::get_wallet()?;
            println!("Wallet Address: {}", address);

            let base_provider = utils::web3::get_provider(&wallet, "https://base.drpc.org")?;

            let mayan_shuttle_address = address!("0x36a79a04fbeec88476c7aa0270137f135dc8361c");
            let mayan_shuttle = MayanShuttle::new(mayan_shuttle_address, base_provider.clone());

            let tx = mayan_shuttle
                .redeem(
                    Bytes::from_hex(encoded_vm.trim_start_matches("0x"))?,
                    Bytes::from_hex(cctp_message.trim_start_matches("0x"))?,
                    Bytes::from_hex(cctp_sender.trim_start_matches("0x"))?,
                )
                .send()
                .await?;
            let receipt = tx.watch().await?;
            println!("MayanShuttle Redeem Receipt: {:?}", receipt);
        }
    }
    Ok(())
}
