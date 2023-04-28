//! Build script for the protobuf definitions

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/siopv2.proto")?;
    Ok(())
}
