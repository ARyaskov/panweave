//! ZDP security service frames and their local TLVs never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use panweave_codec::Decode;
use panweave_zdo::security::*;

fuzz_target!(|data: &[u8]| {
    let _ = StartKeyNegotiationReq::decode_exact(data);
    let _ = StartKeyNegotiationRsp::decode_exact(data);
    let _ = RetrieveAuthenticationTokenReq::decode_exact(data);
    let _ = RetrieveAuthenticationTokenRsp::decode_exact(data);
    let _ = GetAuthenticationLevelReq::decode_exact(data);
    let _ = GetAuthenticationLevelRsp::decode_exact(data);
    let _ = SetConfigurationReq::decode_exact(data);
    let _ = SetConfigurationRsp::decode_exact(data);
    let _ = GetConfigurationReq::decode_exact(data);
    let _ = GetConfigurationRsp::decode_exact(data);
    let _ = StartKeyUpdateReq::decode_exact(data);
    let _ = DecommissionReq::decode_exact(data);
    let _ = ChallengeReq::decode_exact(data);
    let _ = ChallengeRsp::decode_exact(data);
    if let Ok(set) = validate(data) {
        let _ = PublicPoint::find(&set);
        let _ = SelectedKeyNegotiationMethod::find(&set);
        let _ = AuthenticationTokenId::find(&set);
        let _ = TargetIeee::find(&set);
        let _ = DeviceAuthenticationLevel::find(&set);
        let _ = Eui64List::find(&set);
        let _ = ProcessingStatus::find(&set);
        let _ = FrameCounterChallenge::find(&set);
        let _ = FrameCounterResponse::find(&set);
    }
});
