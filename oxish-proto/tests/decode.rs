use oxish_proto::{
    Completion, Encode, IncomingPacket, MessageType, ProtoError, ReadState,
    channels::{ChannelOpen, ChannelOpenType, DirectTcpip},
};

#[test]
fn padding_too_large() {
    const PACKET: &[u8] = include_bytes!("padding-too-large.bin");
    let mut state = ReadState::default();
    assert!(matches!(
        decode(PACKET, &mut state).unwrap_err(),
        ProtoError::InvalidPacket("padding length exceeds packet length"),
    ));
}

#[test]
fn direct_tcpip_addresses() {
    for host in ["127.0.0.1", "::1", "service.example"] {
        let mut state = ReadState::default();
        let open = decode_channel_open(
            b"direct-tcpip",
            &direct_tcpip_fields(host.as_bytes(), b"::1"),
            &mut state,
        )
        .unwrap();
        assert_eq!(open.sender_channel, 7);
        assert_eq!(open.initial_window_size, 65_536);
        assert_eq!(open.maximum_packet_size, 32_768);
        assert_eq!(
            open.r#type,
            ChannelOpenType::DirectTcpip(DirectTcpip {
                host,
                port: 8080,
                originator_address: "::1",
                originator_port: 43_210,
            })
        );
    }
}

#[test]
fn direct_tcpip_truncated_fields() {
    let fields = direct_tcpip_fields(b"127.0.0.1", b"::1");
    for end in 0..fields.len() {
        let mut state = ReadState::default();
        assert!(matches!(
            decode_channel_open(b"direct-tcpip", &fields[..end], &mut state),
            Err(ProtoError::Incomplete(_))
        ));
    }
}

#[test]
fn direct_tcpip_invalid_addresses() {
    for invalid in [&b"host\0.example"[..], b"host\0", &[0xff]] {
        for (host, originator) in [(invalid, &b"::1"[..]), (&b"localhost"[..], invalid)] {
            let mut state = ReadState::default();
            assert!(matches!(
                decode_channel_open(
                    b"direct-tcpip",
                    &direct_tcpip_fields(host, originator),
                    &mut state
                ),
                Err(ProtoError::InvalidPacket(_))
            ));
        }
    }
}

#[test]
fn direct_tcpip_trailing_data() {
    let mut fields = direct_tcpip_fields(b"localhost", b"::1");
    fields.push(0);
    let mut state = ReadState::default();
    assert!(matches!(
        decode_channel_open(b"direct-tcpip", &fields, &mut state),
        Err(ProtoError::InvalidPacket(_))
    ));
}

#[test]
fn session_channel_open_has_no_type_specific_fields() {
    let mut state = ReadState::default();
    let open = decode_channel_open(b"session", &[], &mut state).unwrap();
    assert_eq!(open.r#type, ChannelOpenType::Session);

    let mut state = ReadState::default();
    assert!(matches!(
        decode_channel_open(b"session", &[0], &mut state),
        Err(ProtoError::InvalidPacket(_))
    ));
}

#[test]
fn unknown_channel_open_keeps_wire_name() {
    let mut state = ReadState::default();
    let open = decode_channel_open(b"vendor-channel", &[0], &mut state).unwrap();
    assert_eq!(open.r#type, ChannelOpenType::Unknown("vendor-channel"));
}

#[test]
fn channel_open_rejects_invalid_type_name() {
    let mut state = ReadState::default();
    assert!(matches!(
        decode_channel_open(&[0xff], &[], &mut state),
        Err(ProtoError::InvalidPacket(_))
    ));
}

fn direct_tcpip_fields(host: &[u8], originator: &[u8]) -> Vec<u8> {
    let mut fields = Vec::new();
    host.encode(&mut fields);
    8080u32.encode(&mut fields);
    originator.encode(&mut fields);
    43_210u32.encode(&mut fields);
    fields
}

fn decode_channel_open<'a>(
    name: &[u8],
    fields: &[u8],
    state: &'a mut ReadState,
) -> Result<ChannelOpen<'a>, ProtoError> {
    let mut packet = vec![0; 5];
    MessageType::ChannelOpen.encode(&mut packet);
    name.encode(&mut packet);
    7u32.encode(&mut packet);
    65_536u32.encode(&mut packet);
    32_768u32.encode(&mut packet);
    packet.extend_from_slice(fields);
    let padding_len = 4 + (8 - (packet.len() + 4) % 8) % 8;
    packet.resize(packet.len() + padding_len, 0);
    let packet_len = (packet.len() - 4) as u32;
    packet[..4].copy_from_slice(&packet_len.to_be_bytes());
    packet[4] = padding_len as u8;
    ChannelOpen::try_from(decode(&packet, state)?)
}

fn decode<'a>(bytes: &[u8], state: &'a mut ReadState) -> Result<IncomingPacket<'a>, ProtoError> {
    state.buf.extend_from_slice(bytes);
    match state.poll_packet()? {
        Completion::Complete((sequence_number, packet_length)) => {
            state.decode_packet(sequence_number, packet_length)
        }
        Completion::Incomplete(needed) => Err(ProtoError::Incomplete(needed)),
    }
}
