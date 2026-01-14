// Copyright (C) 2020, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#[macro_use]
extern crate log;

use std::io;

use std::net;

use std::io::prelude::*;

use std::collections::HashMap;

use std::convert::TryFrom;

use std::rc::Rc;

use std::cell::RefCell;

use std::time::{SystemTime, UNIX_EPOCH};

use ring::aead;
use ring::rand::*;

use hkdf::Hkdf;

use quiche_apps::args::*;

use quiche_apps::common::*;

use quiche_apps::sendto::*;

const MAX_BUF_SIZE: usize = 65507;

const MAX_DATAGRAM_SIZE: usize = 1350;

const RETRY_TOKEN_KEY_SIZE: usize = 16;
const RETRY_TOKEN_IV_SIZE: usize = 12;
const RETRY_CONNECTION_ID_LEN: usize = 8;
// const RETRY_TOKEN_TAG_SIZE: usize = 16;

fn main() {
    let mut buf = [0; MAX_BUF_SIZE];
    let mut out = [0; MAX_BUF_SIZE];
    let mut pacing = false;

    env_logger::builder().format_timestamp_nanos().init();

    // Parse CLI parameters.
    let docopt = docopt::Docopt::new(SERVER_USAGE).unwrap();
    let conn_args = CommonArgs::with_docopt(&docopt);
    let args = ServerArgs::with_docopt(&docopt);

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Create the UDP listening socket, and register it with the event loop.
    let mut socket =
        mio::net::UdpSocket::bind(args.listen.parse().unwrap()).unwrap();

    // Set SO_TXTIME socket option on the listening UDP socket for pacing
    // outgoing packets.
    if !args.disable_pacing {
        match set_txtime_sockopt(&socket) {
            Ok(_) => {
                pacing = true;
                debug!("successfully set SO_TXTIME socket option");
            },
            Err(e) => debug!("setsockopt failed {:?}", e),
        };
    }

    info!("listening on {:}", socket.local_addr().unwrap());

    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    let max_datagram_size = MAX_DATAGRAM_SIZE;
    let enable_gso = if args.disable_gso {
        false
    } else {
        detect_gso(&socket, max_datagram_size)
    };

    trace!("GSO detected: {}", enable_gso);

    // Create the configuration for the QUIC connections.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    config.load_cert_chain_from_pem_file(&args.cert).unwrap();
    config.load_priv_key_from_pem_file(&args.key).unwrap();

    config.set_application_protos(&conn_args.alpns).unwrap();

    config.discover_pmtu(args.enable_pmtud);
    config.set_max_idle_timeout(conn_args.idle_timeout);
    config.set_max_recv_udp_payload_size(max_datagram_size);
    config.set_max_send_udp_payload_size(max_datagram_size);
    config.set_initial_max_data(conn_args.max_data);
    config.set_initial_max_stream_data_bidi_local(conn_args.max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(conn_args.max_stream_data);
    config.set_initial_max_stream_data_uni(conn_args.max_stream_data);
    config.set_initial_max_streams_bidi(conn_args.max_streams_bidi);
    config.set_initial_max_streams_uni(conn_args.max_streams_uni);
    config.set_disable_active_migration(!conn_args.enable_active_migration);
    config.set_active_connection_id_limit(conn_args.max_active_cids);
    config.set_initial_congestion_window_packets(
        usize::try_from(conn_args.initial_cwnd_packets).unwrap(),
    );

    config.set_max_connection_window(conn_args.max_window);
    config.set_max_stream_window(conn_args.max_stream_window);

    config.enable_pacing(pacing);

    let mut keylog = None;

    if let Some(keylog_path) = std::env::var_os("SSLKEYLOGFILE") {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(keylog_path)
            .unwrap();

        keylog = Some(file);

        config.log_keys();
    }

    if conn_args.early_data {
        config.enable_early_data();
    }

    if conn_args.no_grease {
        config.grease(false);
    }

    config
        .set_cc_algorithm_name(&conn_args.cc_algorithm)
        .unwrap();

    if conn_args.disable_hystart {
        config.enable_hystart(false);
    }

    if conn_args.dgrams_enabled {
        config.enable_dgram(true, 1000, 1000);
    }

    let rng = SystemRandom::new();
    let conn_id_seed =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut next_client_id = 0;
    let mut clients_ids = ClientIdMap::new();
    let mut clients = ClientMap::new();

    let mut pkt_count = 0;

    let mut continue_write = false;

    let local_addr = socket.local_addr().unwrap();

    loop {
        // Find the shorter timeout from all the active connections.
        //
        // TODO: use event loop that properly supports timers
        let timeout = match continue_write {
            true => Some(std::time::Duration::from_secs(0)),

            false => clients.values().filter_map(|c| c.conn.timeout()).min(),
        };

        let mut poll_res = poll.poll(&mut events, timeout);
        while let Err(e) = poll_res.as_ref() {
            if e.kind() == std::io::ErrorKind::Interrupted {
                trace!("mio poll() call failed, retrying: {:?}", e);
                poll_res = poll.poll(&mut events, timeout);
            } else {
                panic!("mio poll() call failed fatally: {:?}", e);
            }
        }

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() && !continue_write {
                trace!("timed out");

                clients.values_mut().for_each(|c| c.conn.on_timeout());

                break 'read;
            }

            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        trace!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {:?}", e);
                },
            };

            trace!("got {len} bytes from {from} to {local_addr}");

            let pkt_buf = &mut buf[..len];

            if let Some(target_path) = conn_args.dump_packet_path.as_ref() {
                let path = format!("{target_path}/{pkt_count}.pkt");

                if let Ok(f) = std::fs::File::create(path) {
                    let mut f = std::io::BufWriter::new(f);
                    f.write_all(pkt_buf).ok();
                }
            }

            pkt_count += 1;

            // Parse the QUIC packet's header.
            let hdr = match quiche::Header::from_slice(
                pkt_buf,
                RETRY_CONNECTION_ID_LEN,
            ) {
                Ok(v) => v,

                Err(e) => {
                    error!("Parsing packet header failed: {:?}", e);
                    continue 'read;
                },
            };

            trace!("got packet {:?}", hdr);

            let conn_id = if !cfg!(feature = "fuzzing") {
                let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
                let conn_id = &conn_id.as_ref()[..RETRY_CONNECTION_ID_LEN];
                conn_id.to_vec().into()
            } else {
                // When fuzzing use an all zero connection ID.
                [0; RETRY_CONNECTION_ID_LEN].to_vec().into()
            };

            // Lookup a connection based on the packet's connection ID. If there
            // is no connection matching, create a new one.
            let client = if !clients_ids.contains_key(&hdr.dcid)
                && !clients_ids.contains_key(&conn_id)
            {
                if hdr.ty != quiche::Type::Initial {
                    error!("Packet is not Initial");
                    continue 'read;
                }

                if !quiche::version_is_supported(hdr.version) {
                    warn!("Doing version negotiation");

                    let len =
                        quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)
                            .unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, from) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            trace!("send() would block");
                            break;
                        }

                        panic!("send() failed: {:?}", e);
                    }
                    continue 'read;
                }

                let mut scid = [0; RETRY_CONNECTION_ID_LEN];
                scid.copy_from_slice(&conn_id);

                let mut odcid = None;

                if !args.no_retry {
                    // Token is always present in Initial packets.
                    let token = hdr.token.as_ref().unwrap();

                    // Do stateless retry if the client didn't send a token.
                    if token.is_empty() {
                        warn!("Doing stateless retry");

                        let scid = quiche::ConnectionId::from_ref(&scid);
                        let new_token = mint_token(&hdr, &from);

                        let len = quiche::retry(
                            &hdr.scid,
                            &hdr.dcid,
                            &scid,
                            &new_token,
                            hdr.version,
                            &mut out,
                        )
                        .unwrap();

                        let out = &out[..len];

                        if let Err(e) = socket.send_to(out, from) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                trace!("send() would block");
                                break;
                            }

                            panic!("send() failed: {:?}", e);
                        }
                        continue 'read;
                    }

                    odcid = validate_token(&from, &hdr, token);

                    // The token was not valid, meaning the retry failed, so
                    // drop the packet.
                    if odcid.is_none() {
                        error!("Invalid address validation token");
                        continue;
                    }

                    if scid.len() != hdr.dcid.len() {
                        error!(
                            "Invalid destination connection ID {:#?} {:#?}",
                            scid.len(),
                            hdr.dcid.len()
                        );
                        continue 'read;
                    }

                    // Reuse the source connection ID we sent in the Retry
                    // packet, instead of changing it again.
                    scid.copy_from_slice(&hdr.dcid);
                }

                let scid = quiche::ConnectionId::from_vec(scid.to_vec());

                debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                #[allow(unused_mut)]
                let mut conn = quiche::accept(
                    &scid,
                    odcid.as_ref(),
                    local_addr,
                    from,
                    &mut config,
                )
                .unwrap();

                if let Some(keylog) = &mut keylog {
                    if let Ok(keylog) = keylog.try_clone() {
                        conn.set_keylog(Box::new(keylog));
                    }
                }

                // Only bother with qlog if the user specified it.
                #[cfg(feature = "qlog")]
                {
                    if let Some(dir) = std::env::var_os("QLOGDIR") {
                        let id = format!("{:?}", &scid);
                        let writer = make_qlog_writer(&dir, "server", &id);

                        conn.set_qlog(
                            std::boxed::Box::new(writer),
                            "quiche-server qlog".to_string(),
                            format!("{} id={}", "quiche-server qlog", id),
                        );
                    }
                }

                let client_id = next_client_id;

                let client = Client {
                    conn,
                    http_conn: None,
                    client_id,
                    partial_requests: HashMap::new(),
                    partial_responses: HashMap::new(),
                    app_proto_selected: false,
                    max_datagram_size,
                    loss_rate: 0.0,
                    max_send_burst: MAX_BUF_SIZE,
                };

                clients.insert(client_id, client);
                clients_ids.insert(scid.clone(), client_id);

                next_client_id += 1;

                clients.get_mut(&client_id).unwrap()
            } else {
                let cid = match clients_ids.get(&hdr.dcid) {
                    Some(v) => v,

                    None => clients_ids.get(&conn_id).unwrap(),
                };

                clients.get_mut(cid).unwrap()
            };

            let recv_info = quiche::RecvInfo {
                to: local_addr,
                from,
            };

            // Process potentially coalesced packets.
            let read = match client.conn.recv(pkt_buf, recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                    continue 'read;
                },
            };

            trace!("{} processed {} bytes", client.conn.trace_id(), read);

            // Create a new application protocol session as soon as the QUIC
            // connection is established.
            if !client.app_proto_selected
                && (client.conn.is_in_early_data()
                    || client.conn.is_established())
            {
                // At this stage the ALPN negotiation succeeded and selected a
                // single application protocol name. We'll use this to construct
                // the correct type of HttpConn but `application_proto()`
                // returns a slice, so we have to convert it to a str in order
                // to compare to our lists of protocols. We `unwrap()` because
                // we need the value and if something fails at this stage, there
                // is not much anyone can do to recover.
                let app_proto = client.conn.application_proto();

                #[allow(clippy::box_default)]
                if alpns::HTTP_09.contains(&app_proto) {
                    client.http_conn = Some(Box::<Http09Conn>::default());

                    client.app_proto_selected = true;
                } else if alpns::HTTP_3.contains(&app_proto) {
                    let dgram_sender = if conn_args.dgrams_enabled {
                        Some(Http3DgramSender::new(
                            conn_args.dgram_count,
                            conn_args.dgram_data.clone(),
                            1,
                        ))
                    } else {
                        None
                    };

                    client.http_conn = match Http3Conn::with_conn(
                        &mut client.conn,
                        conn_args.max_field_section_size,
                        conn_args.qpack_max_table_capacity,
                        conn_args.qpack_blocked_streams,
                        dgram_sender,
                        Rc::new(RefCell::new(stdout_sink)),
                    ) {
                        Ok(v) => Some(v),

                        Err(e) => {
                            trace!("{} {}", client.conn.trace_id(), e);
                            None
                        },
                    };

                    client.app_proto_selected = true;
                }

                // Update max_datagram_size after connection established.
                client.max_datagram_size =
                    client.conn.max_send_udp_payload_size();
            }

            if client.http_conn.is_some() {
                let conn = &mut client.conn;
                let http_conn = client.http_conn.as_mut().unwrap();
                let partial_responses = &mut client.partial_responses;

                // Visit all writable response streams to send any remaining HTTP
                // content.
                for stream_id in writable_response_streams(conn) {
                    http_conn.handle_writable(conn, partial_responses, stream_id);
                }

                if http_conn
                    .handle_requests(
                        conn,
                        &mut client.partial_requests,
                        partial_responses,
                        &args.root,
                        &args.index,
                        &mut buf,
                    )
                    .is_err()
                {
                    continue 'read;
                }
            }

            handle_path_events(client);

            // See whether source Connection IDs have been retired.
            while let Some(retired_scid) = client.conn.retired_scid_next() {
                info!("Retiring source CID {:?}", retired_scid);
                clients_ids.remove(&retired_scid);
            }

            // Provides as many CIDs as possible.
            while client.conn.scids_left() > 0 {
                let (scid, reset_token) = generate_cid_and_reset_token(&rng);
                if client.conn.new_scid(&scid, reset_token, false).is_err() {
                    break;
                }

                clients_ids.insert(scid, client.client_id);
            }
        }

        // Generate outgoing QUIC packets for all active connections and send
        // them on the UDP socket, until quiche reports that there are no more
        // packets to be sent.
        continue_write = false;
        for client in clients.values_mut() {
            // Reduce max_send_burst by 25% if loss is increasing more than 0.1%.
            let loss_rate =
                client.conn.stats().lost as f64 / client.conn.stats().sent as f64;
            if loss_rate > client.loss_rate + 0.001 {
                client.max_send_burst = client.max_send_burst / 4 * 3;
                // Minimum bound of 10xMSS.
                client.max_send_burst =
                    client.max_send_burst.max(client.max_datagram_size * 10);
                client.loss_rate = loss_rate;
            }

            let max_send_burst =
                client.conn.send_quantum().min(client.max_send_burst)
                    / client.max_datagram_size
                    * client.max_datagram_size;
            let mut total_write = 0;
            let mut dst_info = None;

            while total_write < max_send_burst {
                let (write, send_info) = match client
                    .conn
                    .send(&mut out[total_write..max_send_burst])
                {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        trace!("{} done writing", client.conn.trace_id());
                        break;
                    },

                    Err(e) => {
                        error!("{} send failed: {:?}", client.conn.trace_id(), e);

                        client.conn.close(false, 0x1, b"fail").ok();
                        break;
                    },
                };

                total_write += write;

                // Use the first packet time to send, not the last.
                let _ = dst_info.get_or_insert(send_info);

                if write < client.max_datagram_size {
                    continue_write = true;
                    break;
                }
            }

            if total_write == 0 || dst_info.is_none() {
                continue;
            }

            if let Err(e) = send_to(
                &socket,
                &out[..total_write],
                &dst_info.unwrap(),
                client.max_datagram_size,
                pacing,
                enable_gso,
            ) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    trace!("send() would block");
                    break;
                }

                panic!("send_to() failed: {:?}", e);
            }

            trace!(
                "{} written {total_write} bytes with {dst_info:?}",
                client.conn.trace_id()
            );

            if total_write >= max_send_burst {
                trace!("{} pause writing", client.conn.trace_id(),);
                continue_write = true;
                break;
            }
        }

        // Garbage collect closed connections.
        clients.retain(|_, ref mut c| {
            trace!("Collecting garbage");

            if c.conn.is_closed() {
                info!(
                    "{} connection collected {:?} {:?}",
                    c.conn.trace_id(),
                    c.conn.stats(),
                    c.conn.path_stats().collect::<Vec<quiche::PathStats>>()
                );

                for id in c.conn.source_ids() {
                    let id_owned = id.clone().into_owned();
                    clients_ids.remove(&id_owned);
                }
            }

            !c.conn.is_closed()
        });
    }
}

/// AES-GCM-128 encryption
/// - key: key
/// - nonce: nonce
/// - data: additional authentication data || plain text
/// - aad_size: length of additional authentication data
pub fn aes_gcm_128_encrypt(
    key: &[u8; 16], nonce: &[u8; 12], data: &[u8], aad_size: usize,
) -> Result<Vec<u8>, ring::error::Unspecified> {
    let (aad, plaintext) = data.split_at(aad_size);

    let unbound_key = aead::UnboundKey::new(&aead::AES_128_GCM, key)?;
    let nonce = aead::Nonce::try_assume_unique_for_key(nonce)?;
    let sealing_key = aead::LessSafeKey::new(unbound_key);

    let mut in_out = plaintext.to_vec();
    sealing_key.seal_in_place_append_tag(
        nonce,
        aead::Aad::from(aad),
        &mut in_out,
    )?;

    let mut result = Vec::with_capacity(aad_size + in_out.len());
    result.extend_from_slice(aad);
    result.extend_from_slice(&in_out);
    Ok(result)
}

/// AES-GCM-128 decryption
/// - key: 16B key
/// - nonce: 12B nonce
/// - data: additional authentication data || plain text || Authentication Tag
/// - aad_size: length of additional authentication data
pub fn aes_gcm_128_decrypt(
    key: &[u8; 16], nonce: &[u8; 12], data: &[u8], aad_size: usize,
) -> Result<Vec<u8>, ring::error::Unspecified> {
    let (aad, rest) = data.split_at(aad_size);
    let ciphertext_len =
        rest.len().checked_sub(16).ok_or(ring::error::Unspecified)?;
    let (ciphertext, tag) = rest.split_at(ciphertext_len);

    let unbound_key = aead::UnboundKey::new(&aead::AES_128_GCM, key)?;
    let nonce = aead::Nonce::try_assume_unique_for_key(nonce)?;
    let opening_key = aead::LessSafeKey::new(unbound_key);

    let mut in_out = ciphertext.to_vec();
    in_out.extend_from_slice(tag);

    let plaintext =
        opening_key.open_in_place(nonce, aead::Aad::from(aad), &mut in_out)?;

    let mut result = Vec::with_capacity(aad_size + plaintext.len());
    result.extend_from_slice(aad);
    result.extend_from_slice(plaintext);
    Ok(result)
}

fn build_hkdf_label(
    label: &str, context: &[u8], len: usize,
) -> Result<Vec<u8>, String> {
    if len > 255 * 32 {
        return Err("Output length too large".into());
    }

    let label_with_prefix = format!("tls13 {}", label);
    let label_len = label_with_prefix.len() as u8;
    let context_len = context.len() as u8;

    let mut hkdf_label = Vec::new();
    hkdf_label.extend_from_slice(&(len as u16).to_be_bytes()); // 输出长度 (2字节)
    hkdf_label.push(label_len); // 标签长度 (1字节)
    hkdf_label.extend_from_slice(label_with_prefix.as_bytes()); // 标签内容
    hkdf_label.push(context_len); // 上下文长度 (1字节)
    hkdf_label.extend_from_slice(context); // 上下文内容

    Ok(hkdf_label)
}

fn hkdf_label_expand(
    prk: &[u8], label: &str, context: &[u8], len: usize,
) -> Result<Vec<u8>, String> {
    let hkdf_label = build_hkdf_label(label, context, len)?;
    let hk = Hkdf::<sha2::Sha256>::from_prk(prk).expect("Failed to build key");
    let mut okm = vec![0u8; len];
    hk.expand(&hkdf_label, &mut okm).expect("Failed to expand");

    Ok(okm)
}

fn derive_token_key_and_iv(
    cid: &[u8],
) -> Result<([u8; 16], [u8; 12]), ring::error::Unspecified> {
    let retry_initial_salt = b"\x1d\x76\xcd\x55\x94\x68\x26\xb6\xdb\x10\x67\xf9\x0d\xe5\x3e\x37\xb1\xbd\xc9\x8b";
    // let prk = hkdf_extract(retry_initial_salt, cid);
    let (prk, _) =
        Hkdf::<sha2::Sha256>::extract(Some(&retry_initial_salt[..]), &cid);
    // println!("{:#?}", prk);
    let retry_secret = hkdf_label_expand(&prk, "retry token", &[], 32)
        .expect("Failed to derive key");

    let key =
        hkdf_label_expand(&retry_secret, "token key", &[], RETRY_TOKEN_KEY_SIZE)
            .expect("Failed to derive key");
    let iv =
        hkdf_label_expand(&retry_secret, "token iv", &[], RETRY_TOKEN_IV_SIZE)
            .expect("Failed to derive iv");
    Ok((
        key.try_into().unwrap(), // Vec<u8> -> [u8; 16]
        iv.try_into().unwrap(),  // Vec<u8> -> [u8; 12]
    ))
}

fn make_nonce(iv: &[u8], counter: u64) -> [u8; RETRY_TOKEN_IV_SIZE] {
    let mut nonce = [0; RETRY_TOKEN_IV_SIZE];
    nonce.copy_from_slice(iv);

    // XOR the last bytes of the IV with the counter. This is equivalent to
    // left-padding the counter with zero bytes.
    for (a, b) in nonce[0..9].iter_mut().zip(counter.to_be_bytes().iter()) {
        *a ^= b;
    }

    nonce
}

/// Generate a stateless retry token.
///
/// The token includes the static string `"quiche"` followed by the IP address
/// of the client and by the original destination connection ID generated by the
/// client.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn mint_token(hdr: &quiche::Header, src: &net::SocketAddr) -> Vec<u8> {
    // Token format {
    //   Token Type (1),
    //   Original Destination Connection ID Length (7),
    //   Timestamp (64),
    //   ------- Below are encrypted part -------------
    //   Original Destination Connection ID (0..160),
    //   Source IP (32),
    //   Source Port (16),
    //   ----------------------------------------------
    //   Authentication Tag (128)
    // }

    // server retry, token type = 1
    let first_byte = (hdr.dcid.len() as u8) | 0x80;
    // get timestamp in big-endian format
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // get source ip address
    let (_, mut ip_bytes) = match src.ip() {
        net::IpAddr::V4(v4) => (0x04, v4.octets().to_vec()),
        net::IpAddr::V6(v6) => (0x06, v6.octets().to_vec()),
    };
    ip_bytes.reverse();
    // get source port
    let port = src.port().to_le_bytes();
    let dcid = hdr.dcid.as_ref();

    // derive key and nonce
    let (token_key, token_iv) = derive_token_key_and_iv(hdr.scid.as_ref())
        .expect("Failed to derive token key and iv");
    let token_nonce: [u8; RETRY_TOKEN_IV_SIZE] = make_nonce(&token_iv, timestamp);

    // concatnate data for encryption
    let mut token =
        Vec::with_capacity(1 + 8 + dcid.len() + ip_bytes.len() + port.len());
    token.push(first_byte);
    token.extend_from_slice(&(timestamp.to_be_bytes()));
    token.extend_from_slice(dcid);
    token.extend_from_slice(&ip_bytes);
    token.extend_from_slice(&port);

    aes_gcm_128_encrypt(&token_key, &token_nonce, token.as_ref(), 9)
        .expect("Failed to encrypt")
}

/// Validates a stateless retry token.
///
/// This checks that the ticket includes the `"quiche"` static string, and that
/// the client IP address matches the address stored in the ticket.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn validate_token<'a>(
    src: &net::SocketAddr, hdr: &quiche::Header, token: &'a [u8],
) -> Option<quiche::ConnectionId<'a>> {
    let odcidl = (token[0] & 0x7f) as usize;
    let timestamp =
        u64::from_be_bytes(token.get(1..9).unwrap().try_into().unwrap());

    let (token_key, token_iv) = derive_token_key_and_iv(hdr.scid.as_ref())
        .expect("Failed to derive token key and iv");
    let token_nonce: [u8; RETRY_TOKEN_IV_SIZE] = make_nonce(&token_iv, timestamp);

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // validate
    if current_time - timestamp > 60 {
        error!("out of date! {:?} {:?}", current_time, timestamp);
        return None;
    }

    let data = aes_gcm_128_decrypt(&token_key, &token_nonce, token, 9)
        .expect("Failed to decrypt");

    // parse plain text
    let (_, plaintext) = data.split_at(9);
    let original_destination_id = plaintext.get(0..odcidl).unwrap();
    trace!("odcid = {:#?}", original_destination_id);
    let mut pos = odcidl;
    // sip
    let mut sip_raw = <[u8; 4]>::try_from(&plaintext[pos..pos + 4]).ok()?;
    sip_raw.reverse();
    let sip = net::IpAddr::from(sip_raw);
    trace!("osip = {:#?}, sip = {:#?}", sip, src.ip());
    pos += 4;
    // sport
    let sport =
        u16::from_le_bytes(plaintext.get(pos..pos + 2)?.try_into().unwrap());
    trace!("osport = {:#?}, sport = {:#?}", sport, src.port());

    // validate
    if sip != src.ip() || sport != src.port() {
        return None;
    }

    Some(quiche::ConnectionId::from_vec(
        original_destination_id.to_vec(),
    ))
}

fn handle_path_events(client: &mut Client) {
    while let Some(qe) = client.conn.path_event_next() {
        match qe {
            quiche::PathEvent::New(local_addr, peer_addr) => {
                info!(
                    "{} Seen new path ({}, {})",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );

                // Directly probe the new path.
                client
                    .conn
                    .probe_path(local_addr, peer_addr)
                    .expect("cannot probe");
            },

            quiche::PathEvent::Validated(local_addr, peer_addr) => {
                info!(
                    "{} Path ({}, {}) is now validated",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            },

            quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                info!(
                    "{} Path ({}, {}) failed validation",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            },

            quiche::PathEvent::Closed(local_addr, peer_addr) => {
                info!(
                    "{} Path ({}, {}) is now closed and unusable",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            },

            quiche::PathEvent::ReusedSourceConnectionId(cid_seq, old, new) => {
                info!(
                    "{} Peer reused cid seq {} (initially {:?}) on {:?}",
                    client.conn.trace_id(),
                    cid_seq,
                    old,
                    new
                );
            },

            quiche::PathEvent::PeerMigrated(local_addr, peer_addr) => {
                info!(
                    "{} Connection migrated to ({}, {})",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            },
        }
    }
}

/// Set SO_TXTIME socket option.
///
/// This socket option is set to send to kernel the outgoing UDP
/// packet transmission time in the sendmsg syscall.
///
/// Note that this socket option is set only on linux platforms.
#[cfg(target_os = "linux")]
fn set_txtime_sockopt(sock: &mio::net::UdpSocket) -> io::Result<()> {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::TxTime;
    use std::os::unix::io::AsRawFd;

    let config = nix::libc::sock_txtime {
        clockid: libc::CLOCK_MONOTONIC,
        flags: 0,
    };

    setsockopt(sock.as_raw_fd(), TxTime, &config)?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_txtime_sockopt(_: &mio::net::UdpSocket) -> io::Result<()> {
    use std::io::Error;
    use std::io::ErrorKind;

    Err(Error::new(
        ErrorKind::Other,
        "Not supported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_macro::hex;

    const RETRY_TOKEN_KEY_SIZE: usize = 16;
    const RETRY_TOKEN_IV_SIZE: usize = 12;

    #[test]
    fn test_aes_gcm_128_encrypt_decrypt() {
        // Test key and nonce
        let key = [0u8; 16];
        let nonce = [0u8; 12];

        // Test data with AAD and plaintext
        let aad = b"additional authenticated data";
        let plaintext = b"secret message";
        let mut data = Vec::new();
        data.extend_from_slice(aad);
        data.extend_from_slice(plaintext);

        // Encrypt
        let encrypted = aes_gcm_128_encrypt(&key, &nonce, &data, aad.len())
            .expect("Encryption failed");

        // Decrypt
        let decrypted = aes_gcm_128_decrypt(&key, &nonce, &encrypted, aad.len())
            .expect("Decryption failed");

        // Verify the decrypted data matches original
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_aes_gcm_128_decrypt_failure() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let aad = b"aad";
        let plaintext = b"plaintext";
        let mut data = Vec::new();
        data.extend_from_slice(aad);
        data.extend_from_slice(plaintext);

        let encrypted = aes_gcm_128_encrypt(&key, &nonce, &data, aad.len())
            .expect("Encryption failed");

        // Tamper with the ciphertext
        let mut tampered = encrypted.clone();
        if let Some(byte) = tampered.last_mut() {
            *byte = !*byte;
        }

        // Decryption should fail
        assert!(aes_gcm_128_decrypt(&key, &nonce, &tampered, aad.len()).is_err());
    }

    #[test]
    fn test_aes_gcm_empty_aad() {
        let key = [1u8; 16];
        let nonce = [2u8; 12];
        let plaintext = b"message with empty aad";

        // Encrypt with empty AAD
        let encrypted = aes_gcm_128_encrypt(&key, &nonce, plaintext, 0)
            .expect("Encryption failed");

        // Decrypt
        let decrypted = aes_gcm_128_decrypt(&key, &nonce, &encrypted, 0)
            .expect("Decryption failed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_rfc9001_appendix_a1() {
        // 初始盐值 (RFC 9001 5.2节)
        let initial_salt = hex!("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");

        // 测试用例 (RFC 9001 附录 A.1)
        let ikm = hex!("8394c8f03e515708");
        let expected_prk = hex!(
            "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"
        );

        // 测试 HKDF-Extract
        let (prk, _) =
            Hkdf::<sha2::Sha256>::extract(Some(&initial_salt[..]), &ikm);
        assert_eq!(prk.to_vec(), expected_prk);

        let expected_key = hex!(
            "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
        );
        let client_secret =
            hkdf_label_expand(&prk, "client in", &[], 32).unwrap();
        assert_eq!(client_secret, expected_key);

        let expected_key = hex!("1f369613dd76d5467730efcbe3b1a22d");
        let quic_key = hkdf_label_expand(
            &client_secret,
            "quic key",
            &[],
            RETRY_TOKEN_KEY_SIZE,
        )
        .unwrap();
        assert_eq!(quic_key, expected_key);

        let expected_key = hex!("fa044b2f42a3fd3b46fb255c");
        let quic_iv = hkdf_label_expand(
            &client_secret,
            "quic iv",
            &[],
            RETRY_TOKEN_IV_SIZE,
        )
        .unwrap();
        assert_eq!(quic_iv, expected_key);
    }

    #[test]
    fn test_derive_key_and_iv() {
        let cid = hex!("be112e4531dbbf4a");
        let (key, iv) = derive_token_key_and_iv(&cid).unwrap();
        let expect_key = hex!("33d0c3067168d38eac40bb791b624264");
        assert_eq!(key, expect_key);
        let expect_iv = hex!("994e27098d0a24c6bb200ebf");
        assert_eq!(iv, expect_iv);
    }

    // #[test]
    // fn test_make_nonce() {
    //     let iv = [
    //         0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
    //         0xCC,
    //     ];
    //     let counter = 0x123456789ABCDEF0;

    //     let nonce = make_nonce(&iv, counter);

    //     // Verify the nonce is constructed correctly
    //     assert_eq!(nonce[0..4], iv[0..4]); // First 4 bytes should be unchanged
    //                                        // Last 8 bytes should be XORed with counter bytes
    //     assert_eq!(nonce[4], iv[4] ^ 0x12);
    //     assert_eq!(nonce[5], iv[5] ^ 0x34);
    //     assert_eq!(nonce[6], iv[6] ^ 0x56);
    //     assert_eq!(nonce[7], iv[7] ^ 0x78);
    //     assert_eq!(nonce[8], iv[8] ^ 0x9A);
    //     assert_eq!(nonce[9], iv[9] ^ 0xBC);
    //     assert_eq!(nonce[10], iv[10] ^ 0xDE);
    //     assert_eq!(nonce[11], iv[11] ^ 0xF0);
    // }

    #[test]
    fn test_decode_token() {
        let cid = hex!("be112e4531dbbf4a");
        let token = hex!("0800000000680b488f604e6b0e6d662e1e3138726b07185e87a23f13fada052cf05715a3a71ccf");
        let odcidl = (token[0] & 0x7f) as usize;
        let timestamp =
            u64::from_be_bytes(token.get(1..9).unwrap().try_into().unwrap());
        assert_eq!(timestamp, 1745569935);

        let (token_key, token_iv) = derive_token_key_and_iv(&cid)
            .expect("Failed to derive token key and iv");

        let expect_key = hex!("33d0c3067168d38eac40bb791b624264");
        assert_eq!(token_key, expect_key);
        let expect_iv = hex!("994e27098d0a24c6bb200ebf");
        assert_eq!(token_iv, expect_iv);

        let expect_nonce = hex!("994e2709e5016c49bb200ebf");
        let token_nonce: [u8; RETRY_TOKEN_IV_SIZE] =
            make_nonce(&token_iv, timestamp);
        assert_eq!(token_nonce, expect_nonce);

        let data = aes_gcm_128_decrypt(&token_key, &token_nonce, &token, 9)
            .expect("Failed to decrypt");

        // parse plain text
        let (_, plaintext) = data.split_at(9);
        let original_destination_id = plaintext.get(0..odcidl).unwrap();
        println!("{:#?}", original_destination_id);
        let mut pos = odcidl;
        // sip
        let sip = net::IpAddr::from(
            <[u8; 4]>::try_from(&plaintext[pos..pos + 4]).ok().unwrap(),
        );
        println!("{:#?}", sip);
        // assert_eq!();
        pos += 4;
        // sport
        let sport = u16::from_be_bytes(
            plaintext.get(pos..pos + 2).unwrap().try_into().unwrap(),
        );
        println!("{:#?}", sport);
    }

    #[test]
    fn test_decode_token_from_aioquic() {
        let cid = hex!("b78a3081a52407ea");
        let token = hex!("08000000006890534a32eceea8cbfc73cc8d204622a09b9af4ad81cfb1c4a1504b9f4089b2b138");
        let odcidl = (token[0] & 0x7f) as usize;
        let timestamp =
            u64::from_be_bytes(token.get(1..9).unwrap().try_into().unwrap());
        // assert_eq!(timestamp, 1754288970);
        println!("{:#?}", timestamp);

        let (token_key, token_iv) = derive_token_key_and_iv(&cid)
            .expect("Failed to derive token key and iv");
        // println!("{:#?} {:?}", token_key, token_iv);

        let expect_key = hex!("9db8177eb5595129997e30d349d26d29");
        assert_eq!(token_key, expect_key);
        let expect_iv = hex!("dfcc1821d8cf2fe9e71356c3");
        assert_eq!(token_iv, expect_iv);

        let expect_nonce = hex!("dfcc1821b05f7ca3e71356c3");
        let token_nonce: [u8; RETRY_TOKEN_IV_SIZE] =
            make_nonce(&token_iv, timestamp);
        assert_eq!(token_nonce, expect_nonce);

        let data = aes_gcm_128_decrypt(&token_key, &token_nonce, &token, 9)
            .expect("Failed to decrypt");
        println!("decrpted");

        // parse plain text
        let (_, plaintext) = data.split_at(9);
        let original_destination_id = plaintext.get(0..odcidl).unwrap();
        println!("odcid = {:#?}", original_destination_id);
        let mut pos = odcidl;
        // sip
        let sip = net::IpAddr::from(
            <[u8; 4]>::try_from(&plaintext[pos..pos + 4]).ok().unwrap(),
        );
        println!("sip = {:#?}", sip);
        // assert_eq!();
        pos += 4;
        // sport
        let sport = u16::from_be_bytes(
            plaintext.get(pos..pos + 2).unwrap().try_into().unwrap(),
        );
        println!("sport = {:#?}", sport);
    }
}
