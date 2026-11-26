use core::{
    fmt,
    future::Future,
    mem,
    pin::Pin,
    str,
    task::{Context, Poll},
    time::Duration,
};
use std::{
    borrow::Cow,
    collections::{BTreeMap, VecDeque, btree_map::Entry},
    io,
    time::Instant,
};

use proto::{
    IncomingPacket, MAX_PACKET_LEN, MessageType, ProtoError, WriteState,
    auth::KeyOptions,
    channels::{
        ChannelClose, ChannelData, ChannelEof, ChannelOpen, ChannelOpenConfirmation,
        ChannelOpenFailure, ChannelRequest, ChannelRequestFailure, ChannelRequestSuccess,
        ChannelRequestType, ChannelType, ChannelWindowAdjust, DirectTcpip, PtyReq,
    },
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tracing::{debug, info, warn};

use crate::{Error, platform::Terminal};

#[derive(Default)]
pub(crate) struct Channels {
    next_id: u32,
    channels: BTreeMap<u32, Channel>,
}

impl Channels {
    pub(crate) fn open(
        &mut self,
        open: ChannelOpen<'_>,
        write: &mut WriteState,
    ) -> Result<(), Error> {
        let kind = match open.r#type {
            ChannelType::Session => ChannelKind::Session(Box::default()),
            ChannelType::DirectTcpip(destination) => {
                if !TcpConnection::valid_destination(&destination, open.maximum_packet_size) {
                    write.encode(&ChannelOpenFailure::administratively_prohibited(
                        open.sender_channel,
                        "invalid TCP destination or channel parameters",
                    ))?;
                    return Ok(());
                }
                let host = destination.host.to_owned();
                let port = destination.port as u16;
                ChannelKind::Tcp(TcpConnection::Connecting(Box::pin(async move {
                    tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port)))
                        .await
                        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
                })))
            }
            _ => {
                write.encode(&ChannelOpenFailure::unknown_type(open.sender_channel))?;
                return Ok(());
            }
        };

        if self.channels.len() + 1 >= MAX_OPEN_CHANNELS_PER_SESSION {
            write.encode(&ChannelOpenFailure::resource_shortage(open.sender_channel))?;
            return Ok(());
        }
        if self
            .channels
            .values()
            .any(|channel| channel.flow.remote_id == open.sender_channel)
        {
            write.encode(&ChannelOpenFailure::duplicate_id(open.sender_channel))?;
            return Ok(());
        }

        let local_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let entry = match self.channels.entry(local_id) {
            Entry::Vacant(entry) => entry,
            Entry::Occupied(_) => {
                write.encode(&ChannelOpenFailure::duplicate_id(open.sender_channel))?;
                return Ok(());
            }
        };

        let channel = entry.insert(Channel {
            flow: ChannelFlow {
                remote_id: open.sender_channel,
                send_window: open.initial_window_size,
                receive_window: 0,
                maximum_packet_size: open.maximum_packet_size,
                close_sent: false,
            },
            kind,
        });

        if matches!(channel.kind, ChannelKind::Session(_)) {
            write.encode(&channel.confirmation(local_id))?;
        }
        Ok(())
    }

    pub(crate) fn request(
        &mut self,
        request: ChannelRequest<'_>,
        write: &mut WriteState,
        banner: Option<&str>,
        options: &KeyOptions,
    ) -> Result<(), Error> {
        let Some(channel) = self.channels.get_mut(&request.recipient_channel) else {
            return Err(ProtoError::InvalidPacket("channel request for unknown channel ID").into());
        };

        let ChannelKind::Session(session) = &mut channel.kind else {
            let client_close = matches!(
                &channel.kind,
                ChannelKind::Tcp(TcpConnection::Connected(forward)) if forward.client_close
            );
            if request.want_reply && !channel.flow.close_sent && !client_close {
                write.encode(&channel.failure())?;
            }
            return Ok(());
        };

        match request.r#type {
            ChannelRequestType::PtyReq(pty_req) => {
                session.terminal = Some(TerminalState::Requested(pty_req.into_owned()));
            }
            ChannelRequestType::Env(env) => {
                const ALLOW_ENV: &[&str] = &["TZ", "LANG"];
                match ALLOW_ENV.contains(&env.name) || env.name.starts_with("LC_") {
                    true if session.env.len() < MAX_ENV_VARIABLE_COUNT
                        && env.name.len() <= MAX_ENV_VARIABLE_NAME_LEN
                        && env.value.len() <= MAX_ENV_VARIABLE_VALUE_LEN =>
                    {
                        session
                            .env
                            .push((env.name.to_owned(), env.value.to_owned()))
                    }
                    _ => {
                        debug!(name = env.name, "ignoring environment variable request");
                        if request.want_reply {
                            write.encode(&channel.failure())?;
                        }
                        return Ok(());
                    }
                }
            }
            ChannelRequestType::Shell => {
                let Some(TerminalState::Requested(pty_req)) = session.terminal.take() else {
                    return Err(
                        ProtoError::InvalidPacket("shell request without prior pty-req").into(),
                    );
                };

                let command = options.command.as_deref();
                if let Some(command) = command {
                    info!(channel_id = %request.recipient_channel, command, "running forced command from authorized key");
                }

                channel.start_terminal(command, &pty_req, write)?;
            }
            ChannelRequestType::Exec(exec) => {
                let Ok(requested) = str::from_utf8(exec.command) else {
                    // TODO: support non-UTF-8 command
                    warn!(channel_id = %request.recipient_channel, "refusing exec request with non-UTF-8 command");
                    if request.want_reply {
                        write.encode(&channel.failure())?;
                    }
                    return Ok(());
                };

                let pty_req = match session.terminal.take() {
                    Some(TerminalState::Requested(pty_req)) => pty_req,
                    state => {
                        session.terminal = state;
                        // TODO: support non-PTY exec channel also
                        warn!(channel_id = %request.recipient_channel, "refusing exec request without pending pty-req");
                        if request.want_reply {
                            write.encode(&channel.failure())?;
                        }
                        return Ok(());
                    }
                };

                let command = match options.command.as_deref() {
                    Some(command) => {
                        info!(channel_id = %request.recipient_channel, command, "running forced command from authorized key");
                        // Clients cannot set this themselves, see `ALLOW_ENV`
                        session
                            .env
                            .push((ORIGINAL_COMMAND_ENV.to_owned(), requested.to_owned()));
                        command
                    }
                    None => requested,
                };

                channel.start_terminal(Some(command), &pty_req, write)?;
            }
            ChannelRequestType::WindowChange(window_change) => match &session.terminal {
                Some(TerminalState::Running(terminal)) => terminal.resize(&window_change)?,
                _ => warn!("window-change request without running terminal"),
            },
            // Should be sent by the server only, ignore when received from clients
            ChannelRequestType::ExitStatus(status) => {
                debug!(channel_id = %request.recipient_channel, exit_status = %status, "received exit-status from client");
                if request.want_reply {
                    write.encode(&channel.failure())?;
                }
                return Ok(());
            }
            // Agent forwarding is not supported -- only reply when asked
            ChannelRequestType::AuthAgentReq | ChannelRequestType::Unknown(_) => {
                if request.want_reply {
                    write.encode(&channel.failure())?;
                }
                return Ok(());
            }
            _ => {
                warn!(request_type = ?request.r#type, "ignoring channel request");
                if request.want_reply {
                    write.encode(&channel.failure())?;
                }
                return Ok(());
            }
        }

        if request.want_reply {
            write.encode(&channel.success())?;
        }

        let Some(banner) = banner else {
            return Ok(());
        };

        let Some(window) = channel.flow.send_window.checked_sub(banner.len() as u32) else {
            return Ok(());
        };

        channel.flow.send_window = window;
        write.encode(&ChannelData {
            recipient_channel: channel.flow.remote_id,
            data: Cow::Borrowed(banner.as_bytes()),
        })?;
        Ok(())
    }

    pub(crate) fn adjust_window(&mut self, adjust: &ChannelWindowAdjust) -> Result<(), ProtoError> {
        let Some(channel) = self.channels.get_mut(&adjust.recipient_channel) else {
            return Err(ProtoError::InvalidPacket(
                "channel window adjust for unknown channel ID",
            ));
        };

        if u32::MAX - channel.flow.send_window < adjust.bytes_to_add {
            debug!(channel_id = %adjust.recipient_channel, "window adjust would overflow; capping");
        }

        channel.flow.send_window = channel.flow.send_window.saturating_add(adjust.bytes_to_add);
        Ok(())
    }

    pub(crate) fn data<'m, 's>(
        &'s mut self,
        data: &'m ChannelData<'m>,
        write: &mut WriteState,
    ) -> Result<Option<(&'s mut Terminal, &'m [u8])>, ProtoError> {
        let Some(channel) = self.channels.get_mut(&data.recipient_channel) else {
            return Err(ProtoError::InvalidPacket(
                "channel data for unknown channel ID",
            ));
        };

        if let ChannelKind::Tcp(tcp) = &mut channel.kind {
            if channel.flow.close_sent {
                return Ok(None);
            }
            let TcpConnection::Connected(forward) = tcp else {
                return Err(ProtoError::InvalidPacket("TCP channel is not open"));
            };
            if forward.client_close {
                return Ok(None);
            }
            if forward.write_state != TcpWriteState::Open {
                return Err(ProtoError::InvalidPacket("channel data after EOF"));
            }
            if data.data.len() > (MAX_PACKET_LEN - 64) as usize {
                return Err(ProtoError::InvalidPacket(
                    "channel data exceeds maximum packet size",
                ));
            }
            let Some(window) = channel
                .flow
                .receive_window
                .checked_sub(data.data.len() as u32)
            else {
                return Err(ProtoError::InvalidPacket(
                    "channel data exceeds receive window",
                ));
            };
            forward.pending.extend(data.data.iter().copied());
            channel.flow.receive_window = window;
            return Ok(None);
        }
        let ChannelKind::Session(session) = &mut channel.kind else {
            return Err(ProtoError::InvalidPacket("invalid channel type"));
        };

        match channel
            .flow
            .receive_window
            .checked_sub(data.data.len() as u32)
        {
            Some(window) => channel.flow.receive_window = window,
            None => {
                return Err(ProtoError::InvalidPacket(
                    "channel data exceeds receive window",
                ));
            }
        }

        if channel.flow.receive_window < INITIAL_WINDOW_SIZE / 2 {
            debug!(channel_id = %data.recipient_channel, "receive window low; sending window adjust");
            let bytes_to_add = INITIAL_WINDOW_SIZE - channel.flow.receive_window;
            channel.flow.receive_window = INITIAL_WINDOW_SIZE;
            write.encode(&ChannelWindowAdjust {
                recipient_channel: channel.flow.remote_id,
                bytes_to_add,
            })?;
        }

        debug!(len = %data.data.len(), "received channel data");
        Ok(match &mut session.terminal {
            Some(TerminalState::Running(terminal)) => Some((terminal, &data.data)),
            _ => None,
        })
    }

    pub(crate) fn eof(&mut self, eof: &ChannelEof) -> Result<(), ProtoError> {
        let Some(channel) = self.channels.get_mut(&eof.recipient_channel) else {
            return Err(ProtoError::InvalidPacket(
                "channel eof for unknown channel ID",
            ));
        };

        match &mut channel.kind {
            ChannelKind::Tcp(TcpConnection::Connecting(_)) => {
                return Err(ProtoError::InvalidPacket("channel EOF before confirmation"));
            }
            ChannelKind::Tcp(TcpConnection::Connected(forward))
                if forward.write_state == TcpWriteState::Open =>
            {
                forward.write_state = TcpWriteState::Draining;
            }
            _ => {}
        }

        debug!(channel_id = %eof.recipient_channel, "received channel eof from client");
        Ok(())
    }

    pub(crate) fn close(
        &mut self,
        close: &ChannelClose,
        write: &mut WriteState,
    ) -> Result<(), Error> {
        let Some(channel) = self.channels.get_mut(&close.recipient_channel) else {
            warn!(channel_id = %close.recipient_channel, "channel close for unknown channel ID");
            return Ok(());
        };

        if let ChannelKind::Tcp(tcp) = &mut channel.kind {
            if matches!(
                tcp.receive_close(&mut channel.flow, write)?,
                ChannelProgress::Remove
            ) {
                self.channels.remove(&close.recipient_channel);
            }
            return Ok(());
        }

        // Reply with our own close if we haven't sent one already.
        channel.flow.send_close(write)?;

        let ChannelKind::Session(session) = &mut channel.kind else {
            return Ok(());
        };

        // The client is no longer listening for output or exit status. Kill the shell,
        // but keep the channel around so the polling loop can reap the process before
        // the channel is dropped.
        match session.terminal.take() {
            Some(
                TerminalState::Running(mut terminal)
                | TerminalState::Exiting {
                    mut terminal,
                    deadline: _,
                },
            ) => {
                debug!(channel_id = %close.recipient_channel, "received channel close from client; killing shell");
                terminal.start_kill();
                session.terminal = Some(TerminalState::Reaping {
                    terminal,
                    deadline: Instant::now() + EXIT_GRACE_PERIOD,
                });
            }
            state @ Some(TerminalState::Reaping { .. }) => session.terminal = state,
            Some(
                TerminalState::Requested(_) | TerminalState::Exited(_) | TerminalState::Closing,
            )
            | None => {
                debug!(channel_id = %close.recipient_channel, "received channel close from client; removing");
                self.channels.remove(&close.recipient_channel);
            }
        }

        Ok(())
    }

    pub(crate) fn poll_io(
        &mut self,
        write: &mut WriteState,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Error>> {
        // NOTE: Terminal and TCP channels share this ascending local-ID scan.
        // Each poll stops at the first channel that makes progress. The 32 KiB
        // TCP read and 4 KiB write budgets bound a visit, but a continuously ready
        // lower-ID channel can still starve higher IDs. Fair scheduling would
        // resume after the last channel that made progress and wrap at the end.
        let mut remove = None;
        for (&local_id, channel) in &mut self.channels {
            let mut confirmation = channel.confirmation(local_id);
            let progress = match &mut channel.kind {
                ChannelKind::Session(session) => {
                    session.poll_io(local_id, &mut channel.flow, write, cx)
                }
                ChannelKind::Tcp(tcp) => {
                    tcp.poll_io(local_id, &mut confirmation, &mut channel.flow, write, cx)
                }
            };
            match progress {
                Poll::Ready(Ok(ChannelProgress::Keep)) => return Poll::Ready(Ok(())),
                Poll::Ready(Ok(ChannelProgress::Remove)) => {
                    remove = Some(local_id);
                    break;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {}
            }
        }
        if let Some(local_id) = remove {
            self.channels.remove(&local_id);
            return Poll::Ready(Ok(()));
        }
        Poll::Pending
    }
}

#[derive(Debug)]
pub(crate) struct Channel {
    flow: ChannelFlow,
    kind: ChannelKind,
}

#[derive(Debug)]
struct ChannelFlow {
    remote_id: u32,
    send_window: u32,
    receive_window: u32,
    maximum_packet_size: u32,
    close_sent: bool,
}

impl ChannelFlow {
    fn send_close(&mut self, write: &mut WriteState) -> Result<(), ProtoError> {
        if !self.close_sent {
            write.encode(&ChannelClose {
                recipient_channel: self.remote_id,
            })?;
            self.close_sent = true;
        }
        Ok(())
    }
}

impl Channel {
    fn confirmation(&self, local_id: u32) -> ChannelOpenConfirmation {
        ChannelOpenConfirmation {
            recipient_channel: self.flow.remote_id,
            sender_channel: local_id,
            initial_window_size: 0,
            maximum_packet_size: MAX_PACKET_LEN - 64, // Leave some room for packet overhead
        }
    }

    /// Spawn the user's shell on a new PTY and open the receive window for its input
    ///
    /// The shell runs `command` if there is one, and is an interactive login shell otherwise.
    fn start_terminal(
        &mut self,
        command: Option<&str>,
        pty_req: &PtyReq<'_>,
        write: &mut WriteState,
    ) -> Result<(), Error> {
        let ChannelKind::Session(session) = &mut self.kind else {
            return Err(Error::InvalidState("terminal requested on TCP channel"));
        };
        session.terminal = Some(TerminalState::Running(Terminal::spawn(
            command,
            pty_req,
            &session.env,
        )?));

        self.flow.receive_window = INITIAL_WINDOW_SIZE;
        write.encode(&ChannelWindowAdjust {
            recipient_channel: self.flow.remote_id,
            bytes_to_add: INITIAL_WINDOW_SIZE,
        })?;
        Ok(())
    }

    fn success(&self) -> ChannelRequestSuccess {
        ChannelRequestSuccess {
            recipient_channel: self.flow.remote_id,
        }
    }

    fn failure(&self) -> ChannelRequestFailure {
        ChannelRequestFailure {
            recipient_channel: self.flow.remote_id,
        }
    }
}

enum ChannelKind {
    // 11/24/2026 10:50 PM IST - TODO: Need to make sure Box is the right choice here. Agent says the reason being to make it compact, which does not make sense to me.
    Session(Box<SessionChannel>),
    Tcp(TcpConnection),
}

enum TcpConnection {
    Connecting(Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>>),
    Connected(TcpForward<TcpStream>),
    Closed,
}

impl TcpConnection {
    fn valid_destination(destination: &DirectTcpip<'_>, maximum_packet_size: u32) -> bool {
        !destination.host.is_empty()
            && destination.port <= u16::MAX as u32
            && destination.originator_port <= u16::MAX as u32
            && maximum_packet_size != 0
    }

    fn receive_close(
        &mut self,
        flow: &mut ChannelFlow,
        write: &mut WriteState,
    ) -> Result<ChannelProgress, Error> {
        match self {
            Self::Connecting(_) => {
                Err(ProtoError::InvalidPacket("channel close before confirmation").into())
            }
            Self::Connected(forward) if !forward.pending.is_empty() => {
                forward.client_close = true;
                Ok(ChannelProgress::Keep)
            }
            Self::Connected(_) | Self::Closed => {
                flow.send_close(write)?;
                Ok(ChannelProgress::Remove)
            }
        }
    }

    fn poll_io(
        &mut self,
        local_id: u32,
        confirmation: &mut ChannelOpenConfirmation,
        flow: &mut ChannelFlow,
        write: &mut WriteState,
        cx: &mut Context<'_>,
    ) -> Poll<Result<ChannelProgress, Error>> {
        match self {
            Self::Connecting(future) => match future.as_mut().poll(cx) {
                Poll::Ready(Ok(stream)) => {
                    *self = Self::Connected(TcpForward {
                        stream,
                        pending: VecDeque::new(),
                        tcp_eof: false,
                        write_state: TcpWriteState::Open,
                        client_close: false,
                    });
                    flow.receive_window = TCP_RECEIVE_WINDOW;
                    confirmation.initial_window_size = TCP_RECEIVE_WINDOW;
                    write.encode(confirmation)?;
                    Poll::Ready(Ok(ChannelProgress::Keep))
                }
                Poll::Ready(Err(error)) => {
                    debug!(channel = local_id, %error, "TCP connection failed");
                    write.encode(&ChannelOpenFailure::destination_failed(
                        confirmation.recipient_channel,
                    ))?;
                    Poll::Ready(Ok(ChannelProgress::Remove))
                }
                Poll::Pending => Poll::Pending,
            },
            Self::Connected(forward) => match forward.poll_io(flow, write, cx) {
                Poll::Ready(Err(Error::Io(error))) => {
                    debug!(channel = local_id, %error, "TCP socket I/O failed");
                    let client_close = forward.client_close;
                    flow.send_close(write)?;
                    *self = Self::Closed;
                    // TODO: but what if the write buffer hasn't been emptied out yet.
                    Poll::Ready(Ok(if client_close {
                        ChannelProgress::Remove
                    } else {
                        ChannelProgress::Keep
                    }))
                }
                Poll::Ready(Ok(ChannelProgress::Keep))
                    if forward.tcp_eof && forward.write_state == TcpWriteState::Shutdown =>
                {
                    flow.send_close(write)?;
                    *self = Self::Closed;
                    Poll::Ready(Ok(ChannelProgress::Keep))
                }
                result => result,
            },
            Self::Closed => Poll::Pending,
        }
    }
}

struct TcpForward<T> {
    stream: T,
    pending: VecDeque<u8>,
    tcp_eof: bool,
    write_state: TcpWriteState,
    client_close: bool,
}

#[derive(PartialEq)]
enum TcpWriteState {
    Open,
    Draining,
    Shutdown,
}

impl<T: AsyncRead + AsyncWrite + Unpin> TcpForward<T> {
    fn poll_io(
        &mut self,
        flow: &mut ChannelFlow,
        write: &mut WriteState,
        cx: &mut Context<'_>,
    ) -> Poll<Result<ChannelProgress, Error>> {
        // TODO: where is this future being exactly being awaited upon?
        let written = self.poll_write(flow, write, cx)?;
        if self.client_close {
            if !self.pending.is_empty() {
                return written.map(Ok);
            }
            flow.send_close(write)?;
            return Poll::Ready(Ok(ChannelProgress::Remove));
        }
        let read = self.poll_read(flow, write, cx)?;
        // TODO: isn't this a premise for select!
        // But are these cancel safe ?
        if written.is_ready() || read.is_ready() {
            Poll::Ready(Ok(ChannelProgress::Keep))
        } else {
            Poll::Pending
        }
    }

    fn poll_read(
        &mut self,
        flow: &mut ChannelFlow,
        write: &mut WriteState,
        cx: &mut Context<'_>,
    ) -> Poll<Result<ChannelProgress, Error>> {
        let limit = TCP_READ_LIMIT.min(flow.send_window.min(flow.maximum_packet_size) as usize);
        if self.tcp_eof || limit == 0 {
            return Poll::Pending;
        }
        let mut bytes = [0; TCP_READ_LIMIT];
        let mut buffer = ReadBuf::new(&mut bytes[..limit]);
        core::task::ready!(Pin::new(&mut self.stream).poll_read(cx, &mut buffer))?;
        let data = buffer.filled();
        if data.is_empty() {
            self.tcp_eof = true;
            write.encode(&ChannelEof {
                recipient_channel: flow.remote_id,
            })?;
            return Poll::Ready(Ok(ChannelProgress::Keep));
        }
        write.encode(&ChannelData {
            recipient_channel: flow.remote_id,
            data: Cow::Borrowed(data),
        })?;
        flow.send_window -= data.len() as u32;
        Poll::Ready(Ok(ChannelProgress::Keep))
    }

    fn poll_write(
        &mut self,
        flow: &mut ChannelFlow,
        write: &mut WriteState,
        cx: &mut Context<'_>,
    ) -> Poll<Result<ChannelProgress, Error>> {
        if self.pending.is_empty() {
            if self.write_state == TcpWriteState::Draining {
                core::task::ready!(Pin::new(&mut self.stream).poll_shutdown(cx))?;
                self.write_state = TcpWriteState::Shutdown;
                return Poll::Ready(Ok(ChannelProgress::Keep));
            }
            return Poll::Pending;
        }

        let (bytes, _) = self.pending.as_slices();
        let bytes = &bytes[..bytes.len().min(4096)];
        match Pin::new(&mut self.stream).poll_write(cx, bytes) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(0)) => {
                Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero).into()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
            Poll::Ready(Ok(count)) => {
                self.pending.drain(..count);
                // Sending message to adjust channel window if the SSH connection is active from the client side!
                if !self.client_close {
                    let count = count as u32;
                    flow.receive_window += count;
                    write.encode(&ChannelWindowAdjust {
                        recipient_channel: flow.remote_id,
                        bytes_to_add: count,
                    })?;
                }
                Poll::Ready(Ok(ChannelProgress::Keep))
            }
        }
    }
}

enum ChannelProgress {
    Keep,
    Remove,
}

impl fmt::Debug for ChannelKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(session) => f.debug_tuple("Session").field(session).finish(),
            Self::Tcp(TcpConnection::Connecting(_)) => f.write_str("Tcp(Connecting)"),
            Self::Tcp(TcpConnection::Connected(_)) => f.write_str("Tcp(Connected)"),
            Self::Tcp(TcpConnection::Closed) => f.write_str("Tcp(Closed)"),
        }
    }
}

#[derive(Debug, Default)]
struct SessionChannel {
    env: Vec<(String, String)>,
    terminal: Option<TerminalState>,
}

impl SessionChannel {
    fn poll_io(
        &mut self,
        local_id: u32,
        flow: &mut ChannelFlow,
        write: &mut WriteState,
        cx: &mut Context<'_>,
    ) -> Poll<Result<ChannelProgress, Error>> {
        let Some(state) = &mut self.terminal else {
            return Poll::Pending;
        };

        let terminal = loop {
            match state {
                TerminalState::Running(terminal) => break terminal,
                TerminalState::Requested(_) => return Poll::Pending,
                TerminalState::Exiting { terminal, deadline } => match terminal.poll_wait(cx) {
                    Poll::Ready(Ok(status)) => {
                        *state = match status.code() {
                            Some(code) => TerminalState::Exited(code as u32),
                            None => TerminalState::Closing,
                        };
                    }
                    Poll::Ready(Err(error)) => {
                        warn!(%error, "error waiting for shell to exit");
                        *state = TerminalState::Closing;
                    }
                    // No waker is registered for the deadline, so an expired
                    // grace period is only noticed on the next poll (driven by
                    // connection traffic).
                    Poll::Pending if Instant::now() < *deadline => return Poll::Pending,
                    Poll::Pending => {
                        warn!(
                            channel = local_id,
                            "shell did not exit after PTY EOF; killing"
                        );
                        // Stay in `Exiting`: once the kill takes effect the shell
                        // becomes reapable and the `Poll::Ready` arms above reap it
                        // and forward its (signal) status.
                        terminal.start_kill();
                        return Poll::Pending;
                    }
                },
                TerminalState::Exited(status) => {
                    let request = ChannelRequest {
                        recipient_channel: flow.remote_id,
                        r#type: ChannelRequestType::ExitStatus(*status),
                        want_reply: false,
                    };

                    *state = TerminalState::Closing;
                    if !flow.close_sent {
                        write.encode(&request)?;
                        return Poll::Ready(Ok(ChannelProgress::Keep));
                    }
                }
                TerminalState::Reaping { terminal, deadline } => match terminal.poll_wait(cx) {
                    Poll::Ready(result) => {
                        match result {
                            Ok(_) => {
                                debug!(channel = local_id, "reaped killed shell; removing channel")
                            }
                            Err(error) => {
                                warn!(%error, "error reaping killed shell; removing channel")
                            }
                        }
                        return Poll::Ready(Ok(ChannelProgress::Remove));
                    }
                    // See `Exiting`: the deadline has no waker of its own.
                    Poll::Pending if Instant::now() < *deadline => return Poll::Pending,
                    Poll::Pending => {
                        warn!(
                            channel = local_id,
                            "killed shell did not exit; removing channel"
                        );
                        return Poll::Ready(Ok(ChannelProgress::Remove));
                    }
                },
                TerminalState::Closing => {
                    if flow.close_sent {
                        return Poll::Pending;
                    }

                    flow.close_sent = true;
                    write.encode(&ChannelClose {
                        recipient_channel: flow.remote_id,
                    })?;
                    return Poll::Ready(Ok(ChannelProgress::Keep));
                }
            }
        };

        let mut buf = [0u8; 4096];
        let limit = Ord::min(flow.maximum_packet_size, flow.send_window) as usize;
        let writable = match limit {
            0 => return Poll::Pending,
            _ if limit < buf.len() => &mut buf[..limit],
            _ => &mut buf,
        };

        match terminal.poll_read(writable, cx) {
            // The PTY can report EOF slightly before the shell becomes reapable, so
            // hold the channel open until the shell has been waited on; its exit
            // status must reach the client before the channel close. PTY EOF only
            // means all user fds were closed, not that the shell exited, so bound
            // the wait with a grace period after which the shell is killed.
            Poll::Ready(Ok(0)) => {
                if let TerminalState::Running(terminal) =
                    mem::replace(state, TerminalState::Closing)
                {
                    *state = TerminalState::Exiting {
                        terminal,
                        deadline: Instant::now() + EXIT_GRACE_PERIOD,
                    };
                }

                write.encode(&ChannelEof {
                    recipient_channel: flow.remote_id,
                })?;
                Poll::Ready(Ok(ChannelProgress::Keep))
            }
            Poll::Ready(Err(error)) => {
                terminal.start_kill();
                warn!(%error, "error reading from terminal");
                Poll::Ready(Err(error.into()))
            }
            Poll::Ready(Ok(n)) => {
                flow.send_window = flow.send_window.saturating_sub(n as u32);
                write.encode(&ChannelData {
                    recipient_channel: flow.remote_id,
                    data: Cow::Borrowed(&buf[..n]),
                })?;
                Poll::Ready(Ok(ChannelProgress::Keep))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

enum TerminalState {
    Requested(PtyReq<'static>),
    Running(Terminal),
    /// Waiting to reap the exited shell, until the deadline
    Exiting {
        terminal: Terminal,
        deadline: Instant,
    },
    /// Shell exited with the given status, which still needs to be sent
    Exited(u32),
    /// Client closed the channel; reap the killed shell (until the deadline), then drop the channel
    Reaping {
        terminal: Terminal,
        deadline: Instant,
    },
    Closing,
}

impl fmt::Debug for TerminalState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Requested(req) => f.debug_tuple("Requested").field(req).finish(),
            Self::Running(_) => f.debug_tuple("Running").field(&"...").finish(),
            Self::Exiting {
                terminal: _,
                deadline,
            } => f.debug_tuple("Exiting").field(deadline).finish(),
            Self::Exited(status) => f.debug_tuple("Exited").field(status).finish(),
            Self::Reaping {
                terminal: _,
                deadline,
            } => f.debug_tuple("Reaping").field(deadline).finish(),
            Self::Closing => f.debug_tuple("Closing").finish(),
        }
    }
}

#[derive(Debug)]
pub(crate) enum IncomingChannelMessage<'a> {
    Open(ChannelOpen<'a>),
    Request(ChannelRequest<'a>),
    Data(ChannelData<'a>),
    WindowAdjust(ChannelWindowAdjust),
    Eof(ChannelEof),
    Close(ChannelClose),
}

impl<'a> TryFrom<IncomingPacket<'a>> for IncomingChannelMessage<'a> {
    type Error = ProtoError;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        match packet.message_type {
            MessageType::ChannelOpen => {
                Ok(IncomingChannelMessage::Open(ChannelOpen::try_from(packet)?))
            }
            MessageType::ChannelRequest => Ok(IncomingChannelMessage::Request(
                ChannelRequest::try_from(packet)?,
            )),
            MessageType::ChannelData => {
                Ok(IncomingChannelMessage::Data(ChannelData::try_from(packet)?))
            }
            MessageType::ChannelWindowAdjust => Ok(IncomingChannelMessage::WindowAdjust(
                ChannelWindowAdjust::try_from(packet)?,
            )),
            MessageType::ChannelEof => {
                Ok(IncomingChannelMessage::Eof(ChannelEof::try_from(packet)?))
            }
            MessageType::ChannelClose => Ok(IncomingChannelMessage::Close(ChannelClose::try_from(
                packet,
            )?)),
            _ => Err(ProtoError::UnexpectedMessage(
                packet.message_type,
                &[
                    MessageType::ChannelOpen,
                    MessageType::ChannelRequest,
                    MessageType::ChannelData,
                    MessageType::ChannelWindowAdjust,
                    MessageType::ChannelEof,
                    MessageType::ChannelClose,
                ],
            )),
        }
    }
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const TCP_RECEIVE_WINDOW: u32 = 64 * 1024;
const TCP_READ_LIMIT: usize = 32 * 1024;

const INITIAL_WINDOW_SIZE: u32 = 16 * MAX_PACKET_LEN;
/// How long to wait for a shell to become reapable after its PTY reports EOF
/// or after it is killed
const EXIT_GRACE_PERIOD: Duration = Duration::from_secs(5);

/// Environment variable holding the command requested by the client when a forced command runs
const ORIGINAL_COMMAND_ENV: &str = "SSH_ORIGINAL_COMMAND";

/// Maximum number of environment variables allowed
const MAX_ENV_VARIABLE_COUNT: usize = 128;
/// Maximum length of an environment variable name
const MAX_ENV_VARIABLE_NAME_LEN: usize = 256;
/// Maximum length of an environment variable value
const MAX_ENV_VARIABLE_VALUE_LEN: usize = 16 * 1024;

/// Maximum number of open channels per session
const MAX_OPEN_CHANNELS_PER_SESSION: usize = 256;

#[cfg(test)]
mod tests {
    use proto::channels::{ChannelType, DirectTcpip};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn tcp_peer_close_drains_queued_data_before_reply() -> anyhow::Result<()> {
        let mut channels = Channels::default();
        let mut write = WriteState::new(crate::DEFAULT_PROVIDER.secure_random());
        let mut peer = open_tcp_channel(&mut channels, &mut write).await?;
        let payload = vec![7; 5000];
        channels.data(
            &ChannelData {
                recipient_channel: 0,
                data: Cow::Borrowed(&payload),
            },
            &mut write,
        )?;
        let close = ChannelClose {
            recipient_channel: 0,
        };
        channels.close(&close, &mut write)?;
        channels.data(
            &ChannelData {
                recipient_channel: 0,
                data: Cow::Borrowed(b"late"),
            },
            &mut write,
        )?;
        assert!(write.buffered().is_empty());

        poll_channels(&mut channels, &mut write).await?;
        assert!(channels.channels.contains_key(&0));
        assert!(write.buffered().is_empty());
        poll_channels(&mut channels, &mut write).await?;
        assert!(channels.channels.is_empty());
        assert_single_close(&write);

        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), peer.read_to_end(&mut received)).await??;
        assert_eq!(received, payload);
        Ok(())
    }

    #[tokio::test]
    async fn tcp_peer_close_waits_for_a_blocked_write_to_drain() {
        let (mut socket, mut peer) = tokio::io::duplex(1);
        socket.write_all(b"x").await.unwrap();
        peer.write_all(b"y").await.unwrap();
        let mut forward = TcpForward {
            stream: socket,
            pending: VecDeque::from(vec![b'z']),
            tcp_eof: false,
            write_state: TcpWriteState::Open,
            client_close: true,
        };
        let mut flow = ChannelFlow {
            remote_id: 42,
            send_window: 32_768,
            receive_window: TCP_RECEIVE_WINDOW - 1,
            maximum_packet_size: 32_768,
            close_sent: false,
        };
        let mut write = WriteState::new(crate::DEFAULT_PROVIDER.secure_random());
        assert!(
            core::future::poll_fn(|cx| Poll::Ready(forward.poll_io(&mut flow, &mut write, cx)))
                .await
                .is_pending()
        );
        assert_eq!(forward.pending.len(), 1);
        assert!(write.buffered().is_empty());

        assert_eq!(peer.read_u8().await.unwrap(), b'x');
        let progress = tokio::time::timeout(
            Duration::from_secs(5),
            core::future::poll_fn(|cx| forward.poll_io(&mut flow, &mut write, cx)),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(progress, ChannelProgress::Remove));
        assert!(forward.pending.is_empty());
        assert_eq!(peer.read_u8().await.unwrap(), b'z');
        assert_eq!(flow.send_window, 32_768);
        assert_eq!(flow.receive_window, TCP_RECEIVE_WINDOW - 1);
        assert_single_close(&write);
    }

    #[tokio::test]
    async fn tcp_crossed_close_releases_id_without_a_second_reply() -> anyhow::Result<()> {
        let mut channels = Channels::default();
        let mut write = WriteState::new(crate::DEFAULT_PROVIDER.secure_random());
        let mut peer = open_tcp_channel(&mut channels, &mut write).await?;
        peer.shutdown().await?;
        poll_channels(&mut channels, &mut write).await?;
        assert_eq!(write.buffered()[5], u8::from(MessageType::ChannelEof));
        write.clear();
        channels.eof(&ChannelEof {
            recipient_channel: 0,
        })?;
        poll_channels(&mut channels, &mut write).await?;
        assert_single_close(&write);
        assert!(matches!(
            channels.channels[&0].kind,
            ChannelKind::Tcp(TcpConnection::Closed)
        ));
        write.clear();
        channels.close(
            &ChannelClose {
                recipient_channel: 0,
            },
            &mut write,
        )?;
        assert!(channels.channels.is_empty());
        assert!(write.buffered().is_empty());

        channels.next_id = 0;
        let _peer = open_tcp_channel(&mut channels, &mut write).await?;
        assert!(channels.channels.contains_key(&0));
        Ok(())
    }

    #[tokio::test]
    async fn tcp_socket_error_leaves_other_channels_usable() -> anyhow::Result<()> {
        let mut channels = Channels::default();
        let mut write = WriteState::new(crate::DEFAULT_PROVIDER.secure_random());
        let peer = open_tcp_channel(&mut channels, &mut write).await?;
        let mut other_peer = open_tcp_channel(&mut channels, &mut write).await?;
        rustix::net::sockopt::set_socket_linger(&peer, Some(Duration::ZERO))?;
        drop(peer);
        poll_channels(&mut channels, &mut write).await?;
        assert_single_close(&write);
        assert!(matches!(
            channels.channels[&0].kind,
            ChannelKind::Tcp(TcpConnection::Closed)
        ));
        write.clear();
        other_peer.write_all(b"ok").await?;
        poll_channels(&mut channels, &mut write).await?;
        assert_eq!(write.buffered()[5], u8::from(MessageType::ChannelData));
        assert_eq!(&write.buffered()[6..10], &43u32.to_be_bytes());
        assert_eq!(&write.buffered()[14..16], b"ok");
        Ok(())
    }

    #[tokio::test]
    async fn tcp_disconnect_drops_pending_connects_and_established_sockets() -> anyhow::Result<()> {
        let mut channels = Channels::default();
        let mut write = WriteState::new(crate::DEFAULT_PROVIDER.secure_random());
        let mut peer = open_tcp_channel(&mut channels, &mut write).await?;
        let (connect_guard, dropped) = tokio::sync::oneshot::channel::<()>();
        channels.channels.insert(
            1,
            Channel {
                flow: ChannelFlow {
                    remote_id: 43,
                    send_window: 32_768,
                    receive_window: 0,
                    maximum_packet_size: 32_768,
                    close_sent: false,
                },
                kind: ChannelKind::Tcp(TcpConnection::Connecting(Box::pin(async move {
                    let _guard = connect_guard;
                    core::future::pending().await
                }))),
            },
        );
        assert!(
            core::future::poll_fn(|cx| Poll::Ready(channels.poll_io(&mut write, cx)))
                .await
                .is_pending()
        );
        drop(channels);
        assert!(dropped.await.is_err());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), peer.read(&mut [0])).await??,
            0
        );
        Ok(())
    }

    async fn open_tcp_channel(
        channels: &mut Channels,
        write: &mut WriteState,
    ) -> anyhow::Result<TcpStream> {
        let target = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
        channels.open(
            ChannelOpen {
                r#type: ChannelType::DirectTcpip(DirectTcpip {
                    host: "127.0.0.1",
                    port: target.local_addr()?.port().into(),
                    originator_address: "127.0.0.1",
                    originator_port: 0,
                }),
                sender_channel: 42 + channels.next_id,
                initial_window_size: 32_768,
                maximum_packet_size: 32_768,
            },
            write,
        )?;
        poll_channels(channels, write).await?;
        assert_eq!(
            write.buffered()[5],
            u8::from(MessageType::ChannelOpenConfirmation)
        );
        write.clear();
        Ok(target.accept().await?.0)
    }

    async fn poll_channels(channels: &mut Channels, write: &mut WriteState) -> anyhow::Result<()> {
        tokio::time::timeout(
            Duration::from_secs(5),
            core::future::poll_fn(|cx| channels.poll_io(write, cx)),
        )
        .await??;
        Ok(())
    }

    fn assert_single_close(write: &WriteState) {
        let packet = write.buffered();
        let len = u32::from_be_bytes(packet[..4].try_into().unwrap()) as usize;
        assert_eq!(packet.len(), 4 + len);
        assert_eq!(packet[5], u8::from(MessageType::ChannelClose));
        assert_eq!(&packet[6..10], &42u32.to_be_bytes());
    }

    #[tokio::test]
    async fn tcp_write_shutdown_waits_for_pending_bytes() {
        let (socket, mut peer) = tokio::io::duplex(3);
        let mut forward = TcpForward {
            stream: socket,
            pending: VecDeque::from(b"request".to_vec()),
            tcp_eof: false,
            write_state: TcpWriteState::Draining,
            client_close: false,
        };
        let mut flow = ChannelFlow {
            remote_id: 42,
            send_window: 32_768,
            receive_window: TCP_RECEIVE_WINDOW - 7,
            maximum_packet_size: 32_768,
            close_sent: false,
        };
        let mut write = WriteState::new(crate::DEFAULT_PROVIDER.secure_random());
        core::future::poll_fn(|cx| forward.poll_write(&mut flow, &mut write, cx))
            .await
            .unwrap();
        assert_eq!(forward.pending.len(), 4);
        assert!(matches!(forward.write_state, TcpWriteState::Draining));
        assert!(
            core::future::poll_fn(|cx| Poll::Ready(forward.poll_write(&mut flow, &mut write, cx)))
                .await
                .is_pending()
        );

        let drain = async {
            while forward.write_state != TcpWriteState::Shutdown {
                core::future::poll_fn(|cx| forward.poll_write(&mut flow, &mut write, cx))
                    .await
                    .unwrap();
            }
        };
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(drain, peer.read_to_end(&mut received))
                .1
                .unwrap()
        })
        .await
        .unwrap();
        assert_eq!(received, b"request");
        assert_eq!(flow.receive_window, TCP_RECEIVE_WINDOW);

        write.clear();
        peer.write_all(b"res").await.unwrap();
        core::future::poll_fn(|cx| forward.poll_read(&mut flow, &mut write, cx))
            .await
            .unwrap();
        assert_eq!(&write.buffered()[14..17], b"res");
    }

    #[tokio::test]
    async fn tcp_read_respects_visit_budget_window_and_packet_size() {
        let payload = vec![7; TCP_READ_LIMIT + 1];
        for (window, packet_size, expected) in [
            (65_536, 65_536, 32 * 1024),
            (512, 32_768, 512),
            (32_768, 256, 256),
        ] {
            let (socket, mut peer) = tokio::io::duplex(payload.len());
            peer.write_all(&payload).await.unwrap();
            let mut forward = TcpForward {
                stream: socket,
                pending: VecDeque::new(),
                tcp_eof: false,
                write_state: TcpWriteState::Open,
                client_close: false,
            };
            let mut flow = ChannelFlow {
                remote_id: 42,
                send_window: window,
                receive_window: TCP_RECEIVE_WINDOW,
                maximum_packet_size: packet_size,
                close_sent: false,
            };
            let mut write = WriteState::new(crate::DEFAULT_PROVIDER.secure_random());
            core::future::poll_fn(|cx| forward.poll_read(&mut flow, &mut write, cx))
                .await
                .unwrap();
            assert_eq!(flow.send_window, window - expected);
            let packet = write.buffered();
            assert_eq!(packet[5], u8::from(MessageType::ChannelData));
            assert_eq!(&packet[6..10], &42u32.to_be_bytes());
            assert_eq!(&packet[10..14], &expected.to_be_bytes());
            assert_eq!(
                &packet[14..14 + expected as usize],
                &payload[..expected as usize]
            );
        }
    }

    #[tokio::test]
    async fn tcp_poll_reads_while_socket_write_is_blocked() {
        let (mut socket, mut peer) = tokio::io::duplex(4);
        socket.write_all(b"full").await.unwrap();
        peer.write_all(b"read").await.unwrap();
        let mut forward = TcpForward {
            stream: socket,
            pending: VecDeque::from(vec![1]),
            tcp_eof: false,
            write_state: TcpWriteState::Open,
            client_close: false,
        };
        let mut flow = ChannelFlow {
            remote_id: 42,
            send_window: 4,
            receive_window: TCP_RECEIVE_WINDOW - 1,
            maximum_packet_size: 32_768,
            close_sent: false,
        };
        let mut write = WriteState::new(crate::DEFAULT_PROVIDER.secure_random());
        let progress =
            core::future::poll_fn(|cx| Poll::Ready(forward.poll_io(&mut flow, &mut write, cx)))
                .await;
        assert!(matches!(progress, Poll::Ready(Ok(ChannelProgress::Keep))));
        assert_eq!(forward.pending.len(), 1);
        assert_eq!(flow.receive_window, TCP_RECEIVE_WINDOW - 1);
        assert_eq!(flow.send_window, 0);
        assert_eq!(&write.buffered()[14..18], b"read");
    }

    #[tokio::test]
    async fn tcp_read_resumes_after_window_adjustment() -> anyhow::Result<()> {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
        let stream = TcpStream::connect(listener.local_addr()?).await?;
        let (mut peer, _) = listener.accept().await?;
        peer.write_all(b"reply").await?;
        stream.readable().await?;
        let mut channels = Channels::default();
        channels.channels.insert(
            0,
            Channel {
                flow: ChannelFlow {
                    remote_id: 42,
                    send_window: 0,
                    receive_window: TCP_RECEIVE_WINDOW,
                    maximum_packet_size: 32_768,
                    close_sent: false,
                },
                kind: ChannelKind::Tcp(TcpConnection::Connected(TcpForward {
                    stream,
                    pending: VecDeque::new(),
                    tcp_eof: false,
                    write_state: TcpWriteState::Open,
                    client_close: false,
                })),
            },
        );
        let mut write = WriteState::new(crate::DEFAULT_PROVIDER.secure_random());
        assert!(
            core::future::poll_fn(|cx| Poll::Ready(channels.poll_io(&mut write, cx)))
                .await
                .is_pending()
        );
        assert!(write.buffered().is_empty());
        channels.adjust_window(&ChannelWindowAdjust {
            recipient_channel: 0,
            bytes_to_add: 1,
        })?;
        tokio::time::timeout(
            Duration::from_secs(5),
            core::future::poll_fn(|cx| channels.poll_io(&mut write, cx)),
        )
        .await??;
        assert_eq!(write.buffered()[5], u8::from(MessageType::ChannelData));
        assert_eq!(&write.buffered()[10..14], &1u32.to_be_bytes());
        assert_eq!(write.buffered()[14], b'r');
        assert_eq!(channels.channels[&0].flow.send_window, 0);
        Ok(())
    }

    #[tokio::test]
    async fn tcp_channel_refuses_pty_requests() -> anyhow::Result<()> {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
        let mut channels = Channels::default();
        let mut write = WriteState::new(crate::DEFAULT_PROVIDER.secure_random());
        channels.open(
            ChannelOpen {
                r#type: ChannelType::DirectTcpip(DirectTcpip {
                    host: "127.0.0.1",
                    port: listener.local_addr()?.port().into(),
                    originator_address: "127.0.0.1",
                    originator_port: 0,
                }),
                sender_channel: 42,
                initial_window_size: 0,
                maximum_packet_size: 32_768,
            },
            &mut write,
        )?;
        tokio::time::timeout(
            Duration::from_secs(5),
            core::future::poll_fn(|cx| channels.poll_io(&mut write, cx)),
        )
        .await??;
        write.clear();

        for want_reply in [false, true] {
            channels.request(
                ChannelRequest {
                    recipient_channel: 0,
                    r#type: ChannelRequestType::PtyReq(PtyReq {
                        term: Cow::Borrowed("xterm"),
                        cols: 80,
                        rows: 24,
                        width_px: 0,
                        height_px: 0,
                        terminal_modes: BTreeMap::new(),
                    }),
                    want_reply,
                },
                &mut write,
                None,
                &KeyOptions::default(),
            )?;
            if want_reply {
                assert_eq!(write.buffered()[5], u8::from(MessageType::ChannelFailure));
                assert_eq!(&write.buffered()[6..10], &42u32.to_be_bytes());
            } else {
                assert!(write.buffered().is_empty());
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn tcp_write_is_limited_to_four_kib_per_poll() {
        let (socket, _peer) = tokio::io::duplex(8192);
        let mut forward = TcpForward {
            stream: socket,
            pending: VecDeque::from(vec![7; 6000]),
            tcp_eof: false,
            write_state: TcpWriteState::Open,
            client_close: false,
        };
        let mut flow = ChannelFlow {
            remote_id: 1,
            send_window: 0,
            receive_window: TCP_RECEIVE_WINDOW - 6000,
            maximum_packet_size: 32768,
            close_sent: false,
        };
        let mut write = WriteState::new(crate::DEFAULT_PROVIDER.secure_random());
        core::future::poll_fn(|cx| forward.poll_write(&mut flow, &mut write, cx))
            .await
            .unwrap();
        assert_eq!(forward.pending.len(), 6000 - 4096);
        assert_eq!(flow.receive_window, TCP_RECEIVE_WINDOW - 6000 + 4096);
        assert_eq!(&write.buffered()[10..14], &4096u32.to_be_bytes());
    }

    #[tokio::test]
    async fn tcp_write_preserves_partial_data_and_credits_only_written_bytes() {
        let (socket, mut peer) = tokio::io::duplex(3);
        let mut forward = TcpForward {
            stream: socket,
            pending: VecDeque::from(b"abcdefgh".to_vec()),
            tcp_eof: false,
            write_state: TcpWriteState::Open,
            client_close: false,
        };
        let mut flow = ChannelFlow {
            remote_id: 42,
            send_window: 0,
            receive_window: TCP_RECEIVE_WINDOW - 8,
            maximum_packet_size: 32768,
            close_sent: false,
        };
        let mut write = WriteState::new(crate::DEFAULT_PROVIDER.secure_random());
        core::future::poll_fn(|cx| forward.poll_write(&mut flow, &mut write, cx))
            .await
            .unwrap();
        assert_eq!(
            forward.pending.iter().copied().collect::<Vec<_>>(),
            b"defgh"
        );
        assert_eq!(flow.receive_window, TCP_RECEIVE_WINDOW - 5);
        assert_eq!(
            write.buffered()[5],
            u8::from(MessageType::ChannelWindowAdjust)
        );
        assert_eq!(&write.buffered()[6..10], &42u32.to_be_bytes());
        assert_eq!(&write.buffered()[10..14], &3u32.to_be_bytes());
        let previous_size = write.buffered().len();
        assert!(
            core::future::poll_fn(|cx| Poll::Ready(forward.poll_write(&mut flow, &mut write, cx)))
                .await
                .is_pending()
        );
        assert_eq!(write.buffered().len(), previous_size);
        assert_eq!(flow.receive_window, TCP_RECEIVE_WINDOW - 5);

        let mut received = [0; 8];
        peer.read_exact(&mut received[..3]).await.unwrap();
        core::future::poll_fn(|cx| forward.poll_write(&mut flow, &mut write, cx))
            .await
            .unwrap();
        assert_eq!(
            &write.buffered()[previous_size + 10..previous_size + 14],
            &3u32.to_be_bytes()
        );
        peer.read_exact(&mut received[3..6]).await.unwrap();
        let previous_size = write.buffered().len();
        core::future::poll_fn(|cx| forward.poll_write(&mut flow, &mut write, cx))
            .await
            .unwrap();
        assert_eq!(
            &write.buffered()[previous_size + 10..previous_size + 14],
            &2u32.to_be_bytes()
        );
        peer.read_exact(&mut received[6..]).await.unwrap();
        assert_eq!(&received, b"abcdefgh");
        assert!(forward.pending.is_empty());
        assert_eq!(flow.receive_window, TCP_RECEIVE_WINDOW);
    }

    #[tokio::test]
    async fn tcp_data_in_flight_after_close_is_ignored() {
        let mut channels = Channels::default();
        channels.channels.insert(
            0,
            Channel {
                flow: ChannelFlow {
                    remote_id: 1,
                    send_window: 0,
                    receive_window: 3,
                    maximum_packet_size: 32768,
                    close_sent: true,
                },
                kind: ChannelKind::Tcp(TcpConnection::Closed),
            },
        );
        let mut write = WriteState::new(crate::DEFAULT_PROVIDER.secure_random());
        let data = ChannelData {
            recipient_channel: 0,
            data: Cow::Borrowed(b"abc"),
        };
        assert!(channels.data(&data, &mut write).unwrap().is_none());
        assert!(write.buffered().is_empty());
        assert_eq!(channels.channels.get(&0).unwrap().flow.receive_window, 3);
    }

    #[tokio::test]
    async fn tcp_data_rejects_oversized_packet_and_exhausted_window() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (_peer, _) = listener.accept().await.unwrap();
        let mut channels = Channels::default();
        channels.channels.insert(
            0,
            Channel {
                flow: ChannelFlow {
                    remote_id: 1,
                    send_window: 0,
                    receive_window: 3,
                    maximum_packet_size: 32768,
                    close_sent: false,
                },
                kind: ChannelKind::Tcp(TcpConnection::Connected(TcpForward {
                    stream,
                    pending: VecDeque::new(),
                    tcp_eof: false,
                    write_state: TcpWriteState::Open,
                    client_close: false,
                })),
            },
        );
        let mut write = WriteState::new(crate::DEFAULT_PROVIDER.secure_random());
        for data in [vec![0; 4], vec![0; (MAX_PACKET_LEN - 64 + 1) as usize]] {
            assert!(
                channels
                    .data(
                        &ChannelData {
                            recipient_channel: 0,
                            data: Cow::Owned(data),
                        },
                        &mut write
                    )
                    .is_err()
            );
        }
        let channel = channels.channels.get(&0).unwrap();
        assert_eq!(channel.flow.receive_window, 3);
        assert!(
            matches!(&channel.kind, ChannelKind::Tcp(TcpConnection::Connected(forward)) if forward.pending.is_empty())
        );
        assert!(write.buffered().is_empty());
    }

    #[tokio::test]
    async fn invalid_tcp_open_does_not_reserve_a_channel() {
        let mut channels = Channels::default();
        let mut write = WriteState::new(crate::DEFAULT_PROVIDER.secure_random());
        for (host, port, originator_port, maximum_packet_size) in [
            ("", 22, 1, 32768),
            ("localhost", 65536, 1, 32768),
            ("localhost", 22, 65536, 32768),
            ("localhost", 22, 1, 0),
        ] {
            let start = write.buffered().len();
            channels
                .open(
                    ChannelOpen {
                        r#type: ChannelType::DirectTcpip(DirectTcpip {
                            host,
                            port,
                            originator_address: "127.0.0.1",
                            originator_port,
                        }),
                        sender_channel: 7,
                        initial_window_size: 0,
                        maximum_packet_size,
                    },
                    &mut write,
                )
                .unwrap();
            assert!(channels.channels.is_empty());
            let packet = &write.buffered()[start..];
            assert_eq!(packet[5], u8::from(MessageType::ChannelOpenFailure));
            assert_eq!(&packet[10..14], &1u32.to_be_bytes());
        }
        assert!(!write.buffered().is_empty());
    }

    #[tokio::test]
    async fn duplicate_sender_does_not_reserve_second_channel() {
        let mut channels = Channels::default();
        let mut write = WriteState::new(crate::DEFAULT_PROVIDER.secure_random());
        channels
            .open(
                ChannelOpen {
                    r#type: ChannelType::Session,
                    sender_channel: 7,
                    initial_window_size: 0,
                    maximum_packet_size: 32768,
                },
                &mut write,
            )
            .unwrap();
        channels
            .open(
                ChannelOpen {
                    r#type: ChannelType::DirectTcpip(DirectTcpip {
                        host: "127.0.0.1",
                        port: 22,
                        originator_address: "127.0.0.1",
                        originator_port: 0,
                    }),
                    sender_channel: 7,
                    initial_window_size: 0,
                    maximum_packet_size: 32768,
                },
                &mut write,
            )
            .unwrap();
        assert_eq!(channels.channels.len(), 1);
        assert!(matches!(
            channels.channels.get(&0).unwrap().kind,
            ChannelKind::Session(_)
        ));
    }

    #[tokio::test]
    async fn pending_tcp_connect_keeps_session_available_and_releases_slot_on_timeout() {
        let mut channels = Channels::default();
        let future = Box::pin(async {
            tokio::time::timeout(Duration::from_millis(20), core::future::pending())
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))
        });
        channels.channels.insert(
            0,
            Channel {
                flow: ChannelFlow {
                    remote_id: 1,
                    send_window: 0,
                    receive_window: 0,
                    maximum_packet_size: 32768,
                    close_sent: false,
                },
                kind: ChannelKind::Tcp(TcpConnection::Connecting(future)),
            },
        );
        channels.next_id = 1;
        let mut write = WriteState::new(crate::DEFAULT_PROVIDER.secure_random());
        assert!(
            core::future::poll_fn(|cx| Poll::Ready(channels.poll_io(&mut write, cx)))
                .await
                .is_pending()
        );
        assert!(write.buffered().is_empty());

        channels
            .open(
                ChannelOpen {
                    r#type: ChannelType::Session,
                    sender_channel: 2,
                    initial_window_size: 0,
                    maximum_packet_size: 32768,
                },
                &mut write,
            )
            .unwrap();
        let before = write.buffered().len();
        core::future::poll_fn(|cx| channels.poll_io(&mut write, cx))
            .await
            .unwrap();
        assert!(write.buffered().len() > before);
        assert!(!channels.channels.contains_key(&0));
        assert!(channels.channels.contains_key(&1));
    }
}
