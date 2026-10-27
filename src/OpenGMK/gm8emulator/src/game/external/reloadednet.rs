//! `reloadednet.dll` emulated in-engine, for the Pokémon Reloaded multiplayer mod.
//!
//! The Windows build of the game loads a real `reloadednet.dll` (32-bit C, ws2_32); on platforms
//! without native externals (Android) the same API is answered here, so the game's GML is
//! identical everywhere. Wire format: TCP, one peer, each message = u32 LE length + bytes.
//!
//!   rn_host(port) -> 1/0          rn_join(ip, port) -> 1/0 (connects in the background)
//!   rn_status() -> 0 off, 1 waiting, 2 connected, -1 error/lost
//!   rn_send(msg) -> 1/0           rn_recv() -> next complete message or ""
//!   rn_local_ip() -> string       rn_close() -> 1
//!
//! Nothing here blocks the game loop: sockets are non-blocking and the outgoing connect runs on
//! a helper thread whose result is picked up by the next call.

use super::dll;
use crate::{
    game::Game,
    gml::{self, network, Function, Value},
};
use std::{
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

const MAX_MSG: usize = 65536;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

const ST_OFF: i32 = 0;
const ST_WAIT: i32 = 1;
const ST_CONN: i32 = 2;
const ST_ERR: i32 = -1;

type PendingConnect = Arc<Mutex<Option<std::io::Result<TcpStream>>>>;

struct Net {
    listener: Option<TcpListener>,
    peer: Option<TcpStream>,
    pending: Option<PendingConnect>,
    state: i32,
    inbuf: Vec<u8>,
    outbuf: Vec<u8>,
}

static NET: Mutex<Net> =
    Mutex::new(Net { listener: None, peer: None, pending: None, state: ST_OFF, inbuf: Vec::new(), outbuf: Vec::new() });

/// Maps `external_define("...reloadednet.dll", symbol, ...)` to the emulated function, if any.
pub fn lookup(signature: &dll::ExternalSignature) -> Option<Function> {
    // The game passes a Windows path ("data\net\reloadednet.dll"); on Android `Path` does not treat
    // '\' as a separator, so split on both by hand.
    let dll = signature.dll.rsplit(|c| c == '/' || c == '\\').next().unwrap_or(&signature.dll);
    if !dll.eq_ignore_ascii_case("reloadednet.dll") {
        return None
    }
    let f: fn(&Game, &[Value]) -> gml::Result<Value> = match signature.symbol.as_str() {
        "rn_host" => rn_host,
        "rn_join" => rn_join,
        "rn_status" => rn_status,
        "rn_send" => rn_send,
        "rn_recv" => rn_recv,
        "rn_local_ip" => rn_local_ip,
        "rn_close" => rn_close,
        _ => return None,
    };
    Some(Function::Volatile(f))
}

fn arg_real(args: &[Value], i: usize) -> i32 {
    match args.get(i) {
        Some(v @ Value::Real(_)) => v.round(),
        _ => 0,
    }
}

fn arg_bytes(args: &[Value], i: usize) -> Vec<u8> {
    match args.get(i) {
        Some(Value::Str(s)) => AsRef::<[u8]>::as_ref(s).to_vec(),
        _ => Vec::new(),
    }
}

impl Net {
    fn close(&mut self) {
        self.listener = None;
        self.peer = None;
        self.pending = None;
        self.inbuf.clear();
        self.outbuf.clear();
        self.state = ST_OFF;
    }

    fn lose_peer(&mut self) {
        self.peer = None;
        self.pending = None;
        self.inbuf.clear();
        self.outbuf.clear();
        // The host goes back to waiting for another player; a guest stays in error until it retries.
        self.state = if self.listener.is_some() { ST_WAIT } else { ST_ERR };
    }

    /// Accepts a peer, finishes a background connect, flushes and reads whatever is available.
    fn pump(&mut self) {
        if self.state == ST_WAIT && self.peer.is_none() {
            let accepted = self.listener.as_ref().and_then(|listener| listener.accept().ok());
            if let Some((stream, _)) = accepted {
                self.attach(stream);
            }
            let connected = self.pending.as_ref().and_then(|pending| pending.lock().ok().and_then(|mut slot| slot.take()));
            match connected {
                Some(Ok(stream)) => {
                    self.pending = None;
                    self.attach(stream);
                },
                Some(Err(_)) => self.lose_peer(),
                None => (),
            }
        }
        if self.state != ST_CONN {
            return
        }
        let mut lost = false;
        if let Some(peer) = self.peer.as_mut() {
            while !self.outbuf.is_empty() {
                match peer.write(&self.outbuf) {
                    Ok(0) => {
                        lost = true;
                        break
                    },
                    Ok(n) => {
                        self.outbuf.drain(..n);
                    },
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(_) => {
                        lost = true;
                        break
                    },
                }
            }
            let mut chunk = [0u8; 4096];
            while !lost {
                match peer.read(&mut chunk) {
                    Ok(0) => lost = true,
                    Ok(n) => self.inbuf.extend_from_slice(&chunk[..n]),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(_) => lost = true,
                }
            }
        }
        if lost {
            self.lose_peer();
        }
    }

    fn attach(&mut self, stream: TcpStream) {
        if stream.set_nonblocking(true).is_err() {
            self.lose_peer();
            return
        }
        let _ = stream.set_nodelay(true);
        self.peer = Some(stream);
        self.inbuf.clear();
        self.outbuf.clear();
        self.state = ST_CONN;
    }

    fn next_message(&mut self) -> Vec<u8> {
        if self.inbuf.len() < 4 {
            return Vec::new()
        }
        let len = u32::from_le_bytes([self.inbuf[0], self.inbuf[1], self.inbuf[2], self.inbuf[3]]) as usize;
        if len > MAX_MSG {
            self.lose_peer();
            return Vec::new()
        }
        if self.inbuf.len() < 4 + len {
            return Vec::new()
        }
        let msg = self.inbuf[4..4 + len].to_vec();
        self.inbuf.drain(..4 + len);
        msg
    }
}

fn with_net<T>(f: impl FnOnce(&mut Net) -> T) -> T {
    let mut net = NET.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    f(&mut net)
}

pub fn rn_host(_: &Game, args: &[Value]) -> gml::Result<Value> {
    let port = arg_real(args, 0) as u16;
    Ok(with_net(|net| {
        net.close();
        match TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port))) {
            Ok(listener) if listener.set_nonblocking(true).is_ok() => {
                net.listener = Some(listener);
                net.state = ST_WAIT;
                1
            },
            _ => {
                net.state = ST_ERR;
                0
            },
        }
    })
    .into())
}

pub fn rn_join(_: &Game, args: &[Value]) -> gml::Result<Value> {
    let ip = String::from_utf8_lossy(&arg_bytes(args, 0)).trim().to_string();
    let port = arg_real(args, 1) as u16;
    Ok(with_net(|net| {
        net.close();
        let addr = match ip.parse::<std::net::IpAddr>() {
            Ok(ip) => SocketAddr::new(ip, port),
            Err(_) => {
                net.state = ST_ERR;
                return 0
            },
        };
        let slot: PendingConnect = Arc::new(Mutex::new(None));
        let worker = Arc::clone(&slot);
        thread::spawn(move || {
            let result = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT);
            if let Ok(mut out) = worker.lock() {
                *out = Some(result);
            }
        });
        net.pending = Some(slot);
        net.state = ST_WAIT;
        1
    })
    .into())
}

pub fn rn_status(_: &Game, _args: &[Value]) -> gml::Result<Value> {
    Ok(with_net(|net| {
        net.pump();
        net.state
    })
    .into())
}

pub fn rn_send(_: &Game, args: &[Value]) -> gml::Result<Value> {
    let msg = arg_bytes(args, 0);
    Ok(with_net(|net| {
        if net.state != ST_CONN || msg.len() > MAX_MSG {
            return 0
        }
        net.outbuf.extend_from_slice(&(msg.len() as u32).to_le_bytes());
        net.outbuf.extend_from_slice(&msg);
        net.pump();
        1
    })
    .into())
}

pub fn rn_recv(_: &Game, _args: &[Value]) -> gml::Result<Value> {
    Ok(with_net(|net| {
        net.pump();
        net.next_message()
    })
    .into())
}

pub fn rn_local_ip(_: &Game, _args: &[Value]) -> gml::Result<Value> {
    Ok(network::get_local_ip().unwrap_or(std::net::Ipv4Addr::LOCALHOST.into()).to_string().into())
}

pub fn rn_close(_: &Game, _args: &[Value]) -> gml::Result<Value> {
    with_net(|net| net.close());
    Ok(1.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signature(dll: &str, symbol: &str) -> dll::ExternalSignature {
        dll::ExternalSignature {
            dll: dll.into(),
            symbol: symbol.into(),
            call_conv: dll::CallConv::Cdecl,
            type_args: vec![],
            type_return: dll::ValueType::Real,
        }
    }

    /// The game defines the functions with a Windows path; it must be recognised on every platform.
    #[test]
    fn lookup_accepts_windows_and_unix_paths() {
        assert!(lookup(&signature("data\\net\\reloadednet.dll", "rn_host")).is_some());
        assert!(lookup(&signature("data/net/ReloadedNet.DLL", "rn_status")).is_some());
        assert!(lookup(&signature("reloadednet.dll", "rn_local_ip")).is_some());
        assert!(lookup(&signature("data\\net\\reloadednet.dll", "rn_unknown")).is_none());
        assert!(lookup(&signature("gmfmodsimple.dll", "rn_host")).is_none());
    }

    /// Two `Net`s in one process: host on loopback, peer connects, messages cross both ways.
    #[test]
    fn loopback_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut host = Net { listener: Some(listener), peer: None, pending: None, state: ST_WAIT, inbuf: vec![], outbuf: vec![] };
        let mut guest = Net { listener: None, peer: None, pending: None, state: ST_WAIT, inbuf: vec![], outbuf: vec![] };
        let slot: PendingConnect = Arc::new(Mutex::new(None));
        *slot.lock().unwrap() = Some(TcpStream::connect(("127.0.0.1", port)));
        guest.pending = Some(slot);

        for _ in 0..200 {
            host.pump();
            guest.pump();
            if host.state == ST_CONN && guest.state == ST_CONN {
                break
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!((host.state, guest.state), (ST_CONN, ST_CONN));

        let big = vec![b'A'; 60000];
        for msg in [b"ola".to_vec(), b"R1|22|100|200".to_vec(), big] {
            guest.outbuf.extend_from_slice(&(msg.len() as u32).to_le_bytes());
            guest.outbuf.extend_from_slice(&msg);
            let mut got = Vec::new();
            for _ in 0..400 {
                guest.pump();
                host.pump();
                got = host.next_message();
                if !got.is_empty() {
                    break
                }
                thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(got, msg);
        }

        // The guest leaves: the host must go back to waiting and accept a new player.
        drop(guest);
        for _ in 0..200 {
            host.pump();
            if host.state == ST_WAIT {
                break
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(host.state, ST_WAIT);

        let mut second = Net { listener: None, peer: None, pending: None, state: ST_WAIT, inbuf: vec![], outbuf: vec![] };
        let slot: PendingConnect = Arc::new(Mutex::new(None));
        *slot.lock().unwrap() = Some(TcpStream::connect(("127.0.0.1", port)));
        second.pending = Some(slot);
        for _ in 0..200 {
            host.pump();
            second.pump();
            if host.state == ST_CONN && second.state == ST_CONN {
                break
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!((host.state, second.state), (ST_CONN, ST_CONN));
    }
}
