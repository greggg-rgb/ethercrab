//! Items to use when not in `no_std` environments.

#[cfg(all(not(target_os = "linux"), unix))]
mod bpf;
#[cfg(target_os = "linux")]
mod linux;

#[cfg(all(not(target_os = "linux"), unix))]
use self::bpf::BpfDevice as RawSocketDesc;
#[cfg(target_os = "linux")]
pub(in crate::std) use self::linux::RawSocketDesc;

use crate::{
    error::Error,
    fmt,
    pdu_loop::{PduRx, PduTx},
};
use async_io::Async;
use core::{future::Future, pin::Pin, task::Poll};
use futures_lite::{AsyncRead, AsyncWrite};

/// Counts frames the TX/RX loop dropped, logging the 1st, 2nd, 4th, 8th... one.
///
/// A burst of drops (late replies after a cable replug, sends while the link is down) must not
/// flood the log from the TX/RX thread.
#[derive(Debug, Default)]
struct DropLog {
    count: u64,
}

impl DropLog {
    /// Counts one drop and returns the running count when this one should be logged.
    fn due(&mut self) -> Option<u64> {
        self.count += 1;

        self.count.is_power_of_two().then_some(self.count)
    }

    fn note(&mut self, what: &str, e: Error) {
        if let Some(count) = self.due() {
            fmt::warn!("{} failed, frame dropped ({} so far): {}", what, count, e);
        }
    }
}

/// Hands one received packet to the PDU loop, dropping it if it matches no in-flight frame.
///
/// A late reply to a frame that already timed out is normal on a real network, for example right
/// after a cable is plugged back in. It must not end the TX/RX task: the task's `PduTx`/`PduRx`
/// would be lost with it and the MainDevice could never communicate again.
fn receive_packet(rx: &mut PduRx<'_>, packet: &[u8], drops: &mut DropLog) {
    if let Err(e) = rx.receive_frame(packet) {
        drops.note("Receive frame", e);
    }
}

struct TxRxFut<'a> {
    socket: Async<RawSocketDesc>,
    mtu: usize,
    tx_drops: DropLog,
    rx_drops: DropLog,
    tx: Option<PduTx<'a>>,
    rx: Option<PduRx<'a>>,
}

impl<'a> Future for TxRxFut<'a> {
    type Output = Result<(PduTx<'a>, PduRx<'a>), Error>;

    fn poll(mut self: Pin<&mut Self>, ctx: &mut core::task::Context<'_>) -> Poll<Self::Output> {
        unsafe {
            // Re-register waker to make sure this future is polled again
            self.tx
                .as_mut()
                .unwrap_unchecked()
                .replace_waker(ctx.waker());

            if self.tx.as_mut().unwrap_unchecked().should_exit() {
                fmt::debug!("TX/RX future was asked to exit");

                return Poll::Ready(Ok((
                    self.tx.take().unwrap().release(),
                    self.rx.take().unwrap().release(),
                )));
            }
        }

        let this = &mut *self;

        while let Some(frame) = unsafe { this.tx.as_mut().unwrap_unchecked() }.next_sendable_frame()
        {
            // Only recorded here: while the link is down every send fails, and logging each one
            // from the TX/RX thread would flood the log.
            let mut os_error = None;

            let res = frame.send_blocking(|data| {
                match Pin::new(&mut this.socket).poll_write(ctx, data) {
                    Poll::Ready(Ok(bytes_written)) if bytes_written != data.len() => {
                        Err(Error::PartialSend {
                            len: data.len(),
                            sent: bytes_written,
                        })
                    }
                    Poll::Ready(Ok(bytes_written)) => Ok(bytes_written),
                    Poll::Ready(Err(e)) => {
                        os_error = Some(e);

                        Err(Error::SendFrame)
                    }
                    Poll::Pending => Ok(0),
                }
            });

            if let Err(e) = res {
                // `send_blocking` put the frame back as sendable. Retry it on the next poll
                // instead of spinning here; if sending keeps failing, the frame's own timeout
                // reports it lost. Ending the task would lose `PduTx`/`PduRx` for good.
                if let Some(count) = this.tx_drops.due() {
                    match os_error {
                        Some(os) => fmt::warn!(
                            "Send frame failed, frame dropped ({} so far): {}",
                            count,
                            os
                        ),
                        None => {
                            fmt::warn!("Send frame failed, frame dropped ({} so far): {}", count, e)
                        }
                    }
                }

                break;
            }
        }

        let mut buf = vec![0; self.mtu];

        match Pin::new(&mut self.socket).poll_read(ctx, &mut buf) {
            Poll::Ready(Ok(n)) => {
                fmt::trace!("Poll ready");
                // Wake again in case there are more frames to consume. This is additionally
                // important for macOS as multiple packets may be received for one `poll_read`
                // call, but will only be returned during the _next_ `poll_read`. If this line
                // is removed, PDU response frames are missed, causing timeout errors.
                ctx.waker().wake_by_ref();

                let packet = buf.get(0..n).ok_or(Error::Internal)?;

                if n == 0 {
                    fmt::warn!("Received zero bytes");
                }

                let this = &mut *self;

                receive_packet(
                    unsafe { this.rx.as_mut().unwrap_unchecked() },
                    packet,
                    &mut this.rx_drops,
                );
            }
            Poll::Ready(Err(e)) => {
                fmt::error!("Receive PDU failed: {}", e);
            }
            Poll::Pending => (),
        }

        Poll::Pending
    }
}

/// Spawn a TX and RX task.
pub fn tx_rx_task<'sto>(
    interface: &str,
    pdu_tx: PduTx<'sto>,
    #[allow(unused_mut)] mut pdu_rx: PduRx<'sto>,
) -> Result<impl Future<Output = Result<(PduTx<'sto>, PduRx<'sto>), Error>> + 'sto, std::io::Error>
{
    let mut socket = RawSocketDesc::new(interface)?;

    // macOS forcibly sets the source address to the NIC's MAC, so instead of using `MASTER_ADDR`
    // for filtering returned packets, we must set the address to compare to the NIC MAC.
    #[cfg(all(not(target_os = "linux"), unix))]
    if let Some(mac) = socket.mac().ok().flatten() {
        fmt::debug!("Setting source MAC to {}", mac);

        pdu_rx.set_source_mac(mac);
    }

    let mtu = socket.interface_mtu()?;

    fmt::debug!("Opening {} with MTU {}", interface, mtu);

    let async_socket = Async::new(socket)?;

    let task = TxRxFut {
        socket: async_socket,
        mtu,
        tx_drops: DropLog::default(),
        rx_drops: DropLog::default(),
        tx: Some(pdu_tx),
        rx: Some(pdu_rx),
    };

    Ok(task)
}

/// Get the current time in nanoseconds from the EtherCAT epoch, 2000-01-01.
///
/// On POSIX systems, this function uses the monotonic clock provided by the system.
pub fn ethercat_now() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time);
    };

    let t = (time.tv_sec as u64) * 1_000_000_000 + (time.tv_nsec as u64);

    // EtherCAT epoch is 2000-01-01
    t.saturating_sub(946684800)
}

// Unix only
#[allow(trivial_numeric_casts)]
fn ifreq_for(name: &str) -> ifreq {
    let mut ifreq = ifreq {
        ifr_name: [0; libc::IF_NAMESIZE],
        ifr_data: 0,
    };
    for (i, byte) in name.as_bytes().iter().enumerate() {
        ifreq.ifr_name[i] = *byte as libc::c_char;
    }
    ifreq
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
struct ifreq {
    ifr_name: [libc::c_char; libc::IF_NAMESIZE],
    ifr_data: libc::c_int, /* ifr_ifindex or ifr_mtu */
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Command, PduStorage, timer_factory::MAX_TIMEOUT};
    use core::{future::poll_fn, pin::pin};

    /// An FPWR reply carrying `pdu_index`, as a SubDevice returns it to the MainDevice.
    fn reply(pdu_index: u8) -> [u8; 32] {
        [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Broadcast address
            0x12, 0x10, 0x10, 0x10, 0x10, 0x10, // Return to master address
            0x88, 0xa4, // EtherCAT ethertype
            0x10, 0x10,      // EtherCAT frame header: type PDU, length 4 (plus header)
            0x05,      // Command: FPWR
            pdu_index, // PDU index
            0x89, 0x67, // SubDevice address
            0x34, 0x12, // Register address
            0x04, 0x00, // Flags, 4 byte length
            0x00, 0x00, // IRQ
            0xdd, 0xcc, 0xbb, 0xaa, // Payload, LE
            0x00, 0x00, // Working counter
        ]
    }

    #[test]
    fn drop_log_is_due_on_powers_of_two_only() {
        let mut drops = DropLog::default();
        let due: Vec<u64> = (0..9).filter_map(|_| drops.due()).collect();
        assert_eq!(due, [1, 2, 4, 8]);
        assert_eq!(drops.count, 9);
    }

    #[test]
    fn stale_reply_is_dropped_and_the_next_reply_still_completes_its_frame() {
        crate::test_logger();

        let storage = PduStorage::<1, 128>::new();
        let (mut tx, mut rx, pdu_loop) = storage.try_split().unwrap();
        let mut drops = DropLog::default();

        let poller = poll_fn(|ctx| {
            let mut frame = pdu_loop.alloc_frame().unwrap();
            frame
                .push_pdu(
                    Command::fpwr(0x6789, 0x1234).into(),
                    0xAABBCCDDu32.to_le_bytes(),
                    None,
                )
                .expect("Push PDU");
            let mut frame_fut = pin!(frame.mark_sendable(&pdu_loop, MAX_TIMEOUT, usize::MAX));
            assert!(frame_fut.as_mut().poll(ctx).is_pending());
            let sendable = tx.next_sendable_frame().expect("need a frame");
            sendable
                .send_blocking(|bytes| Ok(bytes.len()))
                .expect("send");

            // A late reply to some earlier, timed-out frame: no frame is waiting on index 7.
            receive_packet(&mut rx, &reply(7), &mut drops);
            assert_eq!(drops.count, 1);

            receive_packet(&mut rx, &reply(0), &mut drops);
            assert_eq!(drops.count, 1, "the real reply is not a drop");
            assert!(
                matches!(frame_fut.poll(ctx), Poll::Ready(Ok(_))),
                "the in-flight frame still gets its reply"
            );
            Poll::Ready(())
        });

        cassette::block_on(poller);
    }
}
