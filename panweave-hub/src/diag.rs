//! Structured diagnostics: typed records in a bounded ring buffer.
//!
//! The hub never formats diagnostic text. Each noteworthy step — a boot
//! milestone, a join stage, an interview request and its answer, an IAS
//! Zone notification, a storage failure — becomes a [`DiagRecord`]: a
//! category, a severity, a stable [`code`], and the identifiers that apply
//! (device, network address, endpoint, cluster, transaction number,
//! status, one argument). Records are filtered by severity and category
//! *before* they are queued ([`TraceConfig`]) and kept in a [`DiagLog`] of
//! fixed capacity, compacted to 32 octets each. Hosts page through it
//! with sequence numbers: a gap in the sequence is a record that was
//! dropped, and [`DiagLog::dropped`] counts them.
//!
//! When the log is full a new record replaces the oldest record of the
//! same or lower severity; when every stored record is more severe, the
//! new record is dropped. Low-priority records give way first, and a
//! flood of debug records never pushes errors out. Nothing here blocks,
//! allocates or touches flash. No record ever carries key material.

use heapless::Vec;

/// Record severities, least severe first.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Severity {
    /// Fine-grained steps (every request of an interview).
    Trace,
    /// Steps useful when debugging one device.
    Debug,
    /// Normal milestones (a device joined, an interview finished).
    Info,
    /// Something degraded but handled (a timeout, a refused step).
    Warning,
    /// A failure (storage error, a command failed).
    Error,
    /// A failure that impairs the hub (network not restored).
    Critical,
}

impl Severity {
    /// The wire code.
    pub const fn code(self) -> u8 {
        match self {
            Severity::Trace => 0,
            Severity::Debug => 1,
            Severity::Info => 2,
            Severity::Warning => 3,
            Severity::Error => 4,
            Severity::Critical => 5,
        }
    }

    /// The severity of a wire code (`None` for unknown codes).
    pub const fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            0 => Severity::Trace,
            1 => Severity::Debug,
            2 => Severity::Info,
            3 => Severity::Warning,
            4 => Severity::Error,
            5 => Severity::Critical,
            _ => return None,
        })
    }

    /// A short name.
    pub const fn name(self) -> &'static str {
        match self {
            Severity::Trace => "trace",
            Severity::Debug => "debug",
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
            Severity::Critical => "critical",
        }
    }

    /// The severity named `name`.
    pub fn parse(name: &str) -> Option<Self> {
        (0..=5)
            .filter_map(Self::from_code)
            .find(|s| s.name().eq_ignore_ascii_case(name))
    }
}

/// Record categories.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Category {
    /// The diagnostics machinery itself.
    System,
    /// Boot and restoration.
    Boot,
    /// The USB link and protocol session.
    Usb,
    /// The radio driver.
    Radio,
    /// The MAC service.
    Mac,
    /// The NWK layer.
    Nwk,
    /// The APS layer.
    Aps,
    /// Trust Center join and key milestones.
    TrustCenter,
    /// Permit-join windows, joins, rejoins and departures.
    Commissioning,
    /// ZDP transactions.
    Zdo,
    /// ZCL transactions and host commands.
    Zcl,
    /// Device interviews.
    Interview,
    /// IAS Zone enrolment and notifications.
    IasZone,
    /// Registry and stack storage.
    Persistence,
    /// The watchdog.
    Watchdog,
    /// Queues, loop timing and other resources.
    Resources,
}

impl Category {
    /// Every category, in code order.
    pub const ALL: [Category; 16] = [
        Category::System,
        Category::Boot,
        Category::Usb,
        Category::Radio,
        Category::Mac,
        Category::Nwk,
        Category::Aps,
        Category::TrustCenter,
        Category::Commissioning,
        Category::Zdo,
        Category::Zcl,
        Category::Interview,
        Category::IasZone,
        Category::Persistence,
        Category::Watchdog,
        Category::Resources,
    ];

    /// The wire code (also the bit of the category in a mask).
    pub const fn code(self) -> u8 {
        match self {
            Category::System => 0,
            Category::Boot => 1,
            Category::Usb => 2,
            Category::Radio => 3,
            Category::Mac => 4,
            Category::Nwk => 5,
            Category::Aps => 6,
            Category::TrustCenter => 7,
            Category::Commissioning => 8,
            Category::Zdo => 9,
            Category::Zcl => 10,
            Category::Interview => 11,
            Category::IasZone => 12,
            Category::Persistence => 13,
            Category::Watchdog => 14,
            Category::Resources => 15,
        }
    }

    /// The category of a wire code.
    pub const fn from_code(c: u8) -> Option<Self> {
        if (c as usize) < Self::ALL.len() {
            Some(Self::ALL[c as usize])
        } else {
            None
        }
    }

    /// The category's bit in a mask.
    pub const fn bit(self) -> u32 {
        1 << self.code()
    }

    /// A short name.
    pub const fn name(self) -> &'static str {
        match self {
            Category::System => "system",
            Category::Boot => "boot",
            Category::Usb => "usb",
            Category::Radio => "radio",
            Category::Mac => "mac",
            Category::Nwk => "nwk",
            Category::Aps => "aps",
            Category::TrustCenter => "trust-center",
            Category::Commissioning => "commissioning",
            Category::Zdo => "zdo",
            Category::Zcl => "zcl",
            Category::Interview => "interview",
            Category::IasZone => "ias-zone",
            Category::Persistence => "persistence",
            Category::Watchdog => "watchdog",
            Category::Resources => "resources",
        }
    }

    /// The category named `name`.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|c| c.name().eq_ignore_ascii_case(name))
    }
}

/// Mask enabling every category.
pub const ALL_CATEGORIES: u32 = 0xffff;

/// Record codes. Codes are stable across releases; the high octet groups
/// them by subsystem. Field use per code is documented on each constant
/// (`ieee`, `short`, `endpoint`, `cluster`, `tsn`, `status`, `arg`).
pub mod code {
    // System.
    /// The trace was cleared (`arg`: records removed).
    pub const TRACE_CLEARED: u16 = 0x0001;
    /// The trace configuration changed (`arg`: category mask, `status`:
    /// minimum severity).
    pub const TRACE_CONFIGURED: u16 = 0x0002;
    /// Frame capture started (`arg`: seconds).
    pub const CAPTURE_STARTED: u16 = 0x0003;
    /// Frame capture stopped (`status`: 0 request, 1 time limit).
    pub const CAPTURE_STOPPED: u16 = 0x0004;

    // Boot.
    /// Boot completed (`arg`: milliseconds from reset to the main loop).
    pub const BOOT_COMPLETED: u16 = 0x0101;
    /// The Zigbee network was resumed from flash.
    pub const NETWORK_RESTORED: u16 = 0x0102;
    /// A new network was formed.
    pub const NETWORK_FORMED: u16 = 0x0103;
    /// Reading the stack's storage failed; no network was formed
    /// (`status`: storage error).
    pub const NETWORK_RESTORE_FAILED: u16 = 0x0104;
    /// The stack's storage held corrupt records and no network; none was
    /// formed automatically (`arg`: corrupt records).
    pub const NETWORK_NOT_FORMED: u16 = 0x0105;
    /// The registry was restored (`arg`: devices).
    pub const REGISTRY_RESTORED: u16 = 0x0106;
    /// The registry has no storage and lives in RAM only.
    pub const REGISTRY_RAM_ONLY: u16 = 0x0107;
    /// The partition table has a problem (`status`: finding kind, `arg`:
    /// partition index).
    pub const PARTITION_PROBLEM: u16 = 0x0108;
    /// Network formation failed.
    pub const FORMATION_FAILED: u16 = 0x0109;
    /// The stack's storage holds a network this firmware cannot use
    /// (`status`: 3 half written, 4 unknown format, 5 undecodable); it
    /// was left untouched.
    pub const NETWORK_RECORD_UNUSABLE: u16 = 0x010a;
    /// Reading the stack's storage was retried (`arg`: attempts so far;
    /// `status`: 0 still unreadable, 1 restored, 2 gave up).
    pub const NETWORK_RESTORE_RETRY: u16 = 0x010b;
    /// Last startup stage retained across a warm reset; status is StartupStage.
    pub const PREVIOUS_BOOT_STAGE: u16 = 0x010c;

    // USB.
    /// Queued output was dropped: the host took nothing for too long
    /// (`arg`: octets).
    pub const USB_OUTPUT_DISCARDED: u16 = 0x0201;
    /// A frame failed its CRC or COBS check.
    pub const USB_FRAME_CORRUPT: u16 = 0x0202;
    /// A frame exceeded the maximum size.
    pub const USB_FRAME_OVERSIZE: u16 = 0x0203;
    /// A frame did not decode as a request (`status`: error code).
    pub const USB_REQUEST_REJECTED: u16 = 0x0204;
    /// A request needed more access than the session has (`arg`: request
    /// identifier).
    pub const USB_UNAUTHORIZED: u16 = 0x0205;
    /// A response was dropped for lack of room.
    pub const USB_RESPONSE_DROPPED: u16 = 0x0206;

    // Radio.
    /// The driver never reported the outcome of a transmission.
    pub const RADIO_TX_FAULT: u16 = 0x0301;
    /// A channel or configuration change was refused (`arg`: channel).
    pub const RADIO_CONFIG_ERROR: u16 = 0x0302;
    /// The watchdog supervisor suspects a stall and attempted the safe
    /// recovery (`status`: cause, 1 radio driver, 2 stack progress;
    /// `arg`: milliseconds since the radio's last progress).
    pub const STALL_SUSPECTED: u16 = 0x0303;
    /// The stall persisted after the recovery (`status`: cause; `arg`: 1
    /// when the watchdog is no longer fed, 0 when escalation is disabled
    /// for this boot because it followed a watchdog reset).
    pub const STALL_CONFIRMED: u16 = 0x0304;
    /// The previous boot ended in a supervisor-requested watchdog reset
    /// (`status`: cause; `arg`: its uptime in seconds).
    pub const PREVIOUS_STALL_RESET: u16 = 0x0305;

    // NWK.
    /// A unicast was refused: all pending slots in use (`arg`: slots held
    /// for sleepy children).
    pub const NWK_PENDING_FULL: u16 = 0x0501;

    // Trust Center (`ieee`, `short` when known).
    /// MAC association request (`status`: capability octet).
    pub const JOIN_ASSOCIATION_REQUEST: u16 = 0x0701;
    /// The NWK layer accepted a child (`status`: 0 secured rejoin, 1
    /// unsecured join, 3 Trust Center rejoin).
    pub const JOIN_CHILD_JOINED: u16 = 0x0702;
    /// A router reported the device (`status`: Update Device status).
    pub const JOIN_UPDATE_DEVICE: u16 = 0x0703;
    /// The Trust Center decided (`status`: 0 negotiate key, 1 transport
    /// key, 2 allow, 3 ignore, 4 remove).
    pub const JOIN_DECISION: u16 = 0x0704;
    /// The network key was sent.
    pub const JOIN_KEY_SENT: u16 = 0x0705;
    /// The network key transport was acknowledged.
    pub const JOIN_KEY_DELIVERED: u16 = 0x0706;
    /// The network key transport failed (`status`: APS status).
    pub const JOIN_KEY_FAILED: u16 = 0x0707;
    /// The device requested its Trust Center link key (`status`: 1
    /// granted, 0 refused).
    pub const JOIN_TCLK_REQUESTED: u16 = 0x0708;
    /// The device verified its Trust Center link key.
    pub const JOIN_TCLK_VERIFIED: u16 = 0x0709;
    /// Join milestones were lost before the hub read them (`arg`:
    /// count).
    pub const JOIN_TRACE_LOST: u16 = 0x070a;
    /// The device holds the network key and must complete the required
    /// key exchange within `bdbTrustCenterNodeJoinTimeout`.
    pub const JOIN_KEY_EXCHANGE_PENDING: u16 = 0x070b;
    /// The key-exchange window passed: the device's link key was removed
    /// and the device asked to leave.
    pub const JOIN_KEY_EXCHANGE_TIMEOUT: u16 = 0x070c;
    /// The device is authorized (`status`: 1 only through an
    /// administrator exemption).
    pub const JOIN_AUTHORIZED: u16 = 0x070d;
    /// The device joined again through the unauthenticated path; its
    /// earlier admission without the key exchange was withdrawn.
    pub const JOIN_EXEMPTION_WITHDRAWN: u16 = 0x070e;

    // Commissioning.
    /// The network opened for joining (`arg`: seconds).
    pub const PERMIT_JOIN_OPENED: u16 = 0x0801;
    /// The network closed for joining.
    pub const PERMIT_JOIN_CLOSED: u16 = 0x0802;
    /// The Trust Center stopped admitting new devices (grace ended).
    pub const JOINS_REFUSED_AGAIN: u16 = 0x0803;
    /// The Trust Center authorized a device.
    pub const DEVICE_AUTHORIZED: u16 = 0x0804;
    /// Device_annce received (`status`: MAC capability).
    pub const DEVICE_ANNOUNCED: u16 = 0x0805;
    /// A known device came back.
    pub const DEVICE_REJOINED: u16 = 0x0806;
    /// A device left the network.
    pub const DEVICE_LEFT: u16 = 0x0807;
    /// A device was refused: the registry is full.
    pub const REGISTRY_FULL: u16 = 0x0808;
    /// A device's network address changed (`arg`: old address).
    pub const ADDRESS_CHANGED: u16 = 0x0809;
    /// A device the registry did not know was heard and registered.
    pub const DEVICE_DISCOVERED: u16 = 0x080a;
    /// A device without application access announced itself or is in
    /// the registry; it is not interviewed (`status`: its
    /// `DeviceAuthorization` code).
    pub const DEVICE_NOT_AUTHORIZED: u16 = 0x080b;
    /// An administrator exempted a device from the key exchange
    /// (`arg`: joining window, seconds).
    pub const KEY_EXCHANGE_EXEMPTION_GRANTED: u16 = 0x080c;
    /// An exemption was revoked.
    pub const KEY_EXCHANGE_EXEMPTION_REVOKED: u16 = 0x080d;
    /// An exemption window passed without the device joining.
    pub const KEY_EXCHANGE_EXEMPTION_EXPIRED: u16 = 0x080e;
    /// A device joined under an exemption; the exemption is kept with it.
    pub const KEY_EXCHANGE_EXEMPTION_USED: u16 = 0x080f;

    // ZDO.
    /// A ZDP request was not answered in time (`cluster`: request).
    pub const ZDP_TIMEOUT: u16 = 0x0901;

    // ZCL and host commands (`arg`: command identifier).
    /// A Default Response with an error status (`cluster`, `status`).
    pub const ZCL_DEFAULT_RESPONSE_ERROR: u16 = 0x0a01;
    /// A read attribute status record with an error (`cluster`,
    /// `status`, `arg`: attribute).
    pub const ZCL_ATTRIBUTE_ERROR: u16 = 0x0a02;
    /// Configure Reporting refused for an attribute (`cluster`,
    /// `status`, `arg`: attribute).
    pub const ZCL_REPORTING_REFUSED: u16 = 0x0a03;
    /// A host command was sent.
    pub const COMMAND_SENT: u16 = 0x0a04;
    /// A host command was answered.
    pub const COMMAND_RESPONDED: u16 = 0x0a05;
    /// A host command's result was read back.
    pub const COMMAND_CONFIRMED: u16 = 0x0a06;
    /// A host command timed out.
    pub const COMMAND_TIMEOUT: u16 = 0x0a07;
    /// A host command failed (`status`: ZCL / ZDP status).
    pub const COMMAND_FAILED: u16 = 0x0a08;
    /// A host command was sent again after a timeout.
    pub const COMMAND_RETRY: u16 = 0x0a09;
    /// An unsupported cluster-specific command arrived (`cluster`,
    /// `arg`: command).
    pub const ZCL_UNSUPPORTED_COMMAND: u16 = 0x0a0a;
    /// A Poll Control Check-in was answered (`status`: 1 fast poll
    /// requested, 0 not; `arg`: fast-poll timeout in quarter seconds).
    pub const POLL_CHECK_IN: u16 = 0x0a0b;
    /// Fast Poll Stop was sent: the hub had nothing more for the device.
    pub const FAST_POLL_STOP: u16 = 0x0a0c;

    // Interview (`arg`: stage << 8 | step).
    /// An interview started or restarted.
    pub const INTERVIEW_STARTED: u16 = 0x0b01;
    /// An interview request was sent (`tsn`, `cluster`, `endpoint`;
    /// `status`: attempt).
    pub const INTERVIEW_REQUEST: u16 = 0x0b02;
    /// An interview request was answered (`status`: 0 or the refusal).
    pub const INTERVIEW_ANSWER: u16 = 0x0b03;
    /// An interview request timed out (`status`: attempt).
    pub const INTERVIEW_TIMEOUT: u16 = 0x0b04;
    /// An optional step was skipped (`status`: ZCL/ZDP status, 0xff for a
    /// timeout).
    pub const INTERVIEW_STEP_SKIPPED: u16 = 0x0b05;
    /// A mandatory stage ran out of attempts: the interview stalls.
    pub const INTERVIEW_STALLED: u16 = 0x0b06;
    /// A stalled interview resumed (the device was heard).
    pub const INTERVIEW_RESUMED: u16 = 0x0b07;
    /// The interview finished (`status`: 1 partial).
    pub const INTERVIEW_COMPLETED: u16 = 0x0b08;
    /// The stack could not take an interview request; it is retried.
    pub const INTERVIEW_SEND_DEFERRED: u16 = 0x0b09;

    // IAS Zone (`endpoint` of the zone).
    /// The zone's attributes were read (`arg`: zone type, `status`: zone
    /// state).
    pub const IAS_ZONE_READ: u16 = 0x0c01;
    /// The hub wrote itself as the CIE.
    pub const IAS_CIE_WRITTEN: u16 = 0x0c02;
    /// Zone Enroll Request received (`arg`: zone type).
    pub const IAS_ENROLL_REQUEST: u16 = 0x0c03;
    /// Zone Enroll Response sent in answer (`status`: response code,
    /// `arg`: zone identifier).
    pub const IAS_ENROLL_RESPONSE: u16 = 0x0c04;
    /// Unsolicited Zone Enroll Response sent (`arg`: zone identifier).
    pub const IAS_ENROLL_UNSOLICITED: u16 = 0x0c05;
    /// ZoneState read back: enrolled.
    pub const IAS_ENROLL_CONFIRMED: u16 = 0x0c06;
    /// ZoneState read back: not enrolled (`status`: retries so far).
    pub const IAS_NOT_ENROLLED: u16 = 0x0c07;
    /// A ZoneStatus was interpreted (`arg`: see
    /// [`super::zone_status_arg`]).
    pub const IAS_STATUS: u16 = 0x0c08;
    /// An enrolled zone reported itself unenrolled: enrolling again.
    pub const IAS_REENROLL: u16 = 0x0c09;

    // Persistence.
    /// A registry write failed (`status`: 0 full, 1 I/O, 2 buffer).
    pub const STORE_FAILED: u16 = 0x0d01;
    /// A device record was skipped at restore (unknown format or
    /// corrupt).
    pub const RECORD_SKIPPED: u16 = 0x0d02;
    /// The registry index could not be decoded.
    pub const INDEX_CORRUPT: u16 = 0x0d03;
    /// A registry record was written.
    pub const RECORD_WRITTEN: u16 = 0x0d04;
    /// Cumulative Flash time in one radio step (`status`: 1 read, 2 write,
    /// 3 erase; `arg`: microseconds), recorded by the board adapter.
    pub const FLASH_RADIO_STEP_TIME: u16 = 0x0d05;

    // Watchdog.
    /// The watchdog was armed (`arg`: timeout in seconds).
    pub const WATCHDOG_ARMED: u16 = 0x0e01;

    // Resources.
    /// A main loop turn took longer than the overrun limit (`arg`:
    /// microseconds).
    pub const LOOP_OVERRUN: u16 = 0x0f01;
    /// Hub events were dropped (`arg`: count).
    pub const EVENTS_DROPPED: u16 = 0x0f02;
    /// Stack events were dropped (`arg`: new drops).
    pub const STACK_EVENTS_DROPPED: u16 = 0x0f03;
}

/// The name of a record code.
pub const fn code_name(c: u16) -> &'static str {
    use code::*;
    match c {
        TRACE_CLEARED => "trace-cleared",
        TRACE_CONFIGURED => "trace-configured",
        CAPTURE_STARTED => "capture-started",
        CAPTURE_STOPPED => "capture-stopped",
        BOOT_COMPLETED => "boot-completed",
        PREVIOUS_BOOT_STAGE => "previous-boot-stage",
        NETWORK_RESTORED => "network-restored",
        NETWORK_FORMED => "network-formed",
        NETWORK_RESTORE_FAILED => "network-restore-failed",
        NETWORK_NOT_FORMED => "network-not-formed",
        REGISTRY_RESTORED => "registry-restored",
        REGISTRY_RAM_ONLY => "registry-ram-only",
        PARTITION_PROBLEM => "partition-problem",
        NETWORK_RECORD_UNUSABLE => "network-record-unusable",
        NETWORK_RESTORE_RETRY => "network-restore-retry",
        FORMATION_FAILED => "formation-failed",
        USB_OUTPUT_DISCARDED => "usb-output-discarded",
        USB_FRAME_CORRUPT => "usb-frame-corrupt",
        USB_FRAME_OVERSIZE => "usb-frame-oversize",
        USB_REQUEST_REJECTED => "usb-request-rejected",
        USB_UNAUTHORIZED => "usb-unauthorized",
        USB_RESPONSE_DROPPED => "usb-response-dropped",
        RADIO_TX_FAULT => "radio-tx-fault",
        RADIO_CONFIG_ERROR => "radio-config-error",
        STALL_SUSPECTED => "stall-suspected",
        STALL_CONFIRMED => "stall-confirmed",
        PREVIOUS_STALL_RESET => "previous-stall-reset",
        FLASH_RADIO_STEP_TIME => "flash-radio-step-time",
        NWK_PENDING_FULL => "nwk-pending-full",
        JOIN_ASSOCIATION_REQUEST => "join-association-request",
        JOIN_CHILD_JOINED => "join-child-joined",
        JOIN_UPDATE_DEVICE => "join-update-device",
        JOIN_DECISION => "join-decision",
        JOIN_KEY_SENT => "join-key-sent",
        JOIN_KEY_DELIVERED => "join-key-delivered",
        JOIN_KEY_FAILED => "join-key-failed",
        JOIN_TCLK_REQUESTED => "join-tclk-requested",
        JOIN_TCLK_VERIFIED => "join-tclk-verified",
        JOIN_TRACE_LOST => "join-trace-lost",
        PERMIT_JOIN_OPENED => "permit-join-opened",
        PERMIT_JOIN_CLOSED => "permit-join-closed",
        JOINS_REFUSED_AGAIN => "joins-refused-again",
        DEVICE_AUTHORIZED => "device-authorized",
        DEVICE_ANNOUNCED => "device-announced",
        DEVICE_REJOINED => "device-rejoined",
        DEVICE_LEFT => "device-left",
        REGISTRY_FULL => "registry-full",
        ADDRESS_CHANGED => "address-changed",
        DEVICE_DISCOVERED => "device-discovered",
        DEVICE_NOT_AUTHORIZED => "device-not-authorized",
        KEY_EXCHANGE_EXEMPTION_GRANTED => "key-exchange-exemption-granted",
        KEY_EXCHANGE_EXEMPTION_REVOKED => "key-exchange-exemption-revoked",
        KEY_EXCHANGE_EXEMPTION_EXPIRED => "key-exchange-exemption-expired",
        KEY_EXCHANGE_EXEMPTION_USED => "key-exchange-exemption-used",
        JOIN_KEY_EXCHANGE_PENDING => "join-key-exchange-pending",
        JOIN_KEY_EXCHANGE_TIMEOUT => "join-key-exchange-timeout",
        JOIN_AUTHORIZED => "join-authorized",
        JOIN_EXEMPTION_WITHDRAWN => "join-exemption-withdrawn",
        ZDP_TIMEOUT => "zdp-timeout",
        ZCL_DEFAULT_RESPONSE_ERROR => "zcl-default-response-error",
        ZCL_ATTRIBUTE_ERROR => "zcl-attribute-error",
        ZCL_REPORTING_REFUSED => "zcl-reporting-refused",
        COMMAND_SENT => "command-sent",
        COMMAND_RESPONDED => "command-responded",
        COMMAND_CONFIRMED => "command-confirmed",
        COMMAND_TIMEOUT => "command-timeout",
        COMMAND_FAILED => "command-failed",
        COMMAND_RETRY => "command-retry",
        ZCL_UNSUPPORTED_COMMAND => "zcl-unsupported-command",
        POLL_CHECK_IN => "poll-check-in",
        FAST_POLL_STOP => "fast-poll-stop",
        INTERVIEW_STARTED => "interview-started",
        INTERVIEW_REQUEST => "interview-request",
        INTERVIEW_ANSWER => "interview-answer",
        INTERVIEW_TIMEOUT => "interview-timeout",
        INTERVIEW_STEP_SKIPPED => "interview-step-skipped",
        INTERVIEW_STALLED => "interview-stalled",
        INTERVIEW_RESUMED => "interview-resumed",
        INTERVIEW_COMPLETED => "interview-completed",
        INTERVIEW_SEND_DEFERRED => "interview-send-deferred",
        IAS_ZONE_READ => "ias-zone-read",
        IAS_CIE_WRITTEN => "ias-cie-written",
        IAS_ENROLL_REQUEST => "ias-enroll-request",
        IAS_ENROLL_RESPONSE => "ias-enroll-response",
        IAS_ENROLL_UNSOLICITED => "ias-enroll-unsolicited",
        IAS_ENROLL_CONFIRMED => "ias-enroll-confirmed",
        IAS_NOT_ENROLLED => "ias-not-enrolled",
        IAS_STATUS => "ias-status",
        IAS_REENROLL => "ias-reenroll",
        STORE_FAILED => "store-failed",
        RECORD_SKIPPED => "record-skipped",
        INDEX_CORRUPT => "index-corrupt",
        RECORD_WRITTEN => "record-written",
        WATCHDOG_ARMED => "watchdog-armed",
        LOOP_OVERRUN => "loop-overrun",
        EVENTS_DROPPED => "events-dropped",
        STACK_EVENTS_DROPPED => "stack-events-dropped",
        _ => "unknown",
    }
}

/// Bits of the [`code::IAS_STATUS`] argument.
pub mod ias_bits {
    /// The normalized contact state is known.
    pub const CONTACT_KNOWN: u32 = 1 << 16;
    /// … and the contact is open.
    pub const CONTACT_OPEN: u32 = 1 << 17;
    /// The normalized water state is known.
    pub const LEAK_KNOWN: u32 = 1 << 18;
    /// … and there is water.
    pub const LEAK: u32 = 1 << 19;
    /// The zone was in test mode (alarms not interpreted).
    pub const TEST_MODE: u32 = 1 << 20;
    /// A manufacturer-specific override decided the interpretation.
    pub const OVERRIDE: u32 = 1 << 21;
    /// The zone type was unknown (alarms not interpreted).
    pub const TYPE_UNKNOWN: u32 = 1 << 22;
}

/// The [`code::IAS_STATUS`] argument: the raw `ZoneStatus` in the low 16
/// bits and the interpretation flags of [`ias_bits`] above them.
pub const fn zone_status_arg(raw: u16, flags: u32) -> u32 {
    raw as u32 | flags
}

/// One diagnostic record. Absent fields do not apply to the code.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DiagRecord {
    /// Sequence number (assigned when the record is stored).
    pub seq: u32,
    /// Milliseconds since boot, modulo 2³² (wraps after 49.7 days; a
    /// trace page carries the full uptime to unwrap it).
    pub at_ms: u32,
    /// Category.
    pub category: Category,
    /// Severity.
    pub severity: Severity,
    /// Code ([`code`]).
    pub code: u16,
    /// Device IEEE address.
    pub ieee: Option<u64>,
    /// Network address.
    pub short: Option<u16>,
    /// Endpoint.
    pub endpoint: Option<u8>,
    /// Cluster.
    pub cluster: Option<u16>,
    /// ZDP or ZCL transaction sequence number.
    pub tsn: Option<u8>,
    /// Protocol status or small code-specific value.
    pub status: Option<u8>,
    /// Code-specific argument.
    pub arg: Option<u32>,
}

impl DiagRecord {
    /// A record without identifiers.
    pub const fn new(category: Category, severity: Severity, code: u16) -> Self {
        DiagRecord {
            seq: 0,
            at_ms: 0,
            category,
            severity,
            code,
            ieee: None,
            short: None,
            endpoint: None,
            cluster: None,
            tsn: None,
            status: None,
            arg: None,
        }
    }

    /// With a device.
    #[must_use]
    pub const fn ieee(mut self, ieee: u64) -> Self {
        self.ieee = Some(ieee);
        self
    }

    /// With a network address.
    #[must_use]
    pub const fn short(mut self, short: u16) -> Self {
        self.short = Some(short);
        self
    }

    /// With an endpoint.
    #[must_use]
    pub const fn endpoint(mut self, endpoint: u8) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    /// With a cluster.
    #[must_use]
    pub const fn cluster(mut self, cluster: u16) -> Self {
        self.cluster = Some(cluster);
        self
    }

    /// With a transaction sequence number.
    #[must_use]
    pub const fn tsn(mut self, tsn: u8) -> Self {
        self.tsn = Some(tsn);
        self
    }

    /// With a status.
    #[must_use]
    pub const fn status(mut self, status: u8) -> Self {
        self.status = Some(status);
        self
    }

    /// With an argument.
    #[must_use]
    pub const fn arg(mut self, arg: u32) -> Self {
        self.arg = Some(arg);
        self
    }
}

/// Presence bits of [`Packed`] and of the wire encoding.
pub(crate) mod present {
    pub const IEEE: u8 = 1 << 0;
    pub const SHORT: u8 = 1 << 1;
    pub const ENDPOINT: u8 = 1 << 2;
    pub const CLUSTER: u8 = 1 << 3;
    pub const TSN: u8 = 1 << 4;
    pub const STATUS: u8 = 1 << 5;
    pub const ARG: u8 = 1 << 6;
}

/// A record as stored: 32 octets, absent fields zero.
#[derive(Clone, Copy, Debug)]
struct Packed {
    ieee: u64,
    seq: u32,
    at_ms: u32,
    arg: u32,
    code: u16,
    short: u16,
    cluster: u16,
    category: u8,
    severity: u8,
    flags: u8,
    endpoint: u8,
    tsn: u8,
    status: u8,
}

impl Packed {
    fn pack(r: &DiagRecord) -> Self {
        let mut flags = 0;
        let mut set = |bit: u8, present: bool| {
            if present {
                flags |= bit;
            }
        };
        set(present::IEEE, r.ieee.is_some());
        set(present::SHORT, r.short.is_some());
        set(present::ENDPOINT, r.endpoint.is_some());
        set(present::CLUSTER, r.cluster.is_some());
        set(present::TSN, r.tsn.is_some());
        set(present::STATUS, r.status.is_some());
        set(present::ARG, r.arg.is_some());
        Packed {
            ieee: r.ieee.unwrap_or(0),
            seq: r.seq,
            at_ms: r.at_ms,
            arg: r.arg.unwrap_or(0),
            code: r.code,
            short: r.short.unwrap_or(0),
            cluster: r.cluster.unwrap_or(0),
            category: r.category.code(),
            severity: r.severity.code(),
            flags,
            endpoint: r.endpoint.unwrap_or(0),
            tsn: r.tsn.unwrap_or(0),
            status: r.status.unwrap_or(0),
        }
    }

    fn unpack(&self) -> DiagRecord {
        let f = self.flags;
        let has = |bit: u8| f & bit != 0;
        DiagRecord {
            seq: self.seq,
            at_ms: self.at_ms,
            category: Category::from_code(self.category).unwrap_or(Category::System),
            severity: Severity::from_code(self.severity).unwrap_or(Severity::Info),
            code: self.code,
            ieee: has(present::IEEE).then_some(self.ieee),
            short: has(present::SHORT).then_some(self.short),
            endpoint: has(present::ENDPOINT).then_some(self.endpoint),
            cluster: has(present::CLUSTER).then_some(self.cluster),
            tsn: has(present::TSN).then_some(self.tsn),
            status: has(present::STATUS).then_some(self.status),
            arg: has(present::ARG).then_some(self.arg),
        }
    }
}

/// What the log keeps.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TraceConfig {
    /// Records below this severity are not kept.
    pub min_severity: Severity,
    /// Categories kept (bit [`Category::bit`]). Critical records are kept
    /// whatever the mask.
    pub categories: u32,
}

impl Default for TraceConfig {
    fn default() -> Self {
        TraceConfig {
            min_severity: Severity::Info,
            categories: ALL_CATEGORIES,
        }
    }
}

/// A bounded log of diagnostic records.
#[derive(Debug)]
pub struct DiagLog<const N: usize> {
    records: Vec<Packed, N>,
    next_seq: u32,
    config: TraceConfig,
    dropped: u32,
    filtered: u32,
}

impl<const N: usize> Default for DiagLog<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> DiagLog<N> {
    /// An empty log keeping Info and above of every category.
    pub const fn new() -> Self {
        DiagLog {
            records: Vec::new(),
            next_seq: 0,
            config: TraceConfig {
                min_severity: Severity::Info,
                categories: ALL_CATEGORIES,
            },
            dropped: 0,
            filtered: 0,
        }
    }

    /// The configuration.
    pub const fn config(&self) -> TraceConfig {
        self.config
    }

    /// Changes what is kept from now on (stored records stay).
    pub fn configure(&mut self, config: TraceConfig) {
        self.config = config;
    }

    /// Whether a record of `category` and `severity` would be kept: test
    /// it before building an expensive record.
    pub fn wants(&self, category: Category, severity: Severity) -> bool {
        severity == Severity::Critical
            || (severity >= self.config.min_severity
                && self.config.categories & category.bit() != 0)
    }

    /// Stores `record` stamped `at_ms`, unless filtered; returns whether
    /// it was stored.
    pub fn record(&mut self, mut record: DiagRecord, at_ms: u32) -> bool {
        if !self.wants(record.category, record.severity) {
            self.filtered = self.filtered.wrapping_add(1);
            return false;
        }
        if self.records.is_full() {
            // The oldest record no more severe than the new one gives way.
            let victim = self
                .records
                .iter()
                .position(|p| p.severity <= record.severity.code());
            match victim {
                Some(i) => {
                    self.records.remove(i);
                    self.dropped = self.dropped.wrapping_add(1);
                }
                None => {
                    self.dropped = self.dropped.wrapping_add(1);
                    return false;
                }
            }
        }
        record.seq = self.next_seq;
        record.at_ms = at_ms;
        self.next_seq = self.next_seq.wrapping_add(1);
        let _ = self.records.push(Packed::pack(&record));
        true
    }

    /// Records stored.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Capacity.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Records dropped (evicted or refused because the log was full).
    pub const fn dropped(&self) -> u32 {
        self.dropped
    }

    /// Records not kept because of the configuration.
    pub const fn filtered(&self) -> u32 {
        self.filtered
    }

    /// The sequence number the next stored record will get.
    pub const fn next_seq(&self) -> u32 {
        self.next_seq
    }

    /// The sequence number of the oldest stored record (`next_seq` when
    /// empty).
    pub fn first_seq(&self) -> u32 {
        self.records.first().map_or(self.next_seq, |p| p.seq)
    }

    /// Up to `limit` (and `out`'s capacity) of the records with a sequence number at or
    /// after `from` (in the wrapping sense), oldest first, optionally only
    /// those of device `ieee`; returns the sequence number to continue
    /// from.
    pub fn read<const M: usize>(
        &self,
        from: u32,
        ieee: Option<u64>,
        limit: usize,
        out: &mut Vec<DiagRecord, M>,
    ) -> u32 {
        for p in &self.records {
            // At or after `from`: the difference is below half the range.
            if p.seq.wrapping_sub(from) >= u32::MAX / 2 {
                continue;
            }
            let r = p.unpack();
            if ieee.is_some_and(|i| r.ieee != Some(i)) {
                continue;
            }
            if out.is_full() || out.len() >= limit {
                return p.seq;
            }
            let _ = out.push(r);
        }
        // Everything stored was examined.
        if self.next_seq.wrapping_sub(from) < u32::MAX / 2 {
            self.next_seq
        } else {
            from
        }
    }

    /// Removes every record; returns how many.
    pub fn clear(&mut self) -> usize {
        let n = self.records.len();
        self.records.clear();
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(sev: Severity) -> DiagRecord {
        DiagRecord::new(Category::Interview, sev, code::INTERVIEW_REQUEST)
    }

    #[test]
    fn records_are_packed_without_losing_fields() {
        assert_eq!(size_of::<Packed>(), 32);
        let r = DiagRecord::new(Category::Zcl, Severity::Warning, code::COMMAND_TIMEOUT)
            .ieee(0x0011_2233_4455_6677)
            .short(0xabcd)
            .endpoint(1)
            .cluster(0x0006)
            .tsn(42)
            .status(0)
            .arg(7);
        let mut log: DiagLog<4> = DiagLog::new();
        assert!(log.record(r, 1234));
        let mut out: Vec<DiagRecord, 4> = Vec::new();
        log.read(0, None, usize::MAX, &mut out);
        let got = out[0];
        assert_eq!(got.at_ms, 1234);
        assert_eq!(got.seq, 0);
        assert_eq!(
            DiagRecord {
                seq: 0,
                at_ms: 0,
                ..got
            },
            r
        );
        let bare = DiagRecord::new(Category::Boot, Severity::Info, code::BOOT_COMPLETED);
        log.record(bare, 5);
        out.clear();
        log.read(1, None, usize::MAX, &mut out);
        assert_eq!(out[0].ieee, None);
        assert_eq!(out[0].status, None);
    }

    #[test]
    fn filtering_happens_before_queueing() {
        let mut log: DiagLog<8> = DiagLog::new();
        assert!(!log.record(rec(Severity::Debug), 0), "below Info");
        assert_eq!(log.filtered(), 1);
        log.configure(TraceConfig {
            min_severity: Severity::Trace,
            categories: Category::Boot.bit(),
        });
        assert!(!log.record(rec(Severity::Error), 0), "category off");
        assert!(log.record(rec(Severity::Critical), 0), "critical always");
        assert!(log.record(
            DiagRecord::new(Category::Boot, Severity::Trace, code::BOOT_COMPLETED),
            0
        ));
        assert_eq!(log.len(), 2);
        assert_eq!(log.dropped(), 0);
    }

    #[test]
    fn a_full_log_drops_low_priority_records_first() {
        let mut log: DiagLog<4> = DiagLog::new();
        log.configure(TraceConfig {
            min_severity: Severity::Trace,
            categories: ALL_CATEGORIES,
        });
        log.record(rec(Severity::Error), 0); // seq 0
        log.record(rec(Severity::Debug), 0); // seq 1
        log.record(rec(Severity::Info), 0); // seq 2
        log.record(rec(Severity::Error), 0); // seq 3
        // A warning evicts the oldest record no more severe: the debug one.
        assert!(log.record(rec(Severity::Warning), 0));
        let mut out: Vec<DiagRecord, 8> = Vec::new();
        log.read(0, None, usize::MAX, &mut out);
        let seqs: std::vec::Vec<u32> = out.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, [0, 2, 3, 4]);
        assert_eq!(log.dropped(), 1);
        // A trace record finds nothing to evict: it is the one dropped.
        log.record(rec(Severity::Error), 0); // evicts info (seq 2)
        assert!(!log.record(rec(Severity::Trace), 0));
        assert_eq!(log.dropped(), 3);
        // A flood of errors still keeps the newest ones.
        for _ in 0..10 {
            log.record(rec(Severity::Critical), 0);
        }
        out.clear();
        log.read(0, None, usize::MAX, &mut out);
        assert!(out.iter().all(|r| r.severity == Severity::Critical));
        assert_eq!(out.last().unwrap().seq, log.next_seq() - 1);
    }

    #[test]
    fn pagination_follows_sequence_numbers_and_device_filters() {
        let mut log: DiagLog<16> = DiagLog::new();
        for i in 0..10u64 {
            log.record(rec(Severity::Info).ieee(i % 2), 0);
        }
        let mut page: Vec<DiagRecord, 3> = Vec::new();
        let next = log.read(0, None, usize::MAX, &mut page);
        assert_eq!(page.len(), 3);
        assert_eq!(next, 3);
        page.clear();
        let next = log.read(next, None, usize::MAX, &mut page);
        assert_eq!((page[0].seq, next), (3, 6));
        // Device 1 only.
        let mut all: Vec<DiagRecord, 16> = Vec::new();
        let next = log.read(0, Some(1), usize::MAX, &mut all);
        assert_eq!(all.len(), 5);
        assert!(all.iter().all(|r| r.ieee == Some(1)));
        assert_eq!(next, 10);
        // Reading from the end yields nothing and stays at the end.
        all.clear();
        assert_eq!(log.read(10, None, usize::MAX, &mut all), 10);
        assert!(all.is_empty());
        assert_eq!(log.clear(), 10);
        assert_eq!(log.first_seq(), 10);
    }

    #[test]
    fn sequence_numbers_wrap() {
        let mut log: DiagLog<4> = DiagLog::new();
        log.next_seq = u32::MAX - 1;
        for _ in 0..4 {
            log.record(rec(Severity::Info), 0);
        }
        let mut out: Vec<DiagRecord, 8> = Vec::new();
        let next = log.read(u32::MAX - 1, None, usize::MAX, &mut out);
        let seqs: std::vec::Vec<u32> = out.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, [u32::MAX - 1, u32::MAX, 0, 1]);
        assert_eq!(next, 2);
        out.clear();
        log.read(0, None, usize::MAX, &mut out);
        assert_eq!(out.len(), 2, "seq 0 and 1 are after u32::MAX");
    }

    #[test]
    fn names_parse_back() {
        for c in Category::ALL {
            assert_eq!(Category::parse(c.name()), Some(c));
            assert_eq!(Category::from_code(c.code()), Some(c));
        }
        assert_eq!(Severity::parse("WARNING"), Some(Severity::Warning));
        assert_eq!(code_name(code::JOIN_KEY_SENT), "join-key-sent");
        assert_eq!(code_name(0x7777), "unknown");
    }
}
