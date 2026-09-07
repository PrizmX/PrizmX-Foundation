import Darwin
import Foundation
import PrizmXAttributionC

/// One-shot sandbox / API probe logged from the packet tunnel at start.
public struct AttributionProbeReport: Sendable, Equatable {
    public var sysctl: [SysctlSample]
    public var socketCount: Int
    public var milliseconds: Int
    public var libproc: LibprocSample
    public var sandbox: SandboxSample

    public struct LibprocSample: Sendable, Equatable {
        public var listpidsBytes: Int32
        public var pidCount: Int32
        public var pidsInspected: Int32
        public var pidsDenied: Int32
        public var socketFDs: Int32
        public var inetSockets: Int32
        public var lastErrno: Int32
    }

    public struct SandboxSample: Sendable, Equatable {
        public var kernprocErrno: Int32
        public var kernprocCount: Int32
        public var selfFDBytes: Int32
        public var selfErrno: Int32
        public var tcpPCBRows: Int32
        public var udpPCBRows: Int32
        public var tcpSamplePGID: Int32
        public var tcpSampleUID: Int32
        public var tcpSampleLPort: Int32
        public var pidinfoOK: Int32
        public var pidinfoFail: Int32
        public var pidinfoErrno: Int32
    }

    public struct SysctlSample: Sendable, Equatable {
        public var name: String
        public var errnoValue: Int32
        public var bytes: Int
    }

    public var summary: String {
        let sysctlText = sysctl.map { sample in
            "\(sample.name) errno=\(sample.errnoValue) bytes=\(sample.bytes)"
        }.joined(separator: " ")
        return "attribution probe sockets=\(socketCount) inet=\(libproc.inetSockets) "
            + "pids=\(libproc.pidCount) inspected=\(libproc.pidsInspected) "
            + "denied=\(libproc.pidsDenied) fds=\(libproc.socketFDs) "
            + "listpids=\(libproc.listpidsBytes) errno=\(libproc.lastErrno) "
            + "kernproc errno=\(sandbox.kernprocErrno) n=\(sandbox.kernprocCount) "
            + "self_fds=\(sandbox.selfFDBytes) self_err=\(sandbox.selfErrno) "
            + "pcb tcp=\(sandbox.tcpPCBRows) udp=\(sandbox.udpPCBRows) "
            + "pgid=\(sandbox.tcpSamplePGID) uid=\(sandbox.tcpSampleUID) "
            + "lport=\(sandbox.tcpSampleLPort) pidinfo ok=\(sandbox.pidinfoOK) "
            + "fail=\(sandbox.pidinfoFail) err=\(sandbox.pidinfoErrno) "
            + "ms=\(milliseconds) \(sysctlText)"
    }
}

public enum AttributionProbe {
    public static func run(attributor: ProcessFlowAttributor? = nil) -> AttributionProbeReport {
        let names = [
            "net.inet.tcp.pcblist",
            "net.inet.tcp.pcblist_n",
            "net.inet.udp.pcblist",
            "net.inet.udp.pcblist_n"
        ]
        let samples = names.map { name -> AttributionProbeReport.SysctlSample in
            var errnoValue: Int32 = 0
            var length: size_t = 0
            _ = prizmx_sysctl_probe(name, &errnoValue, &length)
            return AttributionProbeReport.SysctlSample(
                name: name,
                errnoValue: errnoValue,
                bytes: length
            )
        }
        var stats = prizmx_libproc_stats()
        var sandbox = prizmx_sandbox_probe()
        let started = ContinuousClock.now
        _ = prizmx_libproc_stats_fill(&stats, getpid())
        _ = prizmx_sandbox_probe_fill(&sandbox)
        let sockets = (attributor ?? ProcessFlowAttributor()).refresh()
        let elapsed = started.duration(to: ContinuousClock.now)
        let parts = elapsed.components
        let milliseconds = Int(parts.seconds * 1_000 + parts.attoseconds / 1_000_000_000_000_000)
        return AttributionProbeReport(
            sysctl: samples,
            socketCount: sockets,
            milliseconds: milliseconds,
            libproc: AttributionProbeReport.LibprocSample(
                listpidsBytes: stats.listpids_bytes,
                pidCount: stats.pid_count,
                pidsInspected: stats.pids_inspected,
                pidsDenied: stats.pids_denied,
                socketFDs: stats.socket_fds,
                inetSockets: stats.inet_sockets,
                lastErrno: stats.last_errno
            ),
            sandbox: AttributionProbeReport.SandboxSample(
                kernprocErrno: sandbox.kernproc_errno,
                kernprocCount: sandbox.kernproc_count,
                selfFDBytes: sandbox.self_fd_bytes,
                selfErrno: sandbox.self_errno,
                tcpPCBRows: sandbox.tcp_pcb_rows,
                udpPCBRows: sandbox.udp_pcb_rows,
                tcpSamplePGID: sandbox.tcp_sample_pgid,
                tcpSampleUID: sandbox.tcp_sample_uid,
                tcpSampleLPort: sandbox.tcp_sample_lport,
                pidinfoOK: sandbox.pidinfo_ok,
                pidinfoFail: sandbox.pidinfo_fail,
                pidinfoErrno: sandbox.pidinfo_sample_errno
            )
        )
    }
}
