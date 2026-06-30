// ©AngelaMos | 2026
// classify.zig

const std = @import("std");
const packet = @import("packet");
const cookie = @import("cookie");

pub const State = enum { open, closed, filtered };

pub const Result = struct {
    ip: u32,
    port: u16,
    state: State,
};

const ETH_HDR_LEN: usize = 14;
const ETH_OFF_TYPE: usize = 12;
const ETHERTYPE_IPV4: u16 = 0x0800;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_ICMP: u8 = 1;
const IP_MIN_IHL: usize = 20;
const IP_IHL_MASK: u8 = 0x0f;
const IP_WORD_BYTES: usize = 4;
const IP_OFF_PROTO: usize = 9;
const IP_OFF_SRC: usize = 12;
const IP_OFF_DST: usize = 16;

const INNER_TCP_MIN_LEN: usize = 8;

const TCP_OFF_SPORT: usize = 0;
const TCP_OFF_DPORT: usize = 2;
const TCP_OFF_SEQ: usize = 4;
const TCP_OFF_ACK: usize = 8;
const TCP_OFF_FLAGS: usize = 13;
const TCP_MIN_LEN: usize = 20;

const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_ACK: u8 = 0x10;

const ICMP_HDR_LEN: usize = 8;
const ICMP_TYPE_DEST_UNREACH: u8 = 3;
const ICMP_OFF_TYPE: usize = 0;
const ICMP_OFF_CODE: usize = 1;

fn icmpCodeIsFilteredForSyn(code: u8) bool {
    return switch (code) {
        1, 2, 3, 9, 10, 13 => true,
        else => false,
    };
}

fn ihlBytes(first_byte: u8) usize {
    return @as(usize, first_byte & IP_IHL_MASK) * IP_WORD_BYTES;
}

pub fn classify(frame: []const u8, ck: cookie.Cookie) ?Result {
    if (frame.len < ETH_HDR_LEN + IP_MIN_IHL) return null;
    if (std.mem.readInt(u16, frame[ETH_OFF_TYPE..][0..2], .big) != ETHERTYPE_IPV4) return null;

    const ip = ETH_HDR_LEN;
    const ihl = ihlBytes(frame[ip]);
    if (ihl < IP_MIN_IHL or frame.len < ip + ihl) return null;

    const proto = frame[ip + IP_OFF_PROTO];
    const ip_src = std.mem.readInt(u32, frame[ip + IP_OFF_SRC ..][0..4], .big);
    const ip_dst = std.mem.readInt(u32, frame[ip + IP_OFF_DST ..][0..4], .big);

    if (proto == IPPROTO_TCP) {
        const tcp = ip + ihl;
        if (frame.len < tcp + TCP_MIN_LEN) return null;
        const sport = std.mem.readInt(u16, frame[tcp + TCP_OFF_SPORT ..][0..2], .big);
        const dport = std.mem.readInt(u16, frame[tcp + TCP_OFF_DPORT ..][0..2], .big);
        const ackno = std.mem.readInt(u32, frame[tcp + TCP_OFF_ACK ..][0..4], .big);
        const flags = frame[tcp + TCP_OFF_FLAGS];

        const is_synack = (flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK);
        if (is_synack) {
            if (ck.validateSynAck(ackno, ip_src, sport, ip_dst, dport))
                return .{ .ip = ip_src, .port = sport, .state = .open };
            return null;
        }
        if ((flags & TCP_FLAG_RST) != 0 and (flags & TCP_FLAG_ACK) != 0) {
            if (ck.validateSynAck(ackno, ip_src, sport, ip_dst, dport))
                return .{ .ip = ip_src, .port = sport, .state = .closed };
        }
        return null;
    }

    if (proto == IPPROTO_ICMP) {
        const icmp = ip + ihl;
        if (frame.len < icmp + ICMP_HDR_LEN) return null;
        if (frame[icmp + ICMP_OFF_TYPE] != ICMP_TYPE_DEST_UNREACH) return null;
        if (!icmpCodeIsFilteredForSyn(frame[icmp + ICMP_OFF_CODE])) return null;

        const inner = icmp + ICMP_HDR_LEN;
        if (frame.len < inner + IP_MIN_IHL) return null;
        const inner_ihl = ihlBytes(frame[inner]);
        if (inner_ihl < IP_MIN_IHL) return null;
        if (frame[inner + IP_OFF_PROTO] != IPPROTO_TCP) return null;

        const inner_src = std.mem.readInt(u32, frame[inner + IP_OFF_SRC ..][0..4], .big);
        const inner_dst = std.mem.readInt(u32, frame[inner + IP_OFF_DST ..][0..4], .big);
        const inner_tcp = inner + inner_ihl;
        if (frame.len < inner_tcp + INNER_TCP_MIN_LEN) return null;
        const inner_sport = std.mem.readInt(u16, frame[inner_tcp + TCP_OFF_SPORT ..][0..2], .big);
        const inner_dport = std.mem.readInt(u16, frame[inner_tcp + TCP_OFF_DPORT ..][0..2], .big);
        const inner_seq = std.mem.readInt(u32, frame[inner_tcp + TCP_OFF_SEQ ..][0..4], .big);

        if (inner_seq == ck.seq(inner_dst, inner_dport, inner_src, inner_sport))
            return .{ .ip = inner_dst, .port = inner_dport, .state = .filtered };
        return null;
    }

    return null;
}

comptime {
    std.debug.assert(@sizeOf(packet.EthHdr) == ETH_HDR_LEN);
    std.debug.assert(@sizeOf(packet.Ipv4Hdr) == IP_MIN_IHL);
    std.debug.assert(@sizeOf(packet.TcpHdr) == TCP_MIN_LEN);
}

const test_key = [16]u8{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

const our_ip: u32 = 0x0a000001;
const our_port: u16 = 40000;
const their_ip: u32 = 0x08080808;
const their_port: u16 = 80;

fn buildTcpReply(buf: *[54]u8, ip_src: u32, ip_dst: u32, sport: u16, dport: u16, seq: u32, ack: u32, flags: u8) void {
    @memset(buf, 0);
    std.mem.writeInt(u16, buf[ETH_OFF_TYPE..][0..2], ETHERTYPE_IPV4, .big);
    buf[ETH_HDR_LEN] = 0x45;
    buf[ETH_HDR_LEN + IP_OFF_PROTO] = IPPROTO_TCP;
    std.mem.writeInt(u32, buf[ETH_HDR_LEN + IP_OFF_SRC ..][0..4], ip_src, .big);
    std.mem.writeInt(u32, buf[ETH_HDR_LEN + IP_OFF_DST ..][0..4], ip_dst, .big);
    const tcp = ETH_HDR_LEN + IP_MIN_IHL;
    std.mem.writeInt(u16, buf[tcp + TCP_OFF_SPORT ..][0..2], sport, .big);
    std.mem.writeInt(u16, buf[tcp + TCP_OFF_DPORT ..][0..2], dport, .big);
    std.mem.writeInt(u32, buf[tcp + TCP_OFF_SEQ ..][0..4], seq, .big);
    std.mem.writeInt(u32, buf[tcp + TCP_OFF_ACK ..][0..4], ack, .big);
    buf[tcp + TCP_OFF_FLAGS] = flags;
}

fn buildIcmpUnreach(buf: *[128]u8, code: u8, inner_src: u32, inner_dst: u32, inner_sport: u16, inner_dport: u16, inner_seq: u32) usize {
    @memset(buf, 0);
    std.mem.writeInt(u16, buf[ETH_OFF_TYPE..][0..2], ETHERTYPE_IPV4, .big);
    buf[ETH_HDR_LEN] = 0x45;
    buf[ETH_HDR_LEN + IP_OFF_PROTO] = IPPROTO_ICMP;
    std.mem.writeInt(u32, buf[ETH_HDR_LEN + IP_OFF_SRC ..][0..4], inner_dst, .big);
    std.mem.writeInt(u32, buf[ETH_HDR_LEN + IP_OFF_DST ..][0..4], inner_src, .big);
    const icmp = ETH_HDR_LEN + IP_MIN_IHL;
    buf[icmp + ICMP_OFF_TYPE] = ICMP_TYPE_DEST_UNREACH;
    buf[icmp + ICMP_OFF_CODE] = code;
    const inner = icmp + ICMP_HDR_LEN;
    buf[inner] = 0x45;
    buf[inner + IP_OFF_PROTO] = IPPROTO_TCP;
    std.mem.writeInt(u32, buf[inner + IP_OFF_SRC ..][0..4], inner_src, .big);
    std.mem.writeInt(u32, buf[inner + IP_OFF_DST ..][0..4], inner_dst, .big);
    const inner_tcp = inner + IP_MIN_IHL;
    std.mem.writeInt(u16, buf[inner_tcp + TCP_OFF_SPORT ..][0..2], inner_sport, .big);
    std.mem.writeInt(u16, buf[inner_tcp + TCP_OFF_DPORT ..][0..2], inner_dport, .big);
    std.mem.writeInt(u32, buf[inner_tcp + TCP_OFF_SEQ ..][0..4], inner_seq, .big);
    return inner_tcp + ICMP_HDR_LEN;
}

test "validated SYN-ACK classifies as open" {
    const ck = cookie.Cookie.init(test_key);
    const our_seq = ck.seq(their_ip, their_port, our_ip, our_port);
    var f: [54]u8 = undefined;
    buildTcpReply(&f, their_ip, our_ip, their_port, our_port, 0xCAFEBABE, our_seq +% 1, TCP_FLAG_SYN | TCP_FLAG_ACK);
    const r = classify(&f, ck).?;
    try std.testing.expectEqual(State.open, r.state);
    try std.testing.expectEqual(their_ip, r.ip);
    try std.testing.expectEqual(their_port, r.port);
}

test "SYN-ACK with a wrong ack is rejected (anti-spoof)" {
    const ck = cookie.Cookie.init(test_key);
    var f: [54]u8 = undefined;
    buildTcpReply(&f, their_ip, our_ip, their_port, our_port, 0xCAFEBABE, 0xDEADBEEF, TCP_FLAG_SYN | TCP_FLAG_ACK);
    try std.testing.expect(classify(&f, ck) == null);
}

test "validated RST/ACK classifies as closed" {
    const ck = cookie.Cookie.init(test_key);
    const our_seq = ck.seq(their_ip, their_port, our_ip, our_port);
    var f: [54]u8 = undefined;
    buildTcpReply(&f, their_ip, our_ip, their_port, our_port, 0, our_seq +% 1, TCP_FLAG_RST | TCP_FLAG_ACK);
    const r = classify(&f, ck).?;
    try std.testing.expectEqual(State.closed, r.state);
    try std.testing.expectEqual(their_ip, r.ip);
    try std.testing.expectEqual(their_port, r.port);
}

test "RST/ACK with a wrong ack is rejected" {
    const ck = cookie.Cookie.init(test_key);
    var f: [54]u8 = undefined;
    buildTcpReply(&f, their_ip, our_ip, their_port, our_port, 0, 0x11112222, TCP_FLAG_RST | TCP_FLAG_ACK);
    try std.testing.expect(classify(&f, ck) == null);
}

test "bare RST without ACK is dropped as unvalidated" {
    const ck = cookie.Cookie.init(test_key);
    var f: [54]u8 = undefined;
    buildTcpReply(&f, their_ip, our_ip, their_port, our_port, 0, 0, TCP_FLAG_RST);
    try std.testing.expect(classify(&f, ck) == null);
}

test "validated ICMP dest-unreachable classifies as filtered" {
    const ck = cookie.Cookie.init(test_key);
    const our_seq = ck.seq(their_ip, their_port, our_ip, our_port);
    var f: [128]u8 = undefined;
    const len = buildIcmpUnreach(&f, 3, our_ip, their_ip, our_port, their_port, our_seq);
    const r = classify(f[0..len], ck).?;
    try std.testing.expectEqual(State.filtered, r.state);
    try std.testing.expectEqual(their_ip, r.ip);
    try std.testing.expectEqual(their_port, r.port);
}

test "ICMP with a mismatched inner seq is rejected" {
    const ck = cookie.Cookie.init(test_key);
    var f: [128]u8 = undefined;
    const len = buildIcmpUnreach(&f, 3, our_ip, their_ip, our_port, their_port, 0x99999999);
    try std.testing.expect(classify(f[0..len], ck) == null);
}

test "ICMP with a non-filtered code is ignored" {
    const ck = cookie.Cookie.init(test_key);
    const our_seq = ck.seq(their_ip, their_port, our_ip, our_port);
    var f: [128]u8 = undefined;
    const len = buildIcmpUnreach(&f, 4, our_ip, their_ip, our_port, their_port, our_seq);
    try std.testing.expect(classify(f[0..len], ck) == null);
}

test "non-IPv4 ethertype is ignored" {
    const ck = cookie.Cookie.init(test_key);
    var f: [54]u8 = undefined;
    buildTcpReply(&f, their_ip, our_ip, their_port, our_port, 0, 0, TCP_FLAG_SYN | TCP_FLAG_ACK);
    std.mem.writeInt(u16, f[ETH_OFF_TYPE..][0..2], 0x0806, .big);
    try std.testing.expect(classify(&f, ck) == null);
}

test "runt frames return null instead of reading out of bounds" {
    const ck = cookie.Cookie.init(test_key);
    var tiny = [_]u8{0} ** 20;
    try std.testing.expect(classify(&tiny, ck) == null);
    var empty = [_]u8{};
    try std.testing.expect(classify(&empty, ck) == null);
}
