// ©AngelaMos | 2026
// scancmd.zig

const std = @import("std");
const targets = @import("targets");
const template = @import("template");
const ratelimit = @import("ratelimit");
const afpacket = @import("afpacket");
const cookie = @import("cookie");
const tx = @import("tx");
const rx = @import("rx");
const dedup = @import("dedup");
const netutil = @import("netutil");

const default_iface = "lo";
const default_rate: u64 = 10_000;
const default_src_port: u16 = 40_000;
const default_wait_ms: i32 = 2_000;
const rx_max_drain_ms: i32 = 60_000;
const ns_per_ms: u64 = 1_000_000;
const default_ports = [_]u16{80};
const dedup_capacity: usize = 1024;
const queue_capacity: usize = 256;

const need_cap_hint =
    "scan: need CAP_NET_RAW + CAP_NET_ADMIN. Grant once, then re-run (no sudo):\n" ++
    "  sudo setcap cap_net_raw,cap_net_admin=eip ./zig-out/bin/zingela\nSkipping.\n";

fn stateLabel(s: rx.State) []const u8 {
    return switch (s) {
        .open => "OPEN",
        .closed => "CLOSED",
        .filtered => "FILTERED",
    };
}

fn consume(io: std.Io, queue: *std.Io.Queue(rx.Result), out: *std.ArrayList(rx.Result), allocator: std.mem.Allocator) void {
    while (true) {
        const r = queue.getOne(io) catch break;
        out.append(allocator, r) catch {};
    }
}

pub fn run(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !void {
    var buf: [1024]u8 = undefined;
    var fw = std.Io.File.stdout().writer(io, &buf);
    const out = &fw.interface;

    const target_text = netutil.getFlag(args, "--target") orelse {
        try out.writeAll("scan: --target <cidr> is required (e.g. --target 10.0.0.0/24)\n");
        try out.flush();
        return;
    };
    const ifname = netutil.getFlag(args, "--iface") orelse default_iface;
    const rate = if (netutil.getFlag(args, "--rate")) |r| try std.fmt.parseInt(u64, r, 10) else default_rate;
    const src_port = if (netutil.getFlag(args, "--src-port")) |p| try std.fmt.parseInt(u16, p, 10) else default_src_port;
    const wait_ms = if (netutil.getFlag(args, "--wait")) |w| try std.fmt.parseInt(i32, w, 10) else default_wait_ms;

    const ports = if (netutil.getFlag(args, "--ports")) |p| try netutil.parsePorts(allocator, p) else try allocator.dupe(u16, &default_ports);
    const gw_mac = if (netutil.getFlag(args, "--gw-mac")) |m| try netutil.parseMac(m) else [_]u8{0} ** 6;
    const src_ip = if (netutil.getFlag(args, "--src-ip")) |s| try netutil.parseIpv4(s) else try netutil.resolveSrcIp(ifname);
    const src_mac = try netutil.resolveSrcMac(ifname);

    var seed: u64 = undefined;
    if (netutil.getFlag(args, "--seed")) |s| {
        seed = try std.fmt.parseInt(u64, s, 10);
    } else {
        var seed_bytes: [8]u8 = undefined;
        try io.randomSecure(&seed_bytes);
        seed = std.mem.readInt(u64, &seed_bytes, .little);
    }

    const cidr = try targets.parseCidr(target_text);
    var eng = try targets.Engine.init(allocator, &.{cidr}, ports, seed);
    defer eng.deinit();
    const count = if (netutil.getFlag(args, "--count")) |c| try std.fmt.parseInt(u64, c, 10) else eng.total;

    const ck = try cookie.Cookie.random(io);
    const tmpl = template.SynTemplate.init(.{
        .src_mac = src_mac,
        .dst_mac = gw_mac,
        .src_ip = src_ip,
        .src_port = src_port,
        .cookie = ck,
    });
    var bucket = ratelimit.TokenBucket.init(rate, rate);

    var backend = afpacket.Backend.open(ifname, .{}) catch |err| switch (err) {
        error.NeedCapNetRaw => {
            try out.writeAll(need_cap_hint);
            try out.flush();
            return;
        },
        else => return err,
    };
    defer backend.close();

    const rx_budget_ns: u64 = @as(u64, @intCast(@max(wait_ms, rx_max_drain_ms))) * ns_per_ms;
    var receiver = rx.Receiver.open(ifname, wait_ms, rx_budget_ns) catch |err| switch (err) {
        error.NeedCapNetRaw => {
            try out.writeAll(need_cap_hint);
            try out.flush();
            return;
        },
        else => return err,
    };
    defer receiver.close();

    var dd = try dedup.Dedup.init(allocator, dedup_capacity);
    defer dd.deinit();

    var qbuf: [queue_capacity]rx.Result = undefined;
    var queue = std.Io.Queue(rx.Result).init(&qbuf);

    var found_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer found_arena.deinit();
    const found_alloc = found_arena.allocator();
    var found: std.ArrayList(rx.Result) = .empty;

    var clock = netutil.RealClock{};
    const t0 = clock.now();

    var consumer = io.async(consume, .{ io, &queue, &found, found_alloc });

    const sent = tx.run(&eng, &tmpl, &bucket, &backend, &clock, count);

    var sink = rx.QueueSink{ .queue = &queue, .io = io };
    rx.run(&receiver, ck, &dd, &sink);

    queue.close(io);
    consumer.await(io);

    const elapsed_ns = clock.now() - t0;
    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;

    var open_n: usize = 0;
    var closed_n: usize = 0;
    var filtered_n: usize = 0;
    for (found.items) |r| {
        const ip = r.ip;
        try out.print("{d}.{d}.{d}.{d}:{d}  {s}\n", .{
            (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff, r.port, stateLabel(r.state),
        });
        switch (r.state) {
            .open => open_n += 1,
            .closed => closed_n += 1,
            .filtered => filtered_n += 1,
        }
    }
    try out.print(
        "scan: sent {d} SYN on {s} in {d:.3}s; {d} open, {d} closed, {d} filtered ({d} replies)\n",
        .{ sent, ifname, elapsed_s, open_n, closed_n, filtered_n, found.items.len },
    );
    try out.flush();
}
