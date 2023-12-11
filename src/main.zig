const std = @import("std");
const debug = std.debug;
const fs = std.fs;
const heap = std.heap;
const log = std.log;
const mem = std.mem;
const path = fs.path;
const process = std.process;

//const ntz = @import("ntz");

const build_options = @import("build_options");

pub fn main() !void {
    var ally: mem.Allocator = undefined;

    var gpa = heap.GeneralPurposeAllocator(.{}){};
    defer debug.assert(gpa.deinit() == .ok);
    ally = gpa.allocator();

    //ally = heap.c_allocator;

    //var buf = [_]u8{0} ** (20 * 1024);
    //var fba = heap.FixedBufferAllocator.init(buf[0..]);
    //ally = fba.allocator();

    //var arena_ally = heap.ArenaAllocator.init(ally);
    //defer arena_ally.deinit();
    //ally = arena_ally.allocator();

    //var ca = CountingAllocator.init(ally);
    //ally = ca.allocator();

    //defer {
    //    const usage_size = humanizeBytes(ca.current);
    //    const max_size = humanizeBytes(ca.max);
    //    const total_size = humanizeBytes(ca.allocated);
    //    const free_size = humanizeBytes(ca.freed);

    //    log.debug(
    //        \\Memory usage:
    //        \\  Current: {d:.2} {s}
    //        \\  Max: {d:.2} {s}
    //        \\  Allocated: {d:.2} {s}
    //        \\  Freed: {d:.2} {s}
    //    ,
    //        .{
    //            usage_size.value, @tagName(usage_size.prefix),
    //            max_size.value,   @tagName(max_size.prefix),
    //            total_size.value, @tagName(total_size.prefix),
    //            free_size.value,  @tagName(free_size.prefix),
    //        },
    //    );
    //}

    //var log_ally = heap.loggingAllocator(ally);
    //ally = log_ally.allocator();

    var opts = opts: {
        var opts_ally: mem.Allocator = undefined;

        var arena_ally = heap.ArenaAllocator.init(ally);
        defer arena_ally.deinit();
        opts_ally = arena_ally.allocator();

        var opts = Options.init(opts_ally, .{
            .name = build_options.name,
            .version = build_options.version,
        }) catch |err| {
            log.err("cannot initialize options: {}", .{err});
            return err;
        };

        opts.fromOS(opts_ally) catch |err| {
            log.err("cannot get options from OS: {}", .{err});
            return err;
        };

        defer opts.deinit(opts_ally);

        break :opts try opts.clone(ally);
    };

    defer opts.deinit(ally);

    try run(ally, opts.destination, opts.sources, opts.bit_rate);
}

pub const Error = error{
    InvalidDestination,
    MissingDestination,
    MissingSources,
    SourceIsNotRegularFile,
};

pub const Options = @import("Options.zig");

pub fn run(
    ally: mem.Allocator,
    dest: []const u8,
    srcs: [][]const u8,
    bit_rate: Options.BitRate,
) !void {
    if (dest.len == 0) {
        log.err("destination is required", .{});
        return Error.MissingDestination;
    }

    var dir = fs.cwd().openDir(dest, .{}) catch |err| {
        log.err("invalid destination '{s}': {}", .{ dest, err });
        return err;
    };

    dir.close();

    if (srcs.len == 0) {
        log.err("no source files given", .{});
        return Error.MissingSources;
    }

    for (srcs) |src| {
        var arena_ally = heap.ArenaAllocator.init(ally);
        defer arena_ally.deinit();
        const arena = arena_ally.allocator();

        log.debug("processing source file '{s}'", .{src});

        const src_stat = fs.cwd().statFile(src) catch |err| {
            log.err("cannot stat source file '{s}: {}'", .{ src, err });
            return err;
        };

        if (src_stat.kind != .file) {
            const msg = "source '{s}' is not a regular file ({})";
            log.err(msg, .{ src, src_stat.kind });
            return Error.SourceIsNotRegularFile;
        }

        const name = path.basename(src);
        const dest_path = try path.join(arena, &.{ dest, name });

        cleanMP3(arena, dest_path, src, bit_rate) catch |err| {
            log.err("cannot clean '{s}': {}", .{ src, err });
            return err;
        };

        const dest_stat = fs.cwd().statFile(dest_path) catch |err| {
            log.err("cannot stat result file '{s}': {}", .{ dest_path, err });
            return err;
        };

        const src_size = humanizeBytes(src_stat.size);
        const dest_size = humanizeBytes(dest_stat.size);

        log.info("'{s}' ({d:.2} {s}) -> '{s}' ({d:.2} {s})", .{
            src,       src_size.value,  @tagName(src_size.prefix),
            dest_path, dest_size.value, @tagName(dest_size.prefix),
        });
    }
}

pub fn cleanMP3(
    ally: mem.Allocator,
    dest: []const u8,
    src: []const u8,
    bit_rate: Options.BitRate,
) !void {
    const cmd = &.{
        "ffmpeg",
        "-loglevel",
        "error",
        "-y",
        "-i",
        src,
        "-vf",
        "scale=w=500:h=500,format=yuvj420p",
        "-c:v",
        "mjpeg",
        "-c:a",
        "libmp3lame",
        "-ab",
        @tagName(bit_rate),
        "-map_metadata",
        "0",
        "-id3v2_version",
        "3",
        dest,
    };

    var child = process.Child.init(cmd, ally);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    var stdout = std.ArrayList(u8).init(ally);
    defer stdout.deinit();

    var stderr = std.ArrayList(u8).init(ally);
    defer stderr.deinit();
    errdefer log.err("ffmpeg failed:\n{s}", .{stderr.items});

    try child.spawn();
    try child.collectOutput(&stdout, &stderr, 50 * 1024);
    _ = try child.wait();
}

// ////////////
// Utilities //
// ////////////

const BytePrefix = enum {
    B,
    KiB,
    MiB,
    GiB,
    TiB,
    PiB,
    EiB,
    ZiB,
    YiB,
};

pub const HumanizeResult = struct {
    value: f64,
    prefix: BytePrefix,
};

pub fn humanizeBytes(n: u64) HumanizeResult {
    var v: f64 = @floatFromInt(n);
    var i: u4 = 0;

    while (v >= 1024 and i < @intFromEnum(BytePrefix.YiB)) {
        v /= 1024;
        i += 1;
    }

    return .{ .value = v, .prefix = @enumFromInt(i) };
}

const Context = struct {
    const Self = @This();

    name: []const u8 = "mp3-cleaner",
    allocator: mem.Allocator = undefined,

    pub fn withAllocator(self: Self, allocator: mem.Allocator) Self {
        var new = self;
        new.allocator = allocator;
        return new;
    }

    pub fn withName(self: Self, name: []const u8) Self {
        var new = self;
        new.name = name;
        return new;
    }
};
