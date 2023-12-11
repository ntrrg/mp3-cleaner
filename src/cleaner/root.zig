// Copyright 2025 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const builtin = @import("builtin");
const std = @import("std");

const ntz = @import("ntz");
const bytes = ntz.types.bytes;

pub const BitRate = enum {
    @"128k",
    @"192k",
    @"320k",
};

pub const Diagnostics = struct {
    pub const UnderlyingError = std.Io.Dir.StatFileError ||
        std.process.SpawnError ||
        std.process.Child.WaitError;

    pub const Stats = struct {
        size: u64 = 0,
    };

    orig: Stats = .{},
    new: Stats = .{},
    err: ?UnderlyingError = null,
};

pub const CleanError = error{
    CannotStatSourceFile,
    CannotExecuteFfmpeg,
    FfmepgFailed,
    CannotStatDestinationFile,
};

pub fn clean(
    io: std.Io,
    bit_rate: BitRate,
    destination: []const u8,
    source: []const u8,
    diagnostics: ?*Diagnostics,
) CleanError!void {
    if (diagnostics) |diag| {
        const cwd = std.Io.Dir.cwd();

        const src_stat = cwd.statFile(io, source, .{}) catch |err| {
            diag.err = err;
            return error.CannotStatSourceFile;
        };

        diag.orig.size = src_stat.size;
    }

    var child = std.process.spawn(io, .{
        .argv = &.{
            "ffmpeg",
            "-loglevel",
            "error",
            "-y",
            "-i",
            source,
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
            destination,
        },

        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .inherit,
    }) catch |err| {
        if (diagnostics) |diag| diag.err = err;
        return error.CannotExecuteFfmpeg;
    };

    _ = child.wait(io) catch |err| {
        if (diagnostics) |diag| diag.err = err;
        return error.FfmepgFailed;
    };

    if (diagnostics) |diag| {
        const cwd = std.Io.Dir.cwd();

        const dest_stat = cwd.statFile(io, destination, .{}) catch |err| {
            diag.err = err;
            return CleanError.CannotStatDestinationFile;
        };

        diag.new.size = dest_stat.size;
    }
}

pub const CleanSeqError = error{
    MissingDestination,
    InvalidDestination,
    MissingSource,
} || CleanError || std.mem.Allocator.Error || std.Io.Cancelable;

pub fn cleanSeq(
    io: std.Io,
    allocator: std.mem.Allocator,
    status: *ntz.Status,
    log: anytype,
    bit_rate: BitRate,
    destination: []const u8,
    sources: []const []const u8,
) CleanSeqError!void {
    if (status.isDone()) return error.Canceled;

    if (destination.len == 0) {
        log.err("no destination given");
        return error.MissingDestination;
    }

    const cwd = std.Io.Dir.cwd();

    var dir = cwd.openDir(io, destination, .{}) catch |err| {
        const msg = "invalid destination '{s}'";
        log.withError(err).errf(allocator, msg, .{destination});
        return error.InvalidDestination;
    };

    dir.close(io);

    if (sources.len == 0) {
        log.err("no source given");
        return error.MissingSource;
    }

    var mux: std.Io.Mutex = .init;
    var src_total_size: u64 = 0;
    var dst_total_size: u64 = 0;

    var wg: std.Io.Group = .init;
    errdefer wg.cancel(io);

    for (sources) |src| {
        wg.async(io, Task(@TypeOf(log)).run, .{
            io,
            allocator,
            status,
            log,
            bit_rate,
            destination,
            src,
            &mux,
            &src_total_size,
            &dst_total_size,
        });
    }

    wg.await(io) catch |err| {
        log.err("cleaning canceled");
        return err;
    };

    const src_total_size_h = humanizeBytes(src_total_size);
    const dst_total_size_h = humanizeBytes(dst_total_size);

    log.infof(allocator, "Done ({d:.2} {s} -> {d:.2} {s})", .{
        src_total_size_h.value, @tagName(src_total_size_h.prefix),
        dst_total_size_h.value, @tagName(dst_total_size_h.prefix),
    });
}

fn Task(comptime Logger: type) type {
    return struct {
        pub fn run(
            io: std.Io,
            allocator: std.mem.Allocator,
            status: *ntz.Status,
            log: Logger,
            bit_rate: BitRate,
            destination: []const u8,
            source: []const u8,
            mux: *std.Io.Mutex,
            src_total_size: *u64,
            dst_total_size: *u64,
        ) std.Io.Cancelable!void {
            if (status.isDone()) return error.Canceled;

            var arena_ally = std.heap.ArenaAllocator.init(allocator);
            defer arena_ally.deinit();
            const arena = arena_ally.allocator();

            log.debugf(arena, "processing source file '{s}'", .{source});

            if (!bytes.endsWith(source, ".mp3")) {
                log.errf(arena, "source file '{s}' is not an MP3 file", .{source});
                return;
            }

            const name = std.fs.path.basename(source);

            const dst = std.fs.path.join(arena, &.{ destination, name }) catch |err| {
                log.withError(err).err("cannot create destination path");
                return;
            };

            //defer allocator.free(dst);

            var diag = Diagnostics{};

            clean(io, bit_rate, dst, source, &diag) catch |err| {
                log.withError(diag.err orelse err)
                    .errf(arena, "cannot clean file '{s}'", .{source});

                return;
            };

            try mux.lock(io);
            src_total_size.* += diag.orig.size;
            dst_total_size.* += diag.new.size;
            mux.unlock(io);

            const src_size_h = humanizeBytes(diag.orig.size);
            const dst_size_h = humanizeBytes(diag.new.size);

            log.infof(arena, "{s} ({d:.2} {s} -> {d:.2} {s})", .{
                name,
                src_size_h.value,
                @tagName(src_size_h.prefix),
                dst_size_h.value,
                @tagName(dst_size_h.prefix),
            });
        }
    };
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

pub const HumanizedResult = struct {
    value: f64,
    prefix: BytePrefix,
};

pub fn humanizeBytes(n: u64) HumanizedResult {
    var v: f64 = @floatFromInt(n);
    var i: u4 = 0;

    while (v >= 1024 and i < @backingInt(BytePrefix.YiB)) {
        v /= 1024;
        i += 1;
    }

    return .{ .value = v, .prefix = @fromBackingInt(@intCast(i)) };
}
