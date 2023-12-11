// Copyright 2025 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");

const ntz = @import("ntz");
const types = ntz.types;
const bytes = types.bytes;

pub const BitRate = enum {
    @"128k",
    @"192k",
    @"320k",
};

pub const CleanError = error{
    InvalidDestination,
    MissingDestination,
    MissingSource,
    SourceIsNotMp3,
    SourceIsNotRegularFile,
};

pub fn clean(
    status: *ntz.Status,
    allocator: anytype,
    logger: anytype,
    bit_rate: BitRate,
    destination: []const u8,
    sources: []const []const u8,
) !void {
    if (status.isDone()) return;

    if (destination.len == 0) {
        logger.err("no destination given");
        return CleanError.MissingDestination;
    }

    const cwd = std.fs.cwd();

    var dir = cwd.openDir(destination, .{}) catch |err| {
        const msg = "invalid destination '{s}': {}";
        logger.errf(allocator, msg, .{ destination, err });
        return CleanError.InvalidDestination;
    };

    dir.close();

    if (sources.len == 0) {
        logger.err("no source given");
        return CleanError.MissingSource;
    }

    var src_total_size: u64 = 0;
    var dst_total_size: u64 = 0;

    for (sources) |src| {
        if (status.isDone()) break;

        //var arena_ally = std.heap.ArenaAllocator.init(allocator);
        //defer arena_ally.deinit();
        //const arena = arena_ally.allocator();

        logger.debugf(allocator, "processing source file '{s}'", .{src});

        if (!bytes.endsWith(src, ".mp3")) {
            logger.errf(allocator, "source file '{s}' is not an MP3 file", .{src});
            return CleanError.SourceIsNotMp3;
        }

        const src_stat = cwd.statFile(src) catch |err| {
            const msg = "cannot stat source file '{s}: {}'";
            logger.errf(allocator, msg, .{ src, err });
            return err;
        };

        if (src_stat.kind != .file) {
            const msg = "source '{s}' is not a regular file ({})";
            logger.errf(allocator, msg, .{ src, src_stat.kind });
            return CleanError.SourceIsNotRegularFile;
        }

        const name = std.fs.path.basename(src);
        const dst = try std.fs.path.join(allocator, &.{ destination, name });

        defer allocator.free(dst);

        cleanMp3(allocator, bit_rate, dst, src) catch |err| {
            logger.errf(allocator, "cannot clean '{s}': {}", .{ src, err });
            return err;
        };

        const dst_stat = cwd.statFile(dst) catch |err| {
            const msg = "cannot stat destination file '{s}': {}";
            logger.errf(allocator, msg, .{ dst, err });
            return err;
        };

        src_total_size += src_stat.size;
        dst_total_size += dst_stat.size;

        const src_size_h = humanizeBytes(src_stat.size);
        const dst_size_h = humanizeBytes(dst_stat.size);

        logger.infof(allocator, "'{s}' ({d:.2} {s}) -> '{s}' ({d:.2} {s})", .{
            src, src_size_h.value, @tagName(src_size_h.prefix),
            dst, dst_size_h.value, @tagName(dst_size_h.prefix),
        });
    }

    const src_total_size_h = humanizeBytes(src_total_size);
    const dst_total_size_h = humanizeBytes(dst_total_size);

    logger.infof(allocator, "Total: {d:.2} {s} -> {d:.2} {s}", .{
        src_total_size_h.value, @tagName(src_total_size_h.prefix),
        dst_total_size_h.value, @tagName(dst_total_size_h.prefix),
    });
}

fn cleanMp3(
    allocator: anytype,
    bit_rate: BitRate,
    destination: []const u8,
    source: []const u8,
) !void {
    const cmd = &.{
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
    };

    var child = std.process.Child.init(cmd, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Pipe;
    child.stderr = std.io.getStdErr();

    try child.spawn();
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

pub const HumanizedResult = struct {
    value: f64,
    prefix: BytePrefix,
};

pub fn humanizeBytes(n: u64) HumanizedResult {
    var v: f64 = @floatFromInt(n);
    var i: u4 = 0;

    while (v >= 1024 and i < @intFromEnum(BytePrefix.YiB)) {
        v /= 1024;
        i += 1;
    }

    return .{ .value = v, .prefix = @enumFromInt(i) };
}
