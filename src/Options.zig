// Copyright 2026 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const Self = @This();

const build_options = @import("build_options");

const builtin = @import("builtin");
const std = @import("std");

const ntz = @import("ntz");
const encoding = ntz.encoding;
const ctxlog = encoding.ctxlog;
const logging = ntz.logging;
const types = ntz.types;
const bytes = types.bytes;
const ui = ntz.ui;
const cli = ui.cli;

const cleaner = @import("cleaner/root.zig");

bit_rate: cleaner.BitRate = .@"128k",
destination: []const u8 = "",
sources: []const []const u8 = &.{},

log: struct {
    file: []const u8 = "",
    format: LogEncoder.Format = .ctxlog,

    level: logging.Level = switch (builtin.mode) {
        .Debug => .debug,
        .ReleaseSafe => .warn,
        .ReleaseFast, .ReleaseSmall => .@"error",
    },
} = .{},

pub fn deinit(opts: Self, allocator: std.mem.Allocator) void {
    if (opts.destination.len > 0) allocator.free(opts.destination);

    for (opts.sources) |source| allocator.free(source);
    if (opts.sources.len > 0) allocator.free(opts.sources);

    if (opts.log.file.len > 0) allocator.free(opts.log.file);
}

pub fn clone(
    opts: Self,
    allocator: std.mem.Allocator,
) std.mem.Allocator.Error!Self {
    var new_opts = opts;

    if (opts.destination.len > 0)
        new_opts.destination = try allocator.dupe(u8, opts.destination);

    if (opts.sources.len > 0) {
        var new_sources = try allocator.alloc([]const u8, opts.sources.len);

        for (0..opts.sources.len) |i|
            new_sources[i] = try allocator.dupe(u8, opts.sources[i]);

        new_opts.sources = new_sources;
    }

    if (opts.log.file.len > 0)
        new_opts.log.file = try allocator.dupe(u8, opts.log.file);

    return new_opts;
}

// //////
// CLI //
// //////

pub const Command = cli.Command(Self);

pub fn command(
    io: std.Io,
    allocator: std.mem.Allocator,
    status: *ntz.Status,
    log: ntz.logging.DefaultLogger,
) !*Command {
    const cmd = try allocator.create(Command);

    cmd.* = .{
        .io = io,
        .allocator = allocator,
        .status = status,
        .log = log,

        .id = build_options.name,
        .name = build_options.name,
        .version = build_options.version,
        .description = "clean and reduce music files",
        .usage = "Usage: " ++ build_options.name ++ " [<options>] <destination> <source>...\n",

        .copyright =
        \\Copyright (c) 2023 Miguel Angel Rivera Notararigo
        \\Released under the MIT License
        ,

        .action = Self.cliMain,
    };

    try cmd.addOption(.{
        .id = "bit_rate",
        .flags = &.{ "-b", "--bit-rate" },
        .env = "BIT_RATE",
        .help = "Output audio bit rate",
        .placeholder = "rate",
        .default = "128",
        .valid_values = &.{ "128", "192", "320" },
        .action = cliBitRate,
    });

    // Logging.

    try cmd.addOption(.{
        .id = "log_file",
        .flags = &.{"--log-file"},
        .env = "LOG_FILE",
        .help = "Use given file as log file",
        .placeholder = "file",
        .action = cliLogFile,
    });

    try cmd.addOption(.{
        .id = "log_format",
        .flags = &.{"--log-format"},
        .env = "LOG_FORMAT",
        .help = "Use given format as log encoding format",
        .placeholder = "format",
        .default = "ctxlog",
        .valid_values = &.{ "ctxlog", "json" },
        .action = cliLogFormat,
    });

    try cmd.addOption(.{
        .id = "log_level",
        .flags = &.{"--log-level"},
        .env = "LOG_LEVEL",
        .help = "Minimum severity for log records",
        .placeholder = "level",
        .valid_values = &.{ "debug", "info", "warn", "error", "fatal", "disabled" },
        .action = cliLogLevel,
    });

    try cmd.addOption(Command.envFileOption);
    try cmd.addOption(Command.helpOption);
    try cmd.addOption(Command.versionOption);

    return cmd;
}

fn cliMain(
    opts: *Self,
    arena: std.mem.Allocator,
    cmd: Command,
    args: []const []const u8,
) !void {
    switch (args.len) {
        0...1 => {
            cmd.log.err("not enough arguments");
            return error.MissingValue;
        },

        2 => {
            cmd.log.err("no source given");
            return error.MissingValue;
        },

        else => {
            try opts.cliDestination(arena, cmd, args[1]);
            try opts.cliSources(arena, cmd, args[2..]);
        },
    }
}

fn cliDestination(
    opts: *Self,
    _: std.mem.Allocator,
    cmd: Command,
    value: []const u8,
) !void {
    if (value.len == 0) {
        cmd.log.err("no destination given");
        return error.MissingValue;
    }

    opts.destination = value;
}

fn cliSources(
    opts: *Self,
    _: std.mem.Allocator,
    cmd: Command,
    value: []const []const u8,
) !void {
    if (value.len == 0) {
        cmd.log.err("no sources given");
        return error.MissingValue;
    }

    opts.sources = value;
}

fn cliBitRate(
    opts: *Self,
    arena: std.mem.Allocator,
    cmd: Command,
    value: []const u8,
) !void {
    if (value.len == 0) {
        cmd.log.err("no bit rate given");
        return error.MissingValue;
    }

    if (bytes.equalAny(value, &.{ "128", "128k", "128kb/s", "128kbps" })) {
        opts.bit_rate = .@"128k";
    } else if (bytes.equalAny(value, &.{ "192", "192k", "192kb/s", "192kbps" })) {
        opts.bit_rate = .@"192k";
    } else if (bytes.equalAny(value, &.{ "320", "320k", "320kb/s", "320kbps" })) {
        opts.bit_rate = .@"320k";
    } else {
        const msg = "invalid bit rate '{s}'";
        cmd.log.errf(arena, msg, .{value});
        return error.InvalidValue;
    }
}

// //////////
// Logging //
// //////////

pub const LogContext = struct {
    level: []const u8,
    msg: []const u8,
    @"error": ?anyerror,
    //utf8: ?codepoints.LogContext,
};

pub const LogEncoder = struct {
    pub const Format = enum {
        ctxlog,
        json,
    };

    format: Format = .ctxlog,

    ctxlog_enc: ctxlog.Encoder,

    json_enc: struct {
        pub fn encode(_: @This(), writer: *std.Io.Writer, val: anytype) !void {
            var enc = std.json.Stringify{
                .writer = writer,
                .options = .{ .emit_null_optional_fields = false },
            };

            try enc.write(val);
        }
    },

    pub fn encode(e: @This(), writer: *std.Io.Writer, val: anytype) !void {
        switch (e.format) {
            .ctxlog => try e.ctxlog_enc.encode(writer, val),
            .json => try e.json_enc.encode(writer, val),
        }
    }
};

fn cliLogFile(
    opts: *Self,
    _: std.mem.Allocator,
    cmd: Command,
    value: []const u8,
) !void {
    if (value.len == 0) {
        cmd.log.info("using stdout as log file");
    }

    opts.log.file = value;
}

fn cliLogFormat(
    opts: *Self,
    arena: std.mem.Allocator,
    cmd: Command,
    value: []const u8,
) !void {
    if (value.len == 0) {
        cmd.log.err("no log format given");
        return error.EmptyValue;
    }

    if (bytes.equal(value, "ctxlog")) {
        opts.log.format = .ctxlog;
    } else if (bytes.equal(value, "json")) {
        opts.log.format = .json;
    } else {
        cmd.log.errf(arena, "invalid log format '{s}'", .{value});
        return error.InvalidValue;
    }
}

fn cliLogLevel(
    opts: *Self,
    arena: std.mem.Allocator,
    cmd: Command,
    value: []const u8,
) !void {
    if (value.len == 0) {
        cmd.log.err("no log severity given");
        return error.EmptyValue;
    }

    opts.log.level = logging.Level.fromKey(value) catch |err| {
        const msg = "invalid log severity '{s}'";
        cmd.log.withError(err).errf(arena, msg, .{value});
        return err;
    };
}
