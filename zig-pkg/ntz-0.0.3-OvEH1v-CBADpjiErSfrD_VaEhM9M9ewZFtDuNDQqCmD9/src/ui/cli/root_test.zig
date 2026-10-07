// Copyright 2026 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");
const testing = std.testing;

const ntz = @import("ntz");
const logging = ntz.logging;
const types = ntz.types;
const bytes = types.bytes;
const ui = ntz.ui;

const cli = ui.cli;

test "ntz.os.cli" {
    const io = testing.io;
    const ally = testing.allocator;
    const status = ntz.Status{ .io = io };

    // Logger //

    var log_buf = bytes.buffer(ally);
    defer log_buf.deinit();
    var log_buf_writer = log_buf.writer().toStd(&.{});
    var log_writer = &log_buf_writer.interface;
    _ = &log_writer;

    const log = logging.initWith(log_writer).withSeverity(.debug);

    // Command //

    const cmd = try Options.command(io, ally, &status, log);
    defer ally.destroy(cmd);
    defer cmd.deinit();

    // Load options //

    var arena_ally = std.heap.ArenaAllocator.init(ally);
    defer arena_ally.deinit();
    const arena = arena_ally.allocator();

    var opts = Options{};
    var entries: cli.Entries = .{};

    cmd.fromEnvString(arena, &opts, &entries, "LOG_LEVEL=\"error\"") catch |err| {
        std.debug.print("{s}\n", .{log_buf.bytes()});
        return err;
    };

    cmd.fromArgsSlice(arena, &opts, &entries, &.{
        "numbers", "--log-file", "log.ctxlog",
    }) catch |err| {
        std.debug.print("{s}\n", .{log_buf.bytes()});
        return err;
    };

    const entries_want: []const cli.Entry = &.{
        .{ .kind = .env, .command = "numbers", .key = "LOG_LEVEL", .value = "error" },
        .{ .kind = .flag, .command = "numbers", .key = "--log-file", .value = "log.ctxlog" },
        .{ .kind = .argument, .command = "numbers", .key = "", .value = "numbers" },
    };

    try testing.expectEqual(entries_want.len, entries.len);

    for (entries.items(), entries_want) |got, want| {
        try testing.expectEqualDeep(want, got);
    }

    cmd.load(arena, &opts, entries.items()) catch |err| {
        std.debug.print("{s}\n", .{log_buf.bytes()});
        return err;
    };

    opts = try opts.clone(ally);
    defer opts.deinit(ally);
}

const Options = struct {
    const Self = @This();

    first: usize = 0,
    last: usize = 10,
    interval: usize = 1,

    calc: struct {
        operation: enum { none, add, sub, mul, div } = .none,
    } = .{},

    log: struct {
        file: []const u8 = "",
        level: logging.Level = .@"error",
    } = .{},

    pub fn deinit(opts: Self, allocator: std.mem.Allocator) void {
        if (opts.log.file.len > 0) allocator.free(opts.log.file);
    }

    pub fn clone(
        opts: Self,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!Self {
        var new_opts = opts;

        new_opts.log.file = if (opts.log.file.len > 0)
            try allocator.dupe(u8, opts.log.file)
        else
            "";

        return new_opts;
    }

    // //////
    // CLI //
    // //////

    pub const Command = cli.Command(Self);

    pub fn command(
        io: std.Io,
        allocator: std.mem.Allocator,
        status: *const ntz.Status,
        log: logging.DefaultLogger,
    ) !*Command {
        const cmd_id = "numbers";

        const cmd = try allocator.create(Command);

        cmd.* = .{
            .io = io,
            .allocator = allocator,
            .status = status,
            .log = log,

            .id = cmd_id,
            .name = cmd_id,
            .version = "0.0.1",
            .description = "print a range of numbers",

            .longDescription =
            \\Print a range of numbers starting from <first number> and ending on
            \\<last number> with the given interval. This will not print more than 5
            \\numbers.
            ,

            .usage = "Usage: " ++ cmd_id ++ " [<options>] <last number>\n" ++
                "  or:  " ++ cmd_id ++ " [<options>] <last number> <interval>\n" ++
                "  or:  " ++ cmd_id ++ " [<options>] <first number> <last number> <interval>\n",

            .copyright =
            \\Copyright (c) 2026 Miguel Angel Rivera Notararigo
            \\Released under the MIT License
            ,

            .action = Self.cliMain,
        };

        try cmd.addOption(.{
            .id = "log_file",
            .flags = &.{"--log-file"},
            .env = "LOG_FILE",
            .help = "Use given file as log file",
            .placeholder = "file",
            .action = cliLogFile,
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

        // calc subcommand //

        var cmdCalc = try cmd.addCommand(
            cmd_id ++ ".calc",
            "calc",
            &.{ "c", "clc" },
            cliMain,
        );

        cmdCalc.description = "Do some math operations on the given range instead of just printing them";
        cmdCalc.env_prefix = "CALC_";

        try cmdCalc.addOption(.{
            .id = "first",
            .flags = &.{ "-f", "--first" },
            .env = "FIRST",
            .help = "First number",
            .placeholder = "number",
            .action = cliFirst,
        });

        try cmdCalc.addOption(.{
            .id = "last",
            .flags = &.{ "-l", "--last" },
            .env = "LAST",
            .help = "Last number",
            .placeholder = "number",
            .action = cliLast,
        });

        try cmdCalc.addOption(.{
            .id = "interval",
            .flags = &.{ "-i", "--interval" },
            .env = "INTERVAL",
            .help = "Interval",
            .placeholder = "interval",
            .has_optional_value = true,
            .default = "2",
            .action = cliInterval,
        });

        try cmdCalc.addOption(.{
            .id = "operation",
            .flags = &.{ "-o", "--operation", "--op" },
            .env = "OPERATION",
            .help = "interval",
            .placeholder = "operation",

            .valid_values = &.{
                "add", "s", "+",
                "sub", "s", "-",
                "mul", "m", "*",
                "div", "d", "/",
            },

            .action = cliOperation,
        });

        try cmdCalc.addOption(Command.helpOption);

        return cmd;
    }

    fn cliMain(
        opts: *Self,
        arena: std.mem.Allocator,
        cmd: Command,
        args: []const []const u8,
    ) !void {
        switch (args.len) {
            0...1 => {},
            2 => try opts.cliLast(arena, cmd, args[1]),

            3 => {
                try opts.cliFirst(arena, cmd, args[1]);
                try opts.cliLast(arena, cmd, args[2]);
            },

            4 => {
                try opts.cliFirst(arena, cmd, args[1]);
                try opts.cliLast(arena, cmd, args[2]);
                try opts.cliInterval(arena, cmd, args[3]);
            },

            else => {
                cmd.log.err("too many arguments");
            },
        }
    }

    fn cliFirst(
        opts: *Self,
        arena: std.mem.Allocator,
        cmd: Command,
        value: []const u8,
    ) !void {
        if (value.len == 0) {
            cmd.log.err("no first number given");
            return error.MissingValue;
        }

        const first_num = std.fmt.parseInt(usize, value, 0) catch |err| {
            const msg = "invalid first number '{s}'";
            cmd.log.withError(err).errf(arena, msg, .{value});
            return err;
        };

        if (first_num > opts.last) {
            const msg = "first number cannot be greater than last";
            cmd.log.err(msg);
            return error.InvalidValue;
        }

        opts.first = first_num;
    }

    fn cliLast(
        opts: *Self,
        arena: std.mem.Allocator,
        cmd: Command,
        value: []const u8,
    ) !void {
        if (value.len == 0) {
            cmd.log.err("no last number given");
            return error.MissingValue;
        }

        const last_num = std.fmt.parseInt(usize, value, 0) catch |err| {
            const msg = "invalid last number '{s}'";
            cmd.log.withError(err).errf(arena, msg, .{value});
            return err;
        };

        if (last_num < opts.first) {
            const msg = "last number cannot be lower than first";
            cmd.log.err(msg);
            return error.InvalidValue;
        }

        opts.last = last_num + 1;
    }

    fn cliInterval(
        opts: *Self,
        arena: std.mem.Allocator,
        cmd: Command,
        value: []const u8,
    ) !void {
        if (value.len == 0) {
            cmd.log.err("no interval given");
            return error.MissingValue;
        }

        const interval = std.fmt.parseInt(usize, value, 0) catch |err| {
            const msg = "invalid interval '{s}'";
            cmd.log.withError(err).errf(arena, msg, .{value});
            return err;
        };

        if (interval < 1) {
            const msg = "interval cannot be lower than 1";
            cmd.log.err(msg);
            return error.InvalidValue;
        }

        opts.interval = interval;
    }

    fn cliOperation(
        opts: *Self,
        _: std.mem.Allocator,
        cmd: Command,
        value: []const u8,
    ) !void {
        if (value.len == 0) {
            cmd.log.err("no operation given");
            return error.MissingValue;
        }

        opts.calc.operation = if (bytes.equalAny(value, &.{ "add", "a", "+" }))
            .add
        else if (bytes.equalAny(value, &.{ "sub", "s", "-" }))
            .sub
        else if (bytes.equalAny(value, &.{ "mul", "m", "*" }))
            .mul
        else if (bytes.equalAny(value, &.{ "div", "d", "/" }))
            .div
        else
            return error.InvalidValue;
    }

    // Logging.

    fn cliLogFile(
        opts: *Self,
        _: std.mem.Allocator,
        _: Command,
        value: []const u8,
    ) !void {
        if (value.len == 0) return;
        opts.log.file = value;
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
};
