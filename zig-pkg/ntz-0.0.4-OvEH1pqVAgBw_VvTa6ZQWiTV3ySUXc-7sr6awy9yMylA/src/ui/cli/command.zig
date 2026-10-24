// Copyright 2026 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");

const Status = @import("../../Status.zig");
const encoding = @import("../../encoding/root.zig");
const logging = @import("../../logging/root.zig");
const types = @import("../../types/root.zig");
const bytes = types.bytes;
const slices = types.slices;

const cli = @import("root.zig");

pub fn Command(comptime Context: type) type {
    return struct {
        const Self = @This();

        pub const Action = *const fn (
            ctx: *Context,
            arena: std.mem.Allocator,
            cmd: Self,
            args: []const []const u8,
        ) anyerror!void;

        parent: ?*const Self = null,
        action: ?Action = null,

        io: std.Io,
        allocator: std.mem.Allocator,
        status: *const Status,
        log: logging.DefaultLogger = logging.init(),

        opts: slices.Slice(cli.Option(Self, Context)) = .{},
        cmds: slices.Slice(Self) = .{},

        env_prefix: []const u8 = "",
        flags_prefix: []const u8 = "",

        id: []const u8,
        name: []const u8,
        aliases: []const []const u8 = &.{},
        version: []const u8,
        version_info: []const u8 = "",
        description: []const u8 = "",
        longDescription: []const u8 = "",
        usage: []const u8 = "",
        epilog: []const u8 = "",
        copyright: []const u8 = "",

        pub fn deinit(cmd: *Self) void {
            cmd.opts.deinit(cmd.allocator);
            for (cmd.cmds.items()) |*sub_cmd| sub_cmd.deinit();
            cmd.cmds.deinit(cmd.allocator);
        }

        pub fn load(
            cmd: Self,
            arena: std.mem.Allocator,
            ctx: *Context,
            entries: []const cli.Entry,
        ) !void {
            for (cmd.opts.items()) |opt| {
                if (cmd.status.isDone()) return error.Canceled;

                opt.load(arena, cmd, ctx, entries) catch |err| {
                    const msg = "cannot load option '{s}'";
                    cmd.log.withError(err).errf(arena, msg, .{opt.id});
                    return err;
                };
            }

            var args: slices.Slice([]const u8) = .{};

            for (entries) |entry| {
                if (cmd.status.isDone()) return error.Canceled;

                if (entry.kind == .argument) {
                    try args.append(arena, entry.value);
                    continue;
                }

                if (entry.kind != .command) continue;

                const name = entry.value;

                for (cmd.cmds.items()) |*sub_cmd| {
                    if (!bytes.equal(name, sub_cmd.name) and
                        !bytes.equalAny(name, sub_cmd.aliases))
                        continue;

                    return sub_cmd.load(arena, ctx, entries) catch |err| {
                        const msg = "cannot load option entries for subcommand '{s}'";
                        cmd.log.withError(err).errf(arena, msg, .{sub_cmd.name});
                        return err;
                    };
                }
            }

            if (cmd.action) |act| try act(ctx, arena, cmd, args.items());
        }

        // ///////////////
        // Sub commands //
        // ///////////////

        pub fn addCommand(
            cmd: *Self,
            comptime id: []const u8,
            comptime name: []const u8,
            comptime aliases: []const []const u8,
            action: ?Action,
        ) !*Self {
            return cmd.cmds.appendAndReturn(cmd.allocator, .{
                .parent = cmd,
                .action = action,

                .io = cmd.io,
                .allocator = cmd.allocator,
                .status = cmd.status,
                .log = cmd.log,

                .env_prefix = cmd.env_prefix,
                .flags_prefix = cmd.flags_prefix,

                .id = id,
                .name = name,
                .aliases = aliases,
                .version = cmd.version,
                .version_info = cmd.version_info,
                .copyright = cmd.copyright,
            });
        }

        // //////////
        // Options //
        // //////////

        pub const AddOptionError = error{
            NoOptionId,
        } || std.mem.Allocator.Error;

        pub fn addOption(
            cmd: *Self,
            opt: cli.Option(Self, Context),
        ) AddOptionError!void {
            try cmd.opts.append(cmd.allocator, opt);
        }

        // Default options //

        pub const envFileOption: cli.Option(Self, Context) = .{
            .id = "env_file",
            .flags = &.{"--env-file"},
            .help = "Read environment variables from the given file",
            .placeholder = "file",
            .has_optional_value = true,
            .default = ".env",
            .readAction = Self.envFileReadAction,
            .action = Self.emptyAction,
        };

        pub const genConfigOption: cli.Option(Self, Context) = .{
            .id = "",
            .flags = &.{"--gen-config"},
            .help = "Prints a sample configuration file to stdout",
            .placeholder = "format",
            .has_optional_value = true,
            .default = "ini",
            .valid_values = &.{ "env", "ini" },
            .readAction = Self.genConfigAction,
            .action = Self.emptyAction,
        };

        pub const helpOption: cli.Option(Self, Context) = .{
            .id = "",
            .flags = &.{"--help"},
            .help = "Print this help message",
            .placeholder = "option_id",
            .has_optional_value = true,
            .readAction = Self.helpReadAction,
            .action = Self.emptyAction,
        };

        pub const versionOption: cli.Option(Self, Context) = .{
            .id = "",
            .flags = &.{"--version"},
            .help = "Print version number",
            .is_boolean = true,
            .readAction = Self.versionAction,
            .action = Self.emptyAction,
        };

        // Default actions //

        pub fn emptyAction(
            _: *Context,
            _: std.mem.Allocator,
            _: Self,
            _: cli.Entry,
        ) !void {}

        pub fn envFileReadAction(
            ctx: *Context,
            arena: std.mem.Allocator,
            cmd: Self,
            entries: *cli.Entries,
            entry: cli.Entry,
        ) !void {
            const name = entry.value;

            cmd.fromEnvFile(arena, ctx, entries, name) catch |err| {
                const msg = "cannot read option entries from env file '{s}'";
                cmd.log.withError(err).errf(arena, msg, .{name});
                return err;
            };
        }

        pub fn genConfigAction(
            _: *Context,
            arena: std.mem.Allocator,
            cmd: Self,
            _: *cli.Entries,
            entry: cli.Entry,
        ) !void {
            const value = entry.value;

            var stdout = std.Io.File.stdout();
            var stdout_writer = stdout.writer(cmd.io, &.{});

            if (bytes.equal(value, "env")) {
                try cli.writeConfigFileEnv(&stdout_writer.interface, cmd);
            } else if (bytes.equal(value, "ini")) {
                try cli.writeConfigFileIni(&stdout_writer.interface, cmd);
            } else {
                const msg = "invalid format for configuration file '{s}'";
                cmd.log.errf(arena, msg, .{value});
                return error.InvalidValue;
            }

            std.process.exit(0);
        }

        pub fn helpReadAction(
            _: *Context,
            arena: std.mem.Allocator,
            cmd: Self,
            _: *cli.Entries,
            entry: cli.Entry,
        ) !void {
            var stdout = std.Io.File.stdout();
            var stdout_writer = stdout.writer(cmd.io, &.{});
            var writer = &stdout_writer.interface;
            _ = &writer;

            if (entry.value.len > 0) {
                const id = entry.value;

                for (cmd.opts.items()) |opt| {
                    if (bytes.equal(id, opt.id)) break;
                } else {
                    const msg = "invalid option '{s}'";
                    cmd.log.errf(arena, msg, .{id});
                    return error.InvalidOption;
                }

                try cli.writeOptionHelp(writer, cmd, entry.value);
            } else {
                try cli.writeHelp(writer, cmd);
            }

            std.process.exit(0);
        }

        pub fn versionAction(
            _: *Context,
            _: std.mem.Allocator,
            cmd: Self,
            _: *cli.Entries,
            _: cli.Entry,
        ) !void {
            var stdout = std.Io.File.stdout();
            var stdout_writer = stdout.writer(cmd.io, &.{});
            try cli.writeVersion(&stdout_writer.interface, cmd);
            std.process.exit(0);
        }

        // //////////
        // Reading //
        // //////////

        pub fn fromInit(
            cmd: Self,
            arena: std.mem.Allocator,
            ctx: *Context,
            init: std.process.Init,
        ) !void {
            return cmd.fromInitMinimal(arena, ctx, init.minimal);
        }

        pub fn fromInitMinimal(
            cmd: Self,
            arena: std.mem.Allocator,
            ctx: *Context,
            init: std.process.Init.Minimal,
        ) !void {
            var entries: cli.Entries = .{};

            cmd.fromEnv(arena, ctx, &entries, init.environ) catch |err| {
                const msg = "cannot read option entries from environment variables";
                cmd.log.withError(err).err(msg);
                return err;
            };

            cmd.fromArgs(arena, ctx, &entries, init.args) catch |err| {
                const msg = "cannot read option entries from arguments";
                cmd.log.withError(err).err(msg);
                return err;
            };

            cmd.load(arena, ctx, entries.items()) catch |err| {
                const msg = "cannot load option entries";
                cmd.log.withError(err).err(msg);
                return err;
            };
        }

        // Arguments and flags //

        pub fn fromArgs(
            cmd: Self,
            arena: std.mem.Allocator,
            ctx: *Context,
            entries: *cli.Entries,
            args: std.process.Args,
        ) !void {
            const args_slc = args.toSlice(arena) catch |err| {
                const msg = "cannot get command line arguments";
                cmd.log.withError(err).err(msg);
                return err;
            };

            try cmd.fromArgsSlice(arena, ctx, entries, args_slc);
        }

        pub fn fromArgsIterator(
            cmd: Self,
            arena: std.mem.Allocator,
            ctx: *Context,
            entries: *cli.Entries,
            args: *slices.Iterator([]const u8),
        ) !void {
            var pos_args: slices.Slice([]const u8) = .{};
            try pos_args.append(arena, args.next() orelse cmd.name);

            var no_more_flags = false;
            var is_first_arg = true;

            while (args.next()) |arg| {
                const is_flag = !no_more_flags and bytes.startsWith(arg, "-");

                if (!is_flag) {
                    if (is_first_arg) {
                        for (cmd.cmds.items()) |sub_cmd| {
                            if (!bytes.equal(arg, sub_cmd.name) and
                                !bytes.equalAny(arg, sub_cmd.aliases))
                                continue;

                            const entry = cli.Entry{
                                .kind = .command,
                                .command = cmd.id,
                                .key = "",
                                .value = arg,
                            };

                            try entries.append(arena, entry);
                            args.index -= 1;

                            return sub_cmd.fromArgsIterator(arena, ctx, entries, args) catch |err| {
                                const msg = "cannot read flags for subcommand '{s}'";
                                cmd.log.withError(err).errf(arena, msg, .{sub_cmd.name});
                                return err;
                            };
                        }

                        is_first_arg = false;
                    }

                    try pos_args.append(arena, arg);
                    continue;
                }

                if (bytes.equal(arg, "--")) {
                    no_more_flags = true;
                    continue;
                }

                if (cmd.flags_prefix.len > 0 and
                    !bytes.startsWith(arg, cmd.flags_prefix))
                    continue;

                const j = bytes.findAt(cmd.flags_prefix.len, arg, '=');
                const has_value = if (j) |_| true else false;
                const key = arg[cmd.flags_prefix.len .. j orelse arg.len];
                var value = if (j) |i| arg[i + 1 ..] else "";

                for (cmd.opts.items()) |opt| {
                    if (!bytes.equalAny(key, opt.flags)) continue;

                    if (!opt.is_boolean and !has_value) {
                        value = if (!opt.has_optional_value)
                            args.next() orelse {
                                const msg = "missing value for flag '{s}'";
                                cmd.log.errf(arena, msg, .{key});
                                return error.MissingValue;
                            }
                        else
                            opt.default;
                    }

                    const entry = cli.Entry{
                        .kind = .flag,
                        .command = cmd.id,
                        .key = key,
                        .value = value,
                    };

                    if (opt.readAction) |act| {
                        try act(ctx, arena, cmd, entries, entry);
                    } else {
                        try entries.append(arena, entry);
                    }

                    break;
                } else {
                    const msg = "unknown flag '{s}'";
                    cmd.log.errf(arena, msg, .{arg});
                    return error.UnknowFlag;
                }
            }

            for (pos_args.items()) |arg| {
                const entry = cli.Entry{
                    .kind = .argument,
                    .command = cmd.id,
                    .key = "",
                    .value = arg,
                };

                try entries.append(arena, entry);
            }
        }

        pub fn fromArgsSlice(
            cmd: Self,
            arena: std.mem.Allocator,
            ctx: *Context,
            entries: *cli.Entries,
            slc: []const []const u8,
        ) !void {
            var it = slices.iterator(slc);
            try cmd.fromArgsIterator(arena, ctx, entries, &it);
        }

        // Environment variables //

        pub fn fromEnv(
            cmd: Self,
            arena: std.mem.Allocator,
            ctx: *Context,
            entries: *cli.Entries,
            env: std.process.Environ,
        ) !void {
            const env_map = env.createMap(arena) catch |err| {
                const msg = "cannot get environment variables";
                cmd.log.withError(err).err(msg);
                return err;
            };

            try cmd.fromEnvMap(arena, ctx, entries, env_map);
        }

        pub fn fromEnvFile(
            cmd: Self,
            arena: std.mem.Allocator,
            ctx: *Context,
            entries: *cli.Entries,
            name: []const u8,
        ) !void {
            const cwd = std.Io.Dir.cwd();

            const data = cwd.readFileAlloc(cmd.io, name, arena, .unlimited) catch |err| {
                const msg = "cannot read env file '{s}'";
                cmd.log.withError(err).errf(arena, msg, .{name});
                return err;
            };

            try cmd.fromEnvBytes(arena, ctx, entries, data);
        }

        pub fn fromEnvMap(
            cmd: Self,
            arena: std.mem.Allocator,
            ctx: *Context,
            entries: *cli.Entries,
            env: std.process.Environ.Map,
        ) !void {
            const prefix = cmd.env_prefix;

            for (cmd.opts.items()) |opt| {
                if (opt.env.len == 0) continue;

                const key = if (prefix.len == 0)
                    opt.env
                else
                    try bytes.concat(arena, prefix, opt.env);

                const value = env.get(key) orelse continue;

                const entry = cli.Entry{
                    .kind = .env,
                    .command = cmd.id,
                    .key = key,
                    .value = value,
                };

                if (opt.readAction) |act| {
                    try act(ctx, arena, cmd, entries, entry);
                } else {
                    try entries.append(arena, entry);
                }
            }

            for (cmd.cmds.items()) |sub_cmd|
                try sub_cmd.fromEnvMap(arena, ctx, entries, env);
        }

        pub fn fromEnvBytes(
            cmd: Self,
            arena: std.mem.Allocator,
            ctx: *Context,
            entries: *cli.Entries,
            data: []const u8,
        ) !void {
            var env = std.process.Environ.Map.init(arena);

            var ln: usize = 1;
            var it = bytes.splitIterator(data, '\n');

            while (it.next()) |line| : (ln += 1) {
                if (line.len == 0) continue;
                if (line[0] == '#') continue;

                const eq_i = bytes.find(line, '=');

                if (eq_i == null or eq_i.? == line.len - 1) {
                    const msg = "missing value for key '{s}' in line {d}";
                    cmd.log.errf(arena, msg, .{ line, ln });
                    return error.MissingValue;
                }

                const key = line[0..eq_i.?];
                var value = line[eq_i.? + 1 ..];

                if (value[0] == '"') {
                    if (value.len == 1 or value[value.len - 1] != '"') {
                        const msg = "unclosed quote for '{s}' in line {d}";
                        cmd.log.errf(arena, msg, .{ key, ln });
                        return error.InvalidSyntax;
                    }

                    value = value[1 .. value.len - 1];
                }

                try env.put(key, value);
            }

            try cmd.fromEnvMap(arena, ctx, entries, env);
        }

        // Configuration //

        pub const ConfigEntry = struct {
            key: []const u8,
            value: []const u8,
        };

        pub fn fromConfig(
            cmd: Self,
            arena: std.mem.Allocator,
            ctx: *Context,
            entries: *cli.Entries,
            cfgEntries: []const ConfigEntry,
        ) !void {
            for (cfgEntries) |cfg| {
                for (cmd.opts.items()) |opt| {
                    if (opt.id.len == 0) continue;

                    const key = if (cmd.parent == null)
                        opt.id
                    else
                        try bytes.concatMany(arena, &.{ cmd.id, ".", opt.id });

                    if (!bytes.equal(cfg.key, key)) continue;

                    const entry = cli.Entry{
                        .kind = .config,
                        .command = cmd.id,
                        .key = opt.id,
                        .value = cfg.value,
                    };

                    if (opt.readAction) |act| {
                        try act(ctx, arena, cmd, entries, entry);
                    } else {
                        try entries.append(arena, entry);
                    }

                    break;
                } else {
                    if (!bytes.startsWith(cfg.key, cmd.id)) continue;
                    const key = cfg.key[cmd.id.len + 1 ..];
                    if (bytes.find(key, '.') != null) continue;

                    const msg = "unknown config entry '{s}'";
                    cmd.log.errf(arena, msg, .{cfg.key});
                    return error.UnknowEntry;
                }
            }

            for (cmd.cmds.items()) |sub_cmd|
                try sub_cmd.fromConfig(arena, ctx, entries, cfgEntries);
        }

        pub fn fromConfigIniFile(
            cmd: Self,
            arena: std.mem.Allocator,
            ctx: *Context,
            entries: *cli.Entries,
            name: []const u8,
        ) !void {
            const cwd = std.Io.Dir.cwd();

            const data = cwd.readFileAlloc(cmd.io, name, arena, .unlimited) catch |err| {
                const msg = "cannot read ini file '{s}'";
                cmd.log.withError(err).errf(arena, msg, .{name});
                return err;
            };

            try cmd.fromConfigIniBytes(arena, ctx, entries, data);
        }

        pub fn fromConfigIniBytes(
            cmd: Self,
            arena: std.mem.Allocator,
            ctx: *Context,
            entries: *cli.Entries,
            data: []const u8,
        ) !void {
            var cfgs: slices.Slice(ConfigEntry) = .{};

            var prefix: []const u8 = "";
            var ln: usize = 1;
            var it = bytes.splitIterator(data, '\n');

            while (it.next()) |line| : (ln += 1) {
                if (line.len == 0) continue;
                if (line[0] == '#' or line[0] == ';') continue;

                if (line[0] == '[') {
                    const j = bytes.find(line, ']');

                    if (j == null) {
                        const msg = "missing ']' in line {d}";
                        cmd.log.errf(arena, msg, .{ln});
                        return error.InvalidSyntax;
                    }

                    prefix = line[1..j.?];
                    continue;
                }

                const eq_i = bytes.find(line, '=');

                if (eq_i == null or eq_i.? == line.len - 1) {
                    const msg = "missing value for key '{s}' in line {d}";
                    cmd.log.errf(arena, msg, .{ line, ln });
                    return error.MissingValue;
                }

                const key = try bytes.concatMany(arena, &.{
                    prefix,
                    ".",
                    line[0..eq_i.?],
                });

                var value = line[eq_i.? + 1 ..];

                if (value[0] == '"') {
                    if (value.len == 1 or value[value.len - 1] != '"') {
                        const msg = "unclosed quote for '{s}' in line {d}";
                        cmd.log.errf(arena, msg, .{ key, ln });
                        return error.InvalidSyntax;
                    }

                    value = value[1 .. value.len - 1];
                }

                try cfgs.append(arena, .{ .key = key, .value = value });
            }

            try cmd.fromConfig(arena, ctx, entries, cfgs.items());
        }
    };
}
