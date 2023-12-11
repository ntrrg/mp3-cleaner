const std = @import("std");
const fmt = std.fmt;
const fs = std.fs;
const io = std.io;
const log = std.log;
const mem = std.mem;
const path = fs.path;
const process = std.process;

const Self = @This();

pub const Error = error{
    InvalidFlagValue,
    MissingEnvValue,
    MissingFlagValue,
    UnclosedQuote,
    UnknowFlag,
};

pub const BitRate = enum {
    @"128k",
    @"192k",
    @"320k",
};

name: []const u8,
version: []const u8,
env_prefix: []const u8,

destination: []const u8,
sources: []const []const u8,
bit_rate: BitRate,

pub fn init(ally: mem.Allocator, values: struct {
    name: []const u8 = "",
    version: []const u8 = "",
    env_prefix: []const u8 = "",

    destination: []const u8 = "",
    sources: []const []const u8 = &.{},
    bit_rate: BitRate = .@"128k",
}) !Self {
    // Name:

    const name = ally.dupe(u8, values.name) catch |err| {
        log.err("cannot set name: {}", .{err});
        return err;
    };

    errdefer ally.free(name);

    // Version:

    const version = ally.dupe(u8, values.version) catch |err| {
        log.err("cannot set version: {}", .{err});
        return err;
    };

    errdefer ally.free(version);

    // Environment variable prefix:

    const env_prefix = ally.dupe(u8, values.env_prefix) catch |err| {
        log.err("cannot set env prefix: {}", .{err});
        return err;
    };

    errdefer ally.free(env_prefix);

    // Destination:

    const destination = ally.dupe(u8, values.destination) catch |err| {
        log.err("cannot set destination: {}", .{err});
        return err;
    };

    errdefer ally.free(destination);

    // Source:

    const sources = ally.alloc([]const u8, values.sources.len) catch |err| {
        log.err("cannot set sources: {}", .{err});
        return err;
    };

    errdefer ally.free(sources);

    for (values.sources, 0..) |source, i| {
        sources[i] = ally.dupe(u8, source) catch |err| {
            if (i > 0) for (0..i) |j| ally.free(sources[j]);

            log.err("cannot set source '{s}': {}", .{ source, err });
            return err;
        };
    }

    errdefer for (sources) |source| ally.free(source);

    // Initialize values:

    return .{
        .name = name,
        .version = version,
        .env_prefix = env_prefix,

        .destination = destination,
        .sources = sources,
        .bit_rate = values.bit_rate,
    };
}

pub fn deinit(self: *Self, ally: mem.Allocator) void {
    ally.free(self.name);
    ally.free(self.version);
    ally.free(self.env_prefix);

    ally.free(self.destination);
    for (self.sources) |source| ally.free(source);
    ally.free(self.sources);
}

pub fn clone(self: *Self, ally: mem.Allocator) !Self {
    return try Self.init(ally, .{
        .name = self.name,
        .version = self.version,
        .env_prefix = self.env_prefix,

        .destination = self.destination,
        .sources = self.sources,
        .bit_rate = self.bit_rate,
    });
}

const help_message =
    \\{[name]s} - clean and reduce MP3 files.
    \\
    \\Usage: {[name]s} [OPTIONS] DESTINATION SOURCE...
    \\
    \\Options:
    \\  -b, --bit-rate=RATE   Use RATE bit rate (*128k, 192k, 320k)
    \\      --env=FILE        Read environment variables from FILE
    \\  -h, --help            Show this help message
    \\      --version         Print version number
    \\
    \\  * - Default value.
    \\
    \\Environment variables:
    \\  - 'DESTINATION' sets given path as destination.
    \\  - 'SOURCE' sets given path as source.
    \\
    \\Copyright (c) 2023 Miguel Angel Rivera Notararigo
    \\Released under the MIT License
;

pub fn fromArgs(self: *Self, ally: mem.Allocator) !void {
    var args_it = process.argsWithAllocator(ally) catch |err| {
        log.err("cannot get arguments: {}", .{err});
        return err;
    };

    defer args_it.deinit();

    _ = args_it.next() orelse unreachable;
    try self.fromArgsIterator(ally, &args_it);
}

pub fn fromArgsIterator(self: *Self, ally: mem.Allocator, it: anytype) !void {
    var destination: []const u8 = "";
    var sources = std.ArrayList([]const u8).init(ally);
    defer sources.deinit();
    var bit_rate: ?BitRate = null;

    var no_more_flags = false;

    while (it.next()) |raw_arg| {
        const arg: []const u8 = mem.trim(u8, raw_arg, " \n\t");
        if (arg.len == 0) continue;

        const is_flag = !no_more_flags and mem.startsWith(u8, arg, "-");

        if (!is_flag) {
            if (destination.len == 0) {
                destination = arg;
                continue;
            }

            sources.append(arg) catch |err| {
                const msg = "cannot register source file '{s}': {}";
                log.err(msg, .{ arg, err });
                return err;
            };

            continue;
        }

        if (mem.eql(u8, arg, "--")) {
            no_more_flags = true;
            continue;
        }

        var pair = mem.splitScalar(u8, arg, '=');
        const arg_name = pair.first();
        var arg_val: []const u8 = pair.rest();

        const w = io.getStdOut().writer();

        if (eqlAny(u8, arg_name, &.{ "-b", "--bit-rate" })) {
            arg_val = if (arg_val.len > 0) arg_val else it.next() orelse "";

            if (arg_val.len == 0) {
                log.err("missing value for flag '{s}'", .{arg_name});
                return Error.MissingFlagValue;
            }

            if (eqlAny(u8, arg_val, &.{
                "128", "128k", "128kb/s", "128kbps",
            })) {
                bit_rate = .@"128k";
            } else if (eqlAny(u8, arg_val, &.{
                "192", "192k", "192kb/s", "192kbps",
            })) {
                bit_rate = .@"192k";
            } else if (eqlAny(u8, arg_val, &.{
                "320", "320k", "320kb/s", "320kbps",
            })) {
                bit_rate = .@"320k";
            } else {
                log.err("invalid bit rate given: '{s}'", .{arg_val});
                return Error.InvalidFlagValue;
            }
        } else if (mem.eql(u8, arg_name, "--env")) {
            arg_val = if (arg_val.len > 0) arg_val else it.next() orelse "";

            if (arg_val.len == 0) {
                log.err("missing value for flag '{s}'", .{arg_name});
                return Error.MissingFlagValue;
            }

            try self.fromEnvFile(ally, arg_val);
        } else if (eqlAny(u8, arg_name, &.{ "-h", "--help" })) {
            const msg = help_message ++ "\n";

            fmt.format(w, msg, .{ .name = self.name }) catch |err| {
                log.err("cannot write help message: {}", .{err});
                return err;
            };

            process.exit(0);
        } else if (mem.eql(u8, arg_name, "--version")) {
            fmt.format(w, "{s}\n", .{self.version}) catch |err| {
                log.err("cannot write program version: {}", .{err});
                return err;
            };

            process.exit(0);
        } else {
            log.err("unknow flag '{s}'", .{arg});
            return Error.UnknowFlag;
        }
    }

    try self.fromValues(ally, .{
        .destination = if (destination.len > 0) destination else null,
        .sources = if (sources.items.len > 0) sources.items else null,
        .bit_rate = bit_rate,
    });
}

pub fn fromEnv(self: *Self, ally: mem.Allocator) !void {
    var env = process.getEnvMap(ally) catch |err| {
        log.err("cannot get environment variables: {}", .{err});
        return err;
    };

    defer env.deinit();

    try self.fromEnvMap(ally, env);
}

pub fn fromEnvFile(
    self: *Self,
    ally: mem.Allocator,
    p: []const u8,
) !void {
    const env_buf = fs.cwd().readFileAlloc(ally, p, 64 * 1024) catch |err| {
        log.err("cannot read env file '{s}': {}'", .{ p, err });
        return err;
    };

    defer ally.free(env_buf);

    try self.fromEnvString(ally, env_buf);
}

pub fn fromEnvMap(self: *Self, ally: mem.Allocator, env: anytype) !void {
    const prefix = self.env_prefix;

    // Destination:

    var destination: []const u8 = "";

    const dest_key = try envKey(ally, prefix, "DESTINATION");
    defer if (prefix.len > 0) ally.free(dest_key);
    destination = env.get(dest_key) orelse "";

    // Sources:

    var sources: [1][]const u8 = .{""};
    var source: []const u8 = "";

    const src_key = try envKey(ally, prefix, "SOURCE");
    defer if (prefix.len > 0) ally.free(src_key);
    source = env.get(src_key) orelse "";
    if (source.len > 0) sources[0] = source;

    // Set new values:

    try self.fromValues(ally, .{
        .destination = if (destination.len > 0) destination else null,
        .sources = if (source.len > 0) sources[0..] else null,
    });
}

pub fn fromEnvString(self: *Self, ally: mem.Allocator, s: []const u8) !void {
    var env = process.EnvMap.init(ally);
    defer env.deinit();

    var ln: usize = 1;
    var it = mem.splitScalar(u8, s, '\n');

    while (it.next()) |line| : (ln += 1) {
        if (line.len == 0) continue;
        if (line[0] == '#') continue;

        const i_opt = mem.indexOfScalar(u8, line, '=');

        if (i_opt == null or i_opt.? == line.len - 1) {
            log.err("missing value for key '{s}' in line {d}", .{ line, ln });
            return Error.MissingEnvValue;
        }

        const i = i_opt.?;
        const key = line[0..i];
        var val = line[i + 1 ..];

        if (val[0] == '"') {
            if (val.len == 1 or val[val.len - 1] != '"') {
                log.err("unclosed quote for '{s}' in line {d}", .{ key, ln });
                return Error.UnclosedQuote;
            }

            val = val[1 .. val.len - 1];
        }

        env.put(key, val) catch |err| {
            log.err("cannot store variable '{s}' in line {d}", .{ key, ln });
            return err;
        };
    }

    try self.fromEnvMap(ally, env);
}

pub fn fromOS(self: *Self, ally: mem.Allocator) !void {
    self.fromEnv(ally) catch |err| {
        log.err("cannot get options from environment variables: {}", .{err});
        return err;
    };

    self.fromArgs(ally) catch |err| {
        log.err("cannot get options from arguments: {}", .{err});
        return err;
    };
}

pub fn fromValues(self: *Self, ally: mem.Allocator, values: struct {
    name: ?[]const u8 = null,
    version: ?[]const u8 = null,
    env_prefix: ?[]const u8 = null,

    destination: ?[]const u8 = null,
    sources: ?[]const []const u8 = null,
    bit_rate: ?BitRate = null,
}) !void {
    // Name:

    var name: []const u8 = undefined;

    if (values.name) |new_name| {
        name = ally.dupe(u8, new_name) catch |err| {
            log.err("cannot allocate name: {}", .{err});
            return err;
        };
    }

    errdefer if (values.name != null) ally.free(name);

    // Version:

    var version: []const u8 = undefined;

    if (values.version) |new_version| {
        version = ally.dupe(u8, new_version) catch |err| {
            log.err("cannot allocate version: {}", .{err});
            return err;
        };
    }

    errdefer if (values.version != null) ally.free(version);

    // Environment variable prefix:

    var env_prefix: []const u8 = undefined;

    if (values.env_prefix) |new_env_prefix| {
        env_prefix = ally.dupe(u8, new_env_prefix) catch |err| {
            log.err("cannot allocate env prefix: {}", .{err});
            return err;
        };
    }

    errdefer if (values.env_prefix != null) ally.free(env_prefix);

    // Destination:

    var destination: []const u8 = undefined;

    if (values.destination) |new_destination| {
        destination = ally.dupe(u8, new_destination) catch |err| {
            log.err("cannot allocate destination: {}", .{err});
            return err;
        };
    }

    errdefer if (values.destination != null) ally.free(destination);

    // Sources:

    var sources: []const []const u8 = undefined;

    if (values.sources) |new_sources| {
        sources = ally.alloc([]const u8, new_sources.len) catch |err| {
            log.err("cannot allocate sources: {}", .{err});
            return err;
        };

        errdefer ally.free(sources);

        for (new_sources, 0..) |source, i| {
            sources[i] = ally.dupe(u8, source) catch |err| {
                if (i > 0) for (0..i) |j| ally.free(sources[j]);

                log.err("cannot allocate source '{s}': {}", .{ source, err });
                return err;
            };
        }
    }

    errdefer for (sources) |source| ally.free(source);
    errdefer ally.free(sources);

    // Bit rate:

    var bit_rate: BitRate = undefined;

    if (values.bit_rate) |new_bit_rate| {
        bit_rate = new_bit_rate;
    }

    // Set new values:

    if (values.name != null) {
        ally.free(self.name);
        self.name = name;
    }

    if (values.version != null) {
        ally.free(self.version);
        self.version = version;
    }

    if (values.env_prefix != null) {
        ally.free(self.env_prefix);
        self.env_prefix = env_prefix;
    }

    if (values.destination != null) {
        ally.free(self.destination);
        self.destination = destination;
    }

    if (values.sources != null) {
        for (self.sources) |item| ally.free(item);
        ally.free(self.sources);
        self.sources = sources;
    }

    if (values.bit_rate != null) {
        self.bit_rate = bit_rate;
    }
}

// ////////////
// Utilities //
// ////////////

fn appendMany(comptime T: type, ally: mem.Allocator, a: []const T, b: []const T) ![]T {
    var new = ally.alloc(T, a.len + b.len) catch |err| {
        log.err("cannot allocate new size: {}", .{err});
        return err;
    };

    @memcpy(new[0..a.len], a);
    @memcpy(new[a.len..], b);

    return new;
}

fn envKey(
    ally: mem.Allocator,
    prefix: []const u8,
    key: []const u8,
) ![]const u8 {
    if (prefix.len == 0)
        return key;

    return appendMany(
        u8,
        ally,
        @constCast(prefix),
        @constCast(key),
    ) catch |err| {
        log.err("cannot concatenate env prefix with key: {}", .{err});
        return err;
    };
}

fn eqlAny(comptime T: type, a: []const T, bs: []const []const T) bool {
    for (bs) |b| {
        if (mem.eql(T, a, b)) return true;
    }

    return false;
}
