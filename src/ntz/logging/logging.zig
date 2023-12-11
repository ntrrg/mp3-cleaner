// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.logging`
//!
//! A logging API with support for contextual logging, message severity and
//! scoping.

const builtin = @import("builtin");
const std = @import("std");

const types = @import("../types/types.zig");
const funcs = types.funcs;
const strings = types.strings;

pub const Src = std.builtin.SourceLocation;

/// Creates a comptime logger. Since this uses `@compileError`, it will
/// terminate compilation when it logs its first record.
pub fn comptimeLog(comptime buf_size: usize) Logger(
    "",
    void,
    buf_size,
    Mode.no_defaults(),
) {
    return .{ .writer = void{} };
}

/// Creates a logger using the standard error as log writer.
pub fn init(comptime buf_size: usize, comptime mode: Mode) Logger(
    "",
    std.fs.File,
    buf_size,
    mode,
) {
    return withWriter(
        std.io.getStdErr(),
        std.debug.getStderrMutex(),
        buf_size,
        mode,
    );
}

/// Creates a logger that logs nothing.
pub fn noop() Logger("", void, 0, Mode.noop()) {
    return .{ .writer = void{} };
}

/// Creates a logger using the given writer as log writer.
pub fn withWriter(
    writer: anytype,
    mutex: ?*std.Thread.Mutex,
    comptime buf_size: usize,
    comptime mode: Mode,
) Logger("", @TypeOf(writer), buf_size, mode) {
    return .{ .writer = writer, .mutex = mutex };
}

// ////////
// Level //
// ////////

/// Represents the severity of a logging message.
pub const Level = enum {
    const Error = error{
        UnkownValue,
    };

    /// Messages intended to be read by developers.
    debug,

    /// Verbose messages about the state of the program.
    info,

    /// Problems that doesn't interrupt the procedure execution.
    warn,

    /// Problems that interrupt the procedure execution.
    err,

    /// Problems that interrupt the program execution.
    fatal,

    /// Returns a string literal of the given level in key form.
    pub fn asKey(lvl: Level) []const u8 {
        return switch (lvl) {
            .debug => "DBG",
            .info => "INF",
            .warn => "WRN",
            .err => "ERR",
            .fatal => "FTL",
        };
    }

    /// Returns a string literal of the given level in full text form.
    pub fn asText(lvl: Level) []const u8 {
        return switch (lvl) {
            .debug => "debug",
            .info => "info",
            .warn => "warning",
            .err => "error",
            .fatal => "fatal",
        };
    }

    /// Return an equivalent logging level from given text.
    pub fn fromText(txt: []const u8) !Level {
        if (strings.eqlAny(txt, &.{ "DBG", "debug", "dbg" }))
            return .debug;

        if (strings.eqlAny(txt, &.{ "INF", "info", "inf", "information" }))
            return .info;

        if (strings.eqlAny(txt, &.{ "WRN", "warning", "warn", "wrn" }))
            return .warn;

        if (strings.eqlAny(txt, &.{ "ERR", "error", "err" }))
            return .err;

        if (strings.eqlAny(txt, &.{ "FTL", "fatal", "ftl" }))
            return .fatal;

        return Error.UnkownValue;
    }
};

// /////////
// Logger //
// /////////

pub fn Logger(
    comptime group: []const u8,
    comptime WriterType: type,
    comptime buf_size: usize,
    comptime mode: Mode,
) type {
    if (comptime !mode.noop and buf_size < 2)
        @compileError("`buf_size` is required to be at least 2");

    return struct {
        const Self = @This();

        writer: WriterType,
        mutex: ?*std.Thread.Mutex = null,

        buf: [buf_size]u8 = undefined,
        buf_end: usize = 0,

        level: Level = switch (builtin.mode) {
            .Debug => .debug,
            .ReleaseSafe => .warn,
            .ReleaseFast, .ReleaseSmall => .err,
        },

        pub fn log(
            l: Self,
            level: Level,
            comptime format: []const u8,
            args: anytype,
        ) void {
            if (comptime mode.noop) return;
            if (!l.should(level)) return;

            var new_l = l;

            if (comptime mode.with_time)
                new_l.writeField("time", std.time.timestamp());

            if (comptime mode.with_level)
                new_l.writeField("level", level.asKey());

            if (comptime format.len > 0) {
                const args_ti = @typeInfo(@TypeOf(args));

                if (new_l.buf_end > 0)
                    new_l.write(" ");

                if (args_ti == .Struct and args_ti.Struct.fields.len > 0) {
                    new_l.write("msg=\"");
                    std.fmt.format(new_l.stdWriter(), format, args) catch unreachable;
                    new_l.write("\"");
                } else {
                    new_l.write("msg=\"" ++ format ++ "\"");
                }
            }

            if (new_l.buf_end == new_l.buf.len) {
                new_l.buf[0] = '#';
                new_l.buf[new_l.buf_end - 1] = '\n';
            } else {
                new_l.write("\n");
            }

            if (@inComptime())
                @compileError(new_l.buf[0..new_l.buf_end]);

            if (new_l.mutex) |mux| mux.lock();
            defer if (new_l.mutex) |mux| mux.unlock();
            _ = new_l.writer.write(new_l.buf[0..new_l.buf_end]) catch undefined;
        }

        /// Checks if given level should be logged.
        pub fn should(l: Self, level: Level) bool {
            if (comptime mode.noop) return false;
            return @intFromEnum(level) >= @intFromEnum(l.level);
        }

        // ///////////////////
        // Severity logging //
        // ///////////////////

        /// Logs messages with `.debug` level.
        ///
        /// This is equivalent to calling `l.log(.debug, "", .{})`.
        pub fn debug(l: Self, comptime format: []const u8, args: anytype) void {
            if (comptime mode.noop) return;
            l.log(.debug, format, args);
        }

        /// Logs messages with `.err` level.
        ///
        /// This is equivalent to calling `l.log(.err, "", .{})`.
        pub fn err(l: Self, comptime format: []const u8, args: anytype) void {
            if (comptime mode.noop) return;
            l.log(.err, format, args);
        }

        /// Logs messages with `.fatal` level.
        ///
        /// This is equivalent to calling `l.log(.fatal, "", .{})` and then
        /// `std.process.exit(3)`.
        pub fn fatal(l: Self, comptime format: []const u8, args: anytype) void {
            if (comptime mode.noop) return;
            l.log(.fatal, format, args);
            std.process.exit(3);
        }

        /// Logs messages with `.info` level.
        ///
        /// This is equivalent to calling `l.log(.info, "", .{})`.
        pub fn info(l: Self, comptime format: []const u8, args: anytype) void {
            if (comptime mode.noop) return;
            l.log(.info, format, args);
        }

        /// Logs messages with `.warn` level.
        ///
        /// This is equivalent to calling `l.log(.warn, "", .{})`.
        pub fn warn(l: Self, comptime format: []const u8, args: anytype) void {
            if (comptime mode.noop) return;
            l.log(.warn, format, args);
        }

        // //////////////////
        // Logger behavior //
        // //////////////////

        /// Creates a no-op logger.
        pub fn noop(l: Self) Logger("", void, 0, .{ .noop = true }) {
            if (comptime mode.noop) return l;
            return .{ .writer = void{} };
        }

        /// Adds a field to the log record. This doesn't modify the logger, but
        /// creates a new one.
        ///
        /// If `T` has a method `.encodeLog`, it will be used instead of default
        /// encoding. This method must be of the following type:
        ///
        /// ```zig
        /// pub fn encodeLog(_: T, log: anytype, comptime key: []const u8) void
        /// ```
        pub fn with(
            l: Self,
            comptime T: type,
            comptime key: []const u8,
            value: T,
        ) Self {
            if (comptime mode.noop) return l;

            var new_l = l;
            new_l.writeField(group ++ key, value);
            return new_l;
        }

        /// Creates a logger with the given buffer size.
        pub fn withBufferSize(
            l: Self,
            comptime new_buf_size: usize,
        ) if (mode.noop) Self else Logger(
            group,
            WriterType,
            new_buf_size,
            mode,
        ) {
            if (comptime mode.noop) return l;

            var new_l = .{
                .writer = l.writer,
                .mutex = l.mutex,
                .level = l.level,
            };

            const end = @min(l.buf_end, new_buf_size);
            @memcpy(new_l.buf[0..end], l.buf[0..end]);
            new_l.buf_end = end;

            return new_l;
        }

        /// Creates a logger that add fields under the given group. Adding a new
        /// field `field` will turn into `group_name.field`.
        pub fn withGroup(
            l: Self,
            comptime new_group: []const u8,
        ) if (mode.noop) Self else Logger(
            (if (group.len > 0) group ++ new_group else new_group) ++ ".",
            WriterType,
            buf_size,
            mode,
        ) {
            if (comptime mode.noop) return l;

            return .{
                .writer = l.writer,
                .mutex = l.mutex,
                .buf = l.buf,
                .buf_end = l.buf_end,
                .level = l.level,
            };
        }

        /// Creates a logger using given level as minimum logging level.
        pub fn withLevel(l: Self, new_level: Level) Self {
            if (comptime mode.noop) return l;

            return .{
                .writer = l.writer,
                .mutex = l.mutex,
                .buf = l.buf,
                .buf_end = l.buf_end,
                .level = new_level,
            };
        }

        /// Creates a logger with the given mode.
        pub fn withMode(
            l: Self,
            comptime new_mode: Mode,
        ) if (mode.noop) Self else Logger(
            group,
            WriterType,
            buf_size,
            new_mode,
        ) {
            if (comptime mode.noop) return l;

            return .{
                .writer = l.writer,
                .mutex = l.mutex,
                .buf = l.buf,
                .buf_end = l.buf_end,
                .level = l.level,
            };
        }

        /// Creates a logger using given writer. An optional mutex is used for
        /// thread-safe logging.
        pub fn withWriter(
            l: Self,
            new_writer: anytype,
            new_mutex: ?*std.Thread.Mutex,
        ) if (mode.noop) Self else Logger(
            group,
            @TypeOf(new_writer),
            buf_size,
            mode,
        ) {
            if (comptime mode.noop) return l;

            return .{
                .writer = new_writer,
                .mutex = new_mutex,
                .buf = l.buf,
                .buf_end = l.buf_end,
                .level = l.level,
            };
        }

        // //////////////
        // Raw writing //
        // //////////////

        pub fn encode(
            l: *Self,
            comptime key: []const u8,
            value: anytype,
        ) void {
            const T = @TypeOf(value);

            if (comptime funcs.hasFn(T, "encodeLog")) {
                value.encodeLog(l, key);
                return;
            }

            const value_ti = @typeInfo(T);

            if (key.len > 0 and value_ti != .Struct and value_ti != .Union)
                l.write(key ++ "=");

            const w = l.stdWriter();

            switch (value_ti) {
                .Bool => {
                    l.write(if (value) "true" else "false");
                },

                .Int, .ComptimeInt, .Float, .ComptimeFloat => {
                    std.fmt.format(w, "{d:.4}", .{value}) catch unreachable;
                },

                .Enum, .EnumLiteral => {
                    l.write("\"");
                    l.write(@tagName(value));
                    l.write("\"");
                },

                .Struct => |struct_ti| {
                    inline for (struct_ti.fields, 0..) |field, i| {
                        if (i > 0) l.write(" ");

                        l.encode(
                            key ++ "." ++ field.name,
                            @field(value, field.name),
                        );
                    }
                },

                .Union => |union_ti| {
                    if (union_ti.tag_type) |_| {
                        switch (value) {
                            inline else => |val| {
                                l.encode(key, val);
                            },
                        }
                    } else {
                        std.fmt.format(w, "\"{any}\"", .{value}) catch unreachable;
                    }
                },

                .Pointer => |ptr_ti| {
                    if (ptr_ti.size == .Slice) {
                        if (ptr_ti.is_const and ptr_ti.child == u8 and std.unicode.utf8ValidateSlice(value)) {
                            l.write("\"");
                            l.write(value);
                            l.write("\"");
                        } else {
                            l.write("[");

                            for (value, 0..) |item, i| {
                                if (i > 0) l.write(", ");
                                l.encode("", item);
                            }

                            l.write("]");
                        }
                    } else {
                        std.fmt.format(w, "\"{*}\"", .{value}) catch unreachable;
                    }
                },

                .Optional => {
                    if (value) |val| {
                        l.encode("", val);
                    } else {
                        l.write("null");
                    }
                },

                .ErrorUnion => {
                    if (value) |val| {
                        l.encode("", val);
                    } else |e| {
                        l.encode("", e);
                    }
                },

                .ErrorSet => {
                    l.write("\"");
                    l.write(@errorName(value));
                    l.write("\"");
                },

                .Void => {
                    l.write("void");
                },

                .Type => {
                    l.write("\"");
                    l.write(@typeName(value));
                    l.write("\"");
                },

                else => {
                    std.fmt.format(w, "\"{any}\"", .{value}) catch unreachable;
                },
            }
        }

        pub fn write(l: *Self, bytes: []const u8) void {
            if (bytes.len == 0) return;
            const available = l.buf.len - l.buf_end;
            if (available == 0) return;
            const j = @min(available, bytes.len);

            const new_end = l.buf_end + j;
            @memcpy(l.buf[l.buf_end..new_end], bytes[0..j]);
            l.buf_end = new_end;
        }

        pub fn writeField(
            l: *Self,
            comptime key: []const u8,
            value: anytype,
        ) void {
            if (l.buf_end > 0 and l.buf[l.buf_end - 1] != ' ')
                l.write(" ");

            l.encode(key, value);
        }

        // ////////////////
        // std.io.Writer //
        // ////////////////

        fn stdWrite(l: *Self, bytes: []const u8) !usize {
            if (comptime mode.noop) bytes.len;
            l.write(bytes);
            return bytes.len;
        }

        const StdWriter = std.io.Writer(*Self, error{}, stdWrite);

        pub fn stdWriter(l: *Self) StdWriter {
            return .{ .context = l };
        }
    };
}

// ///////
// Mode //
// ///////

/// Represents a logger mode.
pub const Mode = packed struct {
    const Self = @This();

    noop: bool = false,
    with_time: bool = true,
    with_level: bool = true,

    /// Regular logger without defaults fields.
    pub fn no_defaults() Self {
        return .{ .with_time = false, .with_level = false };
    }

    /// No-op logger.
    pub fn noop() Self {
        return .{ .noop = true };
    }
};
