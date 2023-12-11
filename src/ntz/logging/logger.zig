// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const builtin = @import("builtin");
const std = @import("std");

const Level = @import("level.zig").Level;
const encode = @import("encoding.zig").encode;

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

        /// Logs records with `.debug` level.
        ///
        /// This is equivalent to calling `l.log(.debug, "", .{})`.
        pub fn debug(l: Self, comptime format: []const u8, args: anytype) void {
            if (comptime mode.noop) return;
            l.log(.debug, format, args);
        }

        /// Logs records with `.err` level.
        ///
        /// This is equivalent to calling `l.log(.err, "", .{})`.
        pub fn err(l: Self, comptime format: []const u8, args: anytype) void {
            if (comptime mode.noop) return;
            l.log(.err, format, args);
        }

        /// Logs records with `.fatal` level.
        ///
        /// This is equivalent to calling `l.log(.fatal, "", .{})` and then
        /// `std.process.exit(3)`.
        ///
        /// Exit code `3` is used for identifying termination from a logger.
        pub fn fatal(l: Self, comptime format: []const u8, args: anytype) void {
            if (comptime mode.noop) return;
            l.log(.fatal, format, args);
            std.process.exit(3);
        }

        /// Logs records with `.info` level.
        ///
        /// This is equivalent to calling `l.log(.info, "", .{})`.
        pub fn info(l: Self, comptime format: []const u8, args: anytype) void {
            if (comptime mode.noop) return;
            l.log(.info, format, args);
        }

        /// Logs records with `.warn` level.
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
        /// If `T` has a method `.asLog`, it will be used instead of default
        /// encoding. This method must be of the following type:
        ///
        /// ```zig
        /// pub fn asLog(_: T, log: anytype, comptime key: []const u8) void
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

            encode(l, key, value);
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
