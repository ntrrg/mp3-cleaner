// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const builtin = @import("builtin");
const std = @import("std");

const id_utils = @import("../id/root.zig");
const tracing = id_utils.tracing;
const types = @import("../types/root.zig");
const funcs = types.funcs;
const structs = types.structs;

const logging = @import("root.zig");
const Level = logging.Level;

/// Creates a logger using the given writer as output.
pub fn init(
    writer: *std.Io.Writer,
    encoder: anytype,
    comptime Context: type,
) Logger(@TypeOf(encoder), Context, "") {
    return .{
        .w = writer,
        .e = encoder,
    };
}

pub fn Logger(
    comptime Encoder: type,
    comptime Context: type,
    comptime scope: []const u8,
) type {
    return struct {
        const Self = @This();

        mux: ?*std.Io.Mutex = null,
        w: *std.Io.Writer,
        e: Encoder,

        level: Level = switch (builtin.mode) {
            .Debug => .debug,
            .ReleaseSafe => .warn,
            .ReleaseFast, .ReleaseSmall => .@"error",
        },

        ctx: Context = structs.init(Context),

        /// Writes a log record with the given message and level of severity.
        ///
        /// If the log context has a method `.onLog`, it will be called just
        /// before writing the log record. This method must be of the following
        /// type:
        ///
        /// ```zig
        /// pub fn onLog(_: Self) T
        /// ```
        ///
        /// The returned value may be of any other type, giving more control
        /// over encoding behavior, like date formatting, field renaming or
        /// computed values.
        pub fn log(l: Self, level: Level, msg: []const u8) void {
            if (!l.should(level)) return;

            var ctx = l.ctx;
            ctx.msg = msg;

            if (@hasField(Context, "level")) {
                ctx.level = if (@TypeOf(ctx.level) == Level)
                    level
                else
                    level.key();
            }

            const val = if (comptime funcs.hasFn(Context, "onLog"))
                ctx.onLog()
            else
                ctx;

            if (l.mux) |mux| {
                std.Io.Threaded.mutexLock(mux) catch return;
                defer std.Io.Threaded.mutexUnlock(mux);

                l.e.encode(l.w, val) catch return;
                l.w.writeAll("\n") catch return;
                return;
            }

            l.e.encode(l.w, val) catch return;
            l.w.writeAll("\n") catch return;
        }

        /// Like `.log` but supports string formatting.
        pub fn logf(
            l: Self,
            allocator: std.mem.Allocator,
            level: Level,
            comptime fmt: []const u8,
            args: anytype,
        ) void {
            const msg = allocator.print(fmt, args) catch return;
            defer allocator.free(msg);
            l.log(level, msg);
        }

        /// Creates a logger using using the given data as context.
        pub fn set(l: Self, ctx: Context) Self {
            var _l = l;
            _l.ctx = ctx;
            return _l;
        }

        /// Checks if given level should be logged.
        pub fn should(l: Self, level: Level) bool {
            if (l.level == .disabled) return false;
            return @backingInt(level) >= @backingInt(l.level);
        }

        /// Updates the context of the logger.
        ///
        /// This doesn't modify the logger, it creates a new one instead.
        pub fn with(
            l: Self,
            comptime key: []const u8,
            value: types.Field(Context, scope ++ key),
        ) Self {
            if (l.level == .disabled) return l;
            var _l = l;
            types.setField(&_l.ctx, scope ++ key, value);
            return _l;
        }

        /// Updates the `error` field in the context of the logger.
        ///
        /// This doesn't modify the logger, it creates a new one instead.
        pub fn withError(l: Self, @"error": anyerror) Self {
            var _l = l;
            _l.ctx.@"error" = @"error";
            return _l;
        }

        /// Creates a logger using the given level as minimum logging severity.
        pub fn withSeverity(l: Self, level: Level) Self {
            var _l = l;
            _l.level = level;
            return _l;
        }

        // //////////
        // Tracing //
        // //////////

        /// Creates a logger using a new trace span identifier.
        pub fn newSpan(l: Self, io: std.Io) Self {
            const id: logging.Span = tracing.span(io) catch |_err| blk: {
                l.withError(_err).err("cannot genetare span id");
                break :blk @splat(0);
            };

            return l.withSpan(id);
        }

        /// Creates a logger using a new trace span identifier with the current
        /// span identifier as parent.
        pub fn newSpanChild(l: Self, io: std.Io) Self {
            const id: logging.Span = tracing.span(io) catch |_err| blk: {
                l.withError(_err).err("cannot genetare child span id");
                break :blk @splat(0);
            };

            return l.withSpanParent(l.ctx.span_id).withSpan(id);
        }

        /// Creates a logger using a new trace identifier.
        pub fn newTrace(l: Self, io: std.Io) Self {
            const id: logging.Trace = tracing.trace(io) catch |_err| blk: {
                l.withError(_err).err("cannot genetare trace id");
                break :blk @splat(0);
            };

            return l.withTrace(id).withSpanParent(null).newSpan(io);
        }

        /// Creates a logger using the given trace span identifier.
        pub fn withSpan(l: Self, id: logging.Span) Self {
            var _l = l;
            _l.ctx.span_id = id;
            return _l;
        }

        /// Creates a logger using the given trace span identifier as parent
        /// span.
        pub fn withSpanParent(l: Self, id: ?logging.Span) Self {
            var _l = l;
            _l.ctx.parent_id = id;
            return _l;
        }

        /// Creates a logger using the given trace identifier.
        pub fn withTrace(l: Self, id: logging.Trace) Self {
            var _l = l;
            _l.ctx.trace_id = id;
            return _l;
        }

        // ///////////////////
        // Severity logging //
        // ///////////////////

        /// Logs records with `.debug` level.
        ///
        /// This is equivalent to calling `l.log(.debug)`.
        pub fn debug(l: Self, msg: []const u8) void {
            l.log(.debug, msg);
        }

        /// Like `.debug` but supports string formatting.
        pub fn debugf(
            l: Self,
            allocator: std.mem.Allocator,
            comptime fmt: []const u8,
            args: anytype,
        ) void {
            l.logf(allocator, .debug, fmt, args);
        }

        /// Logs records with `.@"error"` level.
        ///
        /// This is equivalent to calling `l.log(.@"error")`.
        pub fn err(l: Self, msg: []const u8) void {
            l.log(.@"error", msg);
        }

        /// Like `.err` but supports string formatting.
        pub fn errf(
            l: Self,
            allocator: std.mem.Allocator,
            comptime fmt: []const u8,
            args: anytype,
        ) void {
            l.logf(allocator, .@"error", fmt, args);
        }

        /// Logs records with `.fatal` level.
        ///
        /// This is equivalent to calling `l.log(.fatal)` and then
        /// `std.process.exit(exit_code)`.
        pub fn fatal(l: Self, exit_code: u8, msg: []const u8) void {
            l.log(.fatal, msg);
            std.process.exit(exit_code);
        }

        /// Like `.fatal` but supports string formatting.
        pub fn fatalf(
            l: Self,
            allocator: std.mem.Allocator,
            exit_code: u8,
            comptime fmt: []const u8,
            args: anytype,
        ) void {
            l.logf(allocator, .fatal, fmt, args);
            std.process.exit(exit_code);
        }

        /// Logs records with `.info` level.
        ///
        /// This is equivalent to calling `l.log(.info)`.
        pub fn info(l: Self, msg: []const u8) void {
            l.log(.info, msg);
        }

        /// Like `.info` but supports string formatting.
        pub fn infof(
            l: Self,
            allocator: std.mem.Allocator,
            comptime fmt: []const u8,
            args: anytype,
        ) void {
            l.logf(allocator, .info, fmt, args);
        }

        /// Logs records with `.warn` level.
        ///
        /// This is equivalent to calling `l.log(.warn)`.
        pub fn warn(l: Self, msg: []const u8) void {
            l.log(.warn, msg);
        }

        /// Like `.warn but supports string formatting.
        pub fn warnf(
            l: Self,
            allocator: std.mem.Allocator,
            comptime fmt: []const u8,
            args: anytype,
        ) void {
            l.logf(allocator, .warn, fmt, args);
        }

        // //////////////////////
        // Logger manipulation //
        // //////////////////////

        /// Creates a logger using the given context.
        pub fn withContext(l: Self, comptime NewContext: type) Logger(
            Encoder,
            NewContext,
            scope,
        ) {
            return .{
                .mux = l.mux,
                .w = l.w,
                .e = l.e,
                .level = l.level,
            };
        }

        /// Creates a logger using the given encoder.
        pub fn withEncoder(l: Self, encoder: anytype) Logger(
            @TypeOf(encoder),
            Context,
            scope,
        ) {
            return .{
                .mux = l.mux,
                .w = l.w,
                .e = encoder,
                .level = l.level,
                .ctx = l.ctx,
            };
        }

        /// Creates a logger using the given scope.
        pub fn withScope(l: Self, comptime new_scope: []const u8) Logger(
            Encoder,
            Context,
            (if (scope.len > 0) scope ++ new_scope else new_scope) ++ ".",
        ) {
            return .{
                .mux = l.mux,
                .w = l.w,
                .e = l.e,
                .level = l.level,
                .ctx = l.ctx,
            };
        }

        /// Creates a logger using the given writer.
        pub fn withWriter(l: Self, writer: *std.Io.Writer) Self {
            var _l = l;
            _l.w = writer;
            return _l;
        }
    };
}
