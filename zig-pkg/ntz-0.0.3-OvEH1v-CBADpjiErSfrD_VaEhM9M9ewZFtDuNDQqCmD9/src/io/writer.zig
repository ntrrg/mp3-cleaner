// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");

/// Creates a writable stream using a custom type.
///
/// `write_fn` should return the number of bytes processed, not the number of
/// bytes written. For example, a compression writer should return the number
/// of bytes it used from `data` during compression, not the resulting number
/// of bytes after compression.
pub fn init(
    writer: anytype,
    comptime Error: type,
    comptime writeFn: fn (w: @TypeOf(writer), data: []const u8) Error!usize,
) Writer(@TypeOf(writer), Error, writeFn) {
    return .{ .writer = writer };
}

/// A common interface for writable streams.
pub fn Writer(
    comptime T: type,
    comptime WriteError: type,
    comptime writeFn: fn (w: T, data: []const u8) WriteError!usize,
) type {
    return struct {
        const Self = @This();
        pub const Error = WriteError;

        writer: T,

        /// Writes the given data and returns the number of bytes processed.
        pub fn write(w: Self, data: []const u8) Error!usize {
            return writeFn(w.writer, data);
        }

        // ////////////////
        // std.Io.Writer //
        // ////////////////

        pub const StdWriter = struct {
            writer: T,
            interface: std.Io.Writer,
            err: ?Error = null,

            fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
                _ = splat;
                const a: *@This() = @alignCast(@fieldParentPtr("interface", w));
                const buffered = w.buffered();

                if (buffered.len != 0) {
                    return w.consume(writeFn(a.writer, buffered) catch |err| {
                        a.err = err;
                        return error.WriteFailed;
                    });
                }

                return writeFn(a.writer, data[0]) catch |err| {
                    a.err = err;
                    return error.WriteFailed;
                };
            }
        };

        pub fn toStd(w: Self, buffer: []u8) StdWriter {
            return .{
                .writer = w.writer,
                .interface = .{
                    .buffer = buffer,
                    .vtable = &.{ .drain = StdWriter.drain },
                },
            };
        }
    };
}
