// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const errors = @import("../types/errors.zig");

/// Allows to use a custom type as a writer.
pub fn init(
    writer: anytype,
    comptime WriterError: type,
    comptime write_fn: fn (writer: @TypeOf(writer), bytes: []const u8) WriterError!usize,
) Writer(@TypeOf(writer), WriterError, write_fn) {
    return .{ .writer = writer };
}

pub fn Writer(
    comptime WriterType: type,
    comptime WriterError: type,
    comptime write_fn: fn (w: WriterType, bytes: []const u8) WriterError!usize,
) type {
    return struct {
        const Self = @This();
        pub const Error = WriterError;

        writer: WriterType,

        pub fn write(w: Self, bytes: []const u8) Error!usize {
            return write_fn(w.writer, bytes);
        }
    };
}
