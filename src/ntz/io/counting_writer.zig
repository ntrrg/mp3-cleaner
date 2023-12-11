// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const errors = @import("../types/errors.zig");
const io = @import("io.zig");

/// Creates a writer that counts how many times it writes and how many bytes it
/// writes.
pub fn init(writer: anytype) CountingWriter(@TypeOf(writer)) {
    return .{ .writer = writer };
}

/// A writer that counts how many times it writes and how many bytes it writes.
pub fn CountingWriter(comptime WriterType: type) type {
    return struct {
        const Self = @This();
        pub const WriterError = errors.From(WriterType);
        pub const Error = WriterError;

        writer: WriterType,

        /// Writes count.
        write_count: u64 = 0,

        /// Bytes written.
        byte_count: u64 = 0,

        /// Sets its counters to 0.
        pub fn reset(cw: *Self) void {
            cw.write_count = 0;
            cw.byte_count = 0;
        }

        /// Counts how many times `.write` is called on the underlying writer
        /// and how many bytes have been written.
        pub fn write(cw: *Self, bytes: []const u8) Error!usize {
            const n = try io.writeAll(cw.writer, Error, bytes);
            cw.write_count += 1;
            cw.byte_count += n;
            return n;
        }
    };
}
