// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const io_utils = @import("root.zig");
const types = @import("../types/root.zig");
const errors = types.errors;

/// Creates a writer that counts how many times it writes and how many bytes it
/// writes.
pub fn init(writer: anytype) CountingWriter(
    @TypeOf(writer),
    errors.From(@TypeOf(writer)),
) {
    return .{ .w = writer };
}

/// A writer that counts how many times it writes and how many bytes it writes.
pub fn CountingWriter(comptime Writer: type, comptime WriteError: type) type {
    return struct {
        const Self = @This();

        pub const Error = WriteError;

        w: Writer,

        /// Writes count.
        write_count: u64 = 0,

        /// Bytes written.
        byte_count: u64 = 0,

        /// Sets its counters to 0.
        pub fn reset(cw: *Self) void {
            cw.write_count = 0;
            cw.byte_count = 0;
        }

        /// Counts how many times `.write` is called and how many bytes have
        /// been written.
        pub fn write(cw: *Self, data: []const u8) Error!usize {
            const n = try cw.w.write(data);
            cw.write_count += 1;
            cw.byte_count += n;
            return data.len;
        }

        pub fn writer(cw: *Self) io_utils.Writer(*Self, Error, write) {
            return .{ .writer = cw };
        }
    };
}
