// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const errors = @import("../types/errors.zig");
const io = @import("io.zig");

/// Creates a writer that only writes an arbitrary amount of bytes.
pub fn init(writer: anytype, comptime limit: usize) LimitedWriter(
    @TypeOf(writer),
    limit,
) {
    return .{ .writer = writer };
}

/// A writer that only writes an arbitrary amount of bytes.
pub fn LimitedWriter(
    comptime WriterType: type,
    comptime limit: usize,
) type {
    return struct {
        const Self = @This();
        pub const WriterError = errors.From(WriterType);
        pub const Error = WriterError;

        writer: WriterType,
        count: usize = 0,

        /// Allows the writer to be reused, by setting its byte count to 0.
        pub fn reset(lw: *Self) void {
            lw.count = 0;
        }

        /// Writes an arbitrary amount of bytes.
        ///
        /// Once the writer reaches its limit, it will discard every byte from
        /// subsequent calls. It is possible to reuse the writer by calling the
        /// `.reset` method.
        pub fn write(lw: *Self, bytes: []const u8) Error!usize {
            if (bytes.len == 0) return 0;
            if (lw.count >= limit) return 0;

            const j = @min(limit - lw.count, bytes.len);
            const n = try io.writeAll(lw.writer, Error, bytes[0..j]);

            lw.count += n;
            return n;
        }
    };
}
