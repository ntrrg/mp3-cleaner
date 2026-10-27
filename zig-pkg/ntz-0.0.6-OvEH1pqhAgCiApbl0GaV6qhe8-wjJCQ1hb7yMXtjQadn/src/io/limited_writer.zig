// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const io_utils = @import("root.zig");
const types = @import("../types/root.zig");
const errors = types.errors;

/// Creates a writer that only writes an arbitrary amount of bytes.
pub fn init(writer: anytype, limit: usize) LimitedWriter(
    @TypeOf(writer),
    errors.From(@TypeOf(writer)),
) {
    return .{ .w = writer, .limit = limit };
}

/// A writer that only writes an arbitrary amount of bytes.
pub fn LimitedWriter(comptime Writer: type, comptime WriteError: type) type {
    return struct {
        const Self = @This();

        pub const Error = WriteError;

        w: Writer,
        limit: usize,
        count: usize = 0,

        /// Allows the writer to be reused, by setting its byte count to 0.
        pub fn reset(lw: *Self) void {
            lw.count = 0;
        }

        /// Writes an arbitrary amount of bytes.
        ///
        /// Once the writer reaches its limit, it will discard all byte from
        /// subsequent calls. It is possible to reuse the writer by calling the
        /// `.reset` method.
        pub fn write(lw: *Self, data: []const u8) Error!usize {
            if (data.len == 0) return data.len;
            if (lw.count >= lw.limit) return data.len;

            const j = @min(lw.limit - lw.count, data.len);
            try io_utils.writeAll(lw.w, data[0..j]);
            lw.count += j;
            return data.len;
        }

        pub fn writer(lw: *Self) io_utils.Writer(*Self, Error, write) {
            return .{ .writer = lw };
        }
    };
}
