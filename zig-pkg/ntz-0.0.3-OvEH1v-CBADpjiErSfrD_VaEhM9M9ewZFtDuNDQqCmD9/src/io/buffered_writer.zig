// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const io_utils = @import("root.zig");
const types = @import("../types/root.zig");
const bytes = types.bytes;
const errors = types.errors;

/// Creates a writer that actually writes once its buffer has been filled.
pub fn init(writer: anytype, buf: []u8) BufferedWriter(
    @TypeOf(writer),
    errors.From(@TypeOf(writer)),
) {
    return .{ .w = writer, .buf = buf };
}

/// A writer that actually writes once its buffer has been filled.
pub fn BufferedWriter(comptime Writer: type, comptime WriteError: type) type {
    return struct {
        const Self = @This();

        pub const Error = WriteError;

        w: Writer,
        buf: []u8 = undefined,
        end: usize = 0,

        /// Writes any buffered bytes to the underlying writer and restores the
        /// buffer to its full capacity.
        pub fn flush(bw: *Self) Error!void {
            if (bw.end == 0) return;
            try io_utils.writeAll(bw.w, bw.buf[0..bw.end]);
            bw.end = 0;
        }

        /// Writes bytes into a buffer until it is full.
        ///
        /// Use the `.flush` method for writing remaining bytes.
        pub fn write(bw: *Self, data: []const u8) Error!usize {
            var i: usize = 0;

            while (i < data.len) {
                const n = bytes.copy(bw.buf[bw.end..], data[i..]);
                bw.end += n;
                if (bw.end == bw.buf.len) try bw.flush();
                i += n;
            }

            return data.len;
        }

        pub fn writer(dw: *Self) io_utils.Writer(*Self, Error, write) {
            return .{ .writer = dw };
        }
    };
}
