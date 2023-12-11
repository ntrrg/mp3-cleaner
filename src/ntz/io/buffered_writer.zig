// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const errors = @import("../types/errors.zig");
const io = @import("io.zig");

/// Creates a writer that actually writes once its buffer has been filled.
pub fn init(writer: anytype, comptime buf_size: usize) BufferedWriter(
    @TypeOf(writer),
    buf_size,
) {
    return .{ .writer = writer };
}

/// A writer that actually writes once its buffer has been filled.
pub fn BufferedWriter(
    comptime WriterType: type,
    comptime buf_size: usize,
) type {
    if (buf_size == 0)
        @compileError("`buf_size` cannot be zero");

    return struct {
        const Self = @This();
        pub const WriterError = errors.From(WriterType);
        pub const Error = WriterError;

        writer: WriterType,
        buf: [buf_size]u8 = undefined,
        end: usize = 0,

        /// Writes any buffered bytes to the underlying writer and restores the
        /// buffer to its full capacity.
        pub fn flush(bw: *Self) Error!void {
            if (bw.end == 0) return;
            _ = try io.writeAll(bw.writer, Error, bw.buf[0..bw.end]);
            bw.end = 0;
        }

        /// Writes bytes into a buffer until it is full.
        ///
        /// Use the `.flush` method for writing remaining bytes.
        pub fn write(bw: *Self, bytes: []const u8) Error!usize {
            var n: usize = 0;
            var i: usize = 0;

            while (i < bytes.len) {
                const available = buf_size - bw.end;
                const remaining = bytes.len - i;
                const j = @min(available, remaining);

                const new_end = bw.end + j;
                @memcpy(bw.buf[bw.end..new_end], bytes[i .. i + j]);
                bw.end = new_end;

                if (bw.end == buf_size) {
                    try bw.flush();
                    n += j;
                }

                i += j;
            }

            return n;
        }
    };
}
