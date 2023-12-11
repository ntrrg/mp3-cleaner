// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");

const errors = @import("../types/errors.zig");
const io = @import("io.zig");
const slices = @import("../types/slices.zig");

/// Creates a writer that actually writes when it finds an arbitrary delimiter.
///
/// `delimiter` might be of any type that coerces to `u8` or `[]const u8`.
/// Using an empty string as delimiter will call write in the underlying writer
/// for every byte.
///
/// Use the `.deinit` method to release resources.
pub fn init(
    writer: anytype,
    delimiter: anytype,
    allocator: anytype,
) DelimitedWriter(
    @TypeOf(writer),
    DelimiterT(@TypeOf(delimiter)),
    @TypeOf(allocator),
) {
    return .{
        .allocator = allocator,
        .writer = writer,
        .buf = .{},
        .delim = delimiter,
    };
}

/// A writer that actually writes when it finds an arbitrary delimiter.
pub fn DelimitedWriter(
    comptime WriterType: type,
    comptime DelimiterType: type,
    comptime AllocatorType: type,
) type {
    return struct {
        const Self = @This();
        pub const WriterError = errors.From(WriterType);
        pub const AllocatorError = errors.From(AllocatorType);
        pub const Error = AllocatorError || WriterError;

        writer: WriterType,
        allocator: AllocatorType,
        buf: std.ArrayListUnmanaged(u8),
        delim: DelimiterType,

        /// If false, the delimiter will not be written.
        include: bool = true,

        pub fn deinit(dw: *Self) void {
            dw.buf.deinit(dw.allocator);
        }

        /// Writes any buffered bytes to the underlying writer and restores the
        /// buffer to its full capacity.
        pub fn flush(dw: *Self) WriterError!void {
            if (dw.buf.items.len == 0) return;
            _ = try io.writeAll(dw.writer, WriterError, dw.buf.items);
            dw.buf.clearRetainingCapacity();
        }

        /// Writes bytes into a buffer until it finds the delimiter.
        ///
        /// Whether the delimiter is written or not along with buffered bytes
        /// is configurable via the `.include` property.
        ///
        /// Bytes after the delimiter will not be written until another
        /// instance of the delimiter is found, use the `.flush` method for
        /// writing remaining bytes.
        pub fn write(dw: *Self, bytes: []const u8) Error!usize {
            if (bytes.len == 0) return 0;

            if (comptime DelimiterType == u8)
                return dw.scalar(bytes, dw.delim);

            if (dw.delim.len == 1)
                return dw.scalar(bytes, dw.delim[0]);

            if (dw.delim.len > 1)
                return dw.sequence(bytes);

            for (0..bytes.len) |i| _ = try dw.writer.write(bytes[i .. i + 1]);

            return bytes.len;
        }

        inline fn scalar(dw: *Self, bytes: []const u8, delim: u8) Error!usize {
            var n: usize = 0;
            var i: usize = 0;

            while (slices.findAt(u8, i, bytes, delim)) |idx| {
                var j = idx;
                if (dw.include) j += 1;

                try dw.buf.appendSlice(dw.allocator, bytes[i..j]);
                n += dw.buf.items.len;
                try dw.flush();

                if (!dw.include) j += 1;
                i = j;
            }

            if (i < bytes.len)
                try dw.buf.appendSlice(dw.allocator, bytes[i..]);

            return n;
        }

        inline fn sequence(dw: *Self, bytes: []const u8) Error!usize {
            var n: usize = 0;
            var i: usize = 0;

            // Check if the delimiter is partially stored in buffered bytes.
            if (dw.missingDelimiterBytes()) |missing| {
                if (missing > bytes.len) {
                    try dw.buf.appendSlice(dw.allocator, bytes);
                    return 0;
                }

                if (slices.endsWith(u8, dw.delim, bytes[0..missing])) {
                    if (dw.include) {
                        try dw.buf.appendSlice(dw.allocator, bytes[0..missing]);
                    } else {
                        const buffered = dw.delim.len - missing;
                        const new_len = dw.buf.items.len - buffered;
                        dw.buf.shrinkRetainingCapacity(new_len);
                    }

                    n += dw.buf.items.len;
                    try dw.flush();
                    i = missing;
                }
            }

            while (slices.findAt(u8, i, bytes, dw.delim[0])) |idx| {
                var j = idx;
                const remaining = bytes[j..];

                if (remaining.len < dw.delim.len) {
                    if (!slices.startsWith(u8, dw.delim, remaining)) {
                        i = j + 1;
                        continue;
                    }

                    try dw.buf.appendSlice(dw.allocator, bytes[i..]);
                    i = bytes.len;
                    break;
                }

                if (!slices.eql(u8, bytes[j .. j + dw.delim.len], dw.delim)) {
                    i = j + 1;
                    continue;
                }

                if (dw.include) j += dw.delim.len;

                try dw.buf.appendSlice(dw.allocator, bytes[i..j]);
                n += dw.buf.items.len;
                try dw.flush();

                if (!dw.include) j += dw.delim.len;
                i = j;
            }

            if (i < bytes.len)
                try dw.buf.appendSlice(dw.allocator, bytes[i..]);

            return n;
        }

        // //////////
        // Helpers //
        // //////////

        fn missingDelimiterBytes(dw: *Self) ?usize {
            const buf_len = dw.buf.items.len;
            if (buf_len == 0) return null;

            var j: usize = @min(dw.delim.len, buf_len);

            while (j > 0) : (j -= 1) {
                const buf_i = buf_len - j;

                if (slices.startsWith(u8, dw.delim, dw.buf.items[buf_i..]))
                    return dw.delim.len - j;
            }

            return null;
        }
    };
}

fn DelimiterT(comptime Delimiter: type) type {
    return switch (@typeInfo(Delimiter)) {
        .ComptimeInt => u8,

        .Int => |int_ti| blk: {
            if (int_ti.signedness != .unsigned)
                @compileError("scalar delimiter must be unsigned");

            if (int_ti.bits > 8)
                @compileError("scalar delimiter must be at most 8 bits long");

            break :blk u8;
        },

        .Array, .Pointer => []const u8,

        else => {
            const msg = "invalid delimiter type, must be a type that coerces to `u8` or `[]const u8`, found `" ++ @typeName(Delimiter) ++ "`";
            @compileError(msg);
        },
    };
}
