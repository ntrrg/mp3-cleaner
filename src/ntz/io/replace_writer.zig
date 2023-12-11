// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");

const errors = @import("../types/errors.zig");
const io = @import("io.zig");
const slices = @import("../types/slices.zig");

/// Creates a writer that replaces single bytes with new arbitrary bytes.
///
/// `this` might be of any type that coerces to `u8` or `[]const u8` with a
/// single element. Using an empty string as replace pattern will replace every
/// byte with `those`.
pub fn init(writer: anytype, this: anytype, those: []const u8) ReplaceWriter(
    @TypeOf(writer),
) {
    return .{
        .writer = writer,
        .buf = .{},

        .this = switch (@typeInfo(@TypeOf(this))) {
            .Pointer, .Array => blk: {
                if (this.len == 0) break :blk null;
                break :blk this[0];
            },

            else => this,
        },

        .those = those,
    };
}

/// A writer that replaces single bytes with new arbitrary bytes.
pub fn ReplaceWriter(comptime WriterType: type) type {
    return struct {
        const Self = @This();
        pub const WriterError = errors.From(WriterType);
        pub const Error = WriterError;

        writer: WriterType,
        buf: std.ArrayListUnmanaged(u8),
        this: ?u8,
        those: []const u8,

        /// Writes and replaces bytes.
        pub fn write(rw: *Self, bytes: []const u8) Error!usize {
            if (bytes.len == 0) return 0;

            if (rw.this == null) {
                for (0..bytes.len) |_|
                    _ = try rw.writer.write(rw.those);

                return rw.those.len * bytes.len;
            }

            var n: usize = 0;
            var i: usize = 0;

            while (slices.findAt(u8, i, bytes, rw.this.?)) |j| {
                if (i < j) n += try rw.writer.write(bytes[i..j]);
                n += try rw.writer.write(rw.those);
                i = j + 1;
            }

            if (i < bytes.len)
                n += try rw.writer.write(bytes[i..]);

            return n;
        }
    };
}

/// Creates a writer that replaces sequences of bytes with new arbitrary bytes.
///
/// Use the `.deinit` method to release resources.
pub fn initMany(
    writer: anytype,
    these: []const u8,
    those: []const u8,
    allocator: anytype,
) ReplaceManyWriter(@TypeOf(writer), @TypeOf(allocator)) {
    return .{
        .allocator = allocator,
        .writer = writer,
        .buf = .{},
        .these = these,
        .those = those,
    };
}

/// A writer that replaces sequences of bytes with new arbitrary bytes.
pub fn ReplaceManyWriter(
    comptime WriterType: type,
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
        these: []const u8,
        those: []const u8,

        pub fn deinit(rw: *Self) void {
            rw.buf.deinit(rw.allocator);
        }

        /// Writes any buffered bytes to the underlying writer and restores the
        /// buffer to its full capacity.
        pub fn flush(rw: *Self) WriterError!void {
            if (rw.buf.items.len == 0) return;
            _ = try io.writeAll(rw.writer, WriterError, rw.buf.items);
            rw.buf.clearRetainingCapacity();
        }

        /// Writes bytes into a buffer until it finds the delimiter.
        ///
        /// Use the `.flush` method for writing remaining bytes.
        pub fn write(rw: *Self, bytes: []const u8) Error!usize {
            if (bytes.len == 0) return 0;

            var n: usize = 0;
            var i: usize = 0;

            // Check if buffered bytes match `.these` property.
            if (rw.buf.items.len > 0) {
                const buf_len = rw.buf.items.len;
                const j = rw.these.len - buf_len;

                if (j > bytes.len) {
                    if (slices.startsWith(u8, rw.these[buf_len..], bytes)) {
                        try rw.buf.appendSlice(rw.allocator, bytes);
                        return 0;
                    }

                    n += buf_len;
                    try rw.flush();
                    n += try rw.writer.write(bytes);
                    return n;
                }

                if (slices.startsWith(u8, rw.these[buf_len..], bytes[0..j])) {
                    rw.buf.clearRetainingCapacity();
                    n += try rw.writer.write(rw.those);
                    i = j;
                } else {
                    n += buf_len;
                    try rw.flush();
                }
            }

            while (slices.findAt(u8, i, bytes, rw.these[0])) |j| {
                const remaining = bytes[j..];

                if (remaining.len < rw.these.len) {
                    if (!slices.startsWith(u8, rw.these, remaining)) {
                        i = j + 1;
                        continue;
                    }

                    if (i < j) n += try rw.writer.write(bytes[i..j]);
                    try rw.buf.appendSlice(rw.allocator, remaining);
                    i = bytes.len;
                    break;
                }

                if (i < j) n += try rw.writer.write(bytes[i..j]);
                n += try rw.writer.write(rw.those);
                i = j + rw.these.len;
            }

            if (i < bytes.len)
                n += try rw.writer.write(bytes[i..]);

            return n;
        }
    };
}
