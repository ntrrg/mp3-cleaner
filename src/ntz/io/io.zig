// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.io`
//!
//! I/O operations and utilities.

const types = @import("../types/types.zig");
const errors = types.errors;
const funcs = types.funcs;

// //////////
// Readers //
// //////////

//pub const CountingReader = @import("counting_reader.zig").CountingReader;
//pub const countingReader = @import("counting_reader.zig").init;

// //////////
// Writers //
// //////////

//pub const Writer = @import("Writer.zig");

pub const CustomWriter = @import("writer.zig").Writer;
pub const customWriter = @import("writer.zig").init;
pub const stdWriter = @import("std_writer.zig").init;

pub const BufferedWriter = @import("buffered_writer.zig").BufferedWriter;
pub const bufferedWriter = @import("buffered_writer.zig").init;

pub const CountingWriter = @import("counting_writer.zig").CountingWriter;
pub const countingWriter = @import("counting_writer.zig").init;

pub const DelimitedWriter = @import("delimited_writer.zig").DelimitedWriter;
pub const delimitedWriter = @import("delimited_writer.zig").init;

pub const LimitedWriter = @import("limited_writer.zig").LimitedWriter;
pub const limitedWriter = @import("limited_writer.zig").init;

pub const ReplaceWriter = @import("replace_writer.zig").ReplaceWriter;
pub const replaceWriter = @import("replace_writer.zig").init;

pub const ReplaceManyWriter = @import("replace_writer.zig").ReplaceManyWriter;
pub const replaceManyWriter = @import("replace_writer.zig").initMany;

/// Ensures all bytes are written into writer.
pub fn writeAll(
    writer: anytype,
    comptime Error: type,
    bytes: []const u8,
) Error!usize {
    if (!comptime funcs.hasFn(@TypeOf(writer), "writeAll"))
        return try writer.write(bytes);

    try writer.writeAll(bytes);
    return bytes.len;
}

//pub fn writeByte(w: Writer, byte: u8) !void {
//    const array = [1]u8{byte};
//    return w.writeAll(&array);
//}
//
//pub fn writeByteNTimes(w: Writer, byte: u8, n: usize) !void {
//    var bytes: [256]u8 = undefined;
//    @memset(bytes[0..], byte);
//
//    var remaining: usize = n;
//    while (remaining > 0) {
//        const to_write = @min(remaining, bytes.len);
//        try w.writeAll(bytes[0..to_write]);
//        remaining -= to_write;
//    }
//}
//
//pub inline fn writeInt(w: Writer, comptime T: type, value: T, endian: std.builtin.Endian) !void {
//    var bytes: [@divExact(@typeInfo(T).Int.bits, 8)]u8 = undefined;
//    mem.writeInt(std.math.ByteAlignedInt(@TypeOf(value)), &bytes, value, endian);
//    return w.writeAll(&bytes);
//}
//
//pub fn writeStruct(w: Writer, value: anytype) !void {
//    // Only extern and packed structs have defined in-memory layout.
//    comptime assert(@typeInfo(@TypeOf(value)).Struct.layout != .Auto);
//    return w.writeAll(mem.asBytes(&value));
//}
