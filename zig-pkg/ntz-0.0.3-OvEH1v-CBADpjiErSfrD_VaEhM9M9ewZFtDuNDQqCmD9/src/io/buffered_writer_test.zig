// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");
const testing = std.testing;

const ntz = @import("ntz");
const types = ntz.types;
const bytes = types.bytes;

const io_utils = ntz.io;

test "ntz.io.buffered_writer: smaller than buffer size" {
    const ally = testing.allocator;

    var buf = bytes.buffer(ally);
    defer buf.deinit();
    var cw = io_utils.countingWriter(buf.writer());

    var bw_buf: [16]u8 = undefined;
    var bw = io_utils.bufferedWriter(cw.writer(), &bw_buf);

    const in = "hello, world!";
    const n = try bw.write(in);
    try testing.expectEqualStrings("", buf.bytes());
    try testing.expectEqual(in.len, n);
    try testing.expectEqual(0, cw.write_count);
    try testing.expectEqual(0, cw.byte_count);

    try bw.flush();
    try testing.expectEqualStrings(in, buf.bytes());
    try testing.expectEqual(1, cw.write_count);
    try testing.expectEqual(13, cw.byte_count);
}

test "ntz.io.buffered_writer: equal than buffer size" {
    const ally = testing.allocator;

    var buf = bytes.buffer(ally);
    defer buf.deinit();
    var cw = io_utils.countingWriter(buf.writer());

    var bw_buf: [13]u8 = undefined;
    var bw = io_utils.bufferedWriter(cw.writer(), &bw_buf);

    const in = "hello, world!";
    const n = try bw.write(in);
    try testing.expectEqualStrings(in, buf.bytes());
    try testing.expectEqual(in.len, n);
    try testing.expectEqual(1, cw.write_count);
    try testing.expectEqual(13, cw.byte_count);

    try bw.flush();
    try testing.expectEqual(1, cw.write_count);
    try testing.expectEqual(13, cw.byte_count);
}

test "ntz.io.buffered_writer: bigger than buffer size" {
    const ally = testing.allocator;

    var buf = bytes.buffer(ally);
    defer buf.deinit();
    var cw = io_utils.countingWriter(buf.writer());

    var bw_buf: [4]u8 = undefined;
    var bw = io_utils.bufferedWriter(cw.writer(), &bw_buf);

    const in = "hello, world!";
    const n = try bw.write(in);
    try testing.expectEqualStrings("hello, world", buf.bytes());
    try testing.expectEqual(in.len, n);
    try testing.expectEqual(3, cw.write_count);
    try testing.expectEqual(12, cw.byte_count);

    try bw.flush();
    try testing.expectEqualStrings(in, buf.bytes());
    try testing.expectEqual(4, cw.write_count);
    try testing.expectEqual(13, cw.byte_count);
}
