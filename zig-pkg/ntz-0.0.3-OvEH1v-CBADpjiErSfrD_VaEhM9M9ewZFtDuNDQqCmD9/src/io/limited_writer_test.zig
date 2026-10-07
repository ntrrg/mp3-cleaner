// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");
const testing = std.testing;

const ntz = @import("ntz");
const types = ntz.types;
const bytes = types.bytes;

const io_utils = ntz.io;

test "ntz.io.limitedWriter: Smaller than limit" {
    const ally = testing.allocator;

    var buf = bytes.buffer(ally);
    defer buf.deinit();
    var cw = io_utils.countingWriter(buf.writer());

    var lw = io_utils.limitedWriter(cw.writer(), 16);

    const in = "hello, world!";
    const n = try lw.write(in);
    try testing.expectEqualStrings(in, buf.bytes());
    try testing.expectEqual(in.len, n);
    try testing.expectEqual(1, cw.write_count);
    try testing.expectEqual(13, cw.byte_count);
}

test "ntz.io.limitedWriter: Equal than limit" {
    const ally = testing.allocator;

    var buf = bytes.buffer(ally);
    defer buf.deinit();
    var cw = io_utils.countingWriter(buf.writer());

    var lw = io_utils.limitedWriter(cw.writer(), 13);

    const in = "hello, world!";
    const n = try lw.write(in);
    try testing.expectEqualStrings(in, buf.bytes());
    try testing.expectEqual(in.len, n);
    try testing.expectEqual(1, cw.write_count);
    try testing.expectEqual(13, cw.byte_count);
}

test "ntz.io.limitedWriter: Bigger than limit" {
    const ally = testing.allocator;

    var buf = bytes.buffer(ally);
    defer buf.deinit();
    var cw = io_utils.countingWriter(buf.writer());

    var lw = io_utils.limitedWriter(cw.writer(), 5);

    var in: []const u8 = "hello, world!";
    var n = try lw.write(in);
    try testing.expectEqualStrings("hello", buf.bytes());
    try testing.expectEqual(13, n);
    try testing.expectEqual(1, cw.write_count);
    try testing.expectEqual(5, cw.byte_count);

    in = "hola, mundo!";
    n = try lw.write(in);
    try testing.expectEqualStrings("hello", buf.bytes());
    try testing.expectEqual(12, n);
    try testing.expectEqual(1, cw.write_count);
    try testing.expectEqual(5, cw.byte_count);

    buf.clear();
    lw.reset();
    in = "hola, mundo!";
    n = try lw.write(in);
    try testing.expectEqualStrings("hola,", buf.bytes());
    try testing.expectEqual(12, n);
    try testing.expectEqual(2, cw.write_count);
    try testing.expectEqual(10, cw.byte_count);
}
