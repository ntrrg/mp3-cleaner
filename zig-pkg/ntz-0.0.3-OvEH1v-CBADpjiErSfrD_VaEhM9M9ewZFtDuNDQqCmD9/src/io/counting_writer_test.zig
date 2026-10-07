// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");
const testing = std.testing;

const ntz = @import("ntz");
const types = ntz.types;
const bytes = types.bytes;

const io_utils = ntz.io;

test "ntz.io.counting_writer" {
    const ally = testing.allocator;

    var buf = bytes.buffer(ally);
    defer buf.deinit();

    var cw = io_utils.countingWriter(buf.writer());

    var n = try cw.write("hello,");
    try testing.expectEqualStrings("hello,", buf.bytes());
    try testing.expectEqual(6, n);
    try testing.expectEqual(1, cw.write_count);
    try testing.expectEqual(6, cw.byte_count);

    n = try cw.write(" world");
    try testing.expectEqualStrings("hello, world", buf.bytes());
    try testing.expectEqual(6, n);
    try testing.expectEqual(2, cw.write_count);
    try testing.expectEqual(12, cw.byte_count);

    n = try cw.write("!");
    try testing.expectEqualStrings("hello, world!", buf.bytes());
    try testing.expectEqual(1, n);
    try testing.expectEqual(3, cw.write_count);
    try testing.expectEqual(13, cw.byte_count);
}
