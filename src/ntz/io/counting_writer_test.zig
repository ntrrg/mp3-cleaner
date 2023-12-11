// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");

const ntz = @import("ntz");
const testing = ntz.testing;

const io = ntz.io;

test "ntz.io.counting_writer" {
    const ally = testing.allocator;

    var buf = std.ArrayList(u8).init(ally);
    defer buf.deinit();
    const w = buf.writer();

    var cw = io.countingWriter(w);

    var n = try cw.write("hello,");
    try testing.expectEqlStrs(buf.items, "hello,");
    try testing.expectEql(n, 6);
    try testing.expectEql(cw.write_count, 1);
    try testing.expectEql(cw.byte_count, 6);

    n = try cw.write(" world");
    try testing.expectEqlStrs(buf.items, "hello, world");
    try testing.expectEql(n, 6);
    try testing.expectEql(cw.write_count, 2);
    try testing.expectEql(cw.byte_count, 12);

    n = try cw.write("!");
    try testing.expectEqlStrs(buf.items, "hello, world!");
    try testing.expectEql(n, 1);
    try testing.expectEql(cw.write_count, 3);
    try testing.expectEql(cw.byte_count, 13);
}
