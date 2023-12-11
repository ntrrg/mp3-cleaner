// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");

const ntz = @import("ntz");
const testing = ntz.testing;

const io = ntz.io;

test "ntz.io.limitedWriter: Smaller than limit" {
    const ally = testing.allocator;

    var buf = std.ArrayList(u8).init(ally);
    defer buf.deinit();
    const w = buf.writer();
    var cw = io.countingWriter(w);

    var lw = io.limitedWriter(&cw, 16);

    const in = "hello, world!";
    const n = try lw.write(in);
    try testing.expectEqlStrs(buf.items, in);
    try testing.expectEql(n, in.len);
    try testing.expectEql(cw.write_count, 1);
    try testing.expectEql(cw.byte_count, 13);
}

test "ntz.io.limitedWriter: Equal than limit" {
    const ally = testing.allocator;

    var buf = std.ArrayList(u8).init(ally);
    defer buf.deinit();
    const w = buf.writer();
    var cw = io.countingWriter(w);

    var lw = io.limitedWriter(&cw, 13);

    const in = "hello, world!";
    const n = try lw.write(in);
    try testing.expectEqlStrs(buf.items, in);
    try testing.expectEql(n, in.len);
    try testing.expectEql(cw.write_count, 1);
    try testing.expectEql(cw.byte_count, 13);
}

test "ntz.io.limitedWriter: Bigger than limit" {
    const ally = testing.allocator;

    var buf = std.ArrayList(u8).init(ally);
    defer buf.deinit();
    const w = buf.writer();
    var cw = io.countingWriter(w);

    var lw = io.limitedWriter(&cw, 5);

    var in: []const u8 = "hello, world!";
    var n = try lw.write(in);
    try testing.expectEqlStrs(buf.items, "hello");
    try testing.expectEql(n, 5);
    try testing.expectEql(cw.write_count, 1);
    try testing.expectEql(cw.byte_count, 5);

    in = "hola, mundo!";
    n = try lw.write(in);
    try testing.expectEqlStrs(buf.items, "hello");
    try testing.expectEql(n, 0);
    try testing.expectEql(cw.write_count, 1);
    try testing.expectEql(cw.byte_count, 5);

    buf.clearRetainingCapacity();
    lw.reset();
    in = "hola, mundo!";
    n = try lw.write(in);
    try testing.expectEqlStrs(buf.items, "hola,");
    try testing.expectEql(n, 5);
    try testing.expectEql(cw.write_count, 2);
    try testing.expectEql(cw.byte_count, 10);
}
