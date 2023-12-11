// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");

const ntz = @import("ntz");
const testing = ntz.testing;

const io = ntz.io;

test "ntz.io.buffered_writer: Smaller than buffer size" {
    const ally = testing.allocator;

    var buf = std.ArrayList(u8).init(ally);
    defer buf.deinit();
    const w = buf.writer();
    var cw = io.countingWriter(w);

    var bw = io.bufferedWriter(&cw, 16);

    const in = "hello, world!";
    const n = try bw.write(in);
    try testing.expectEqlStrs(buf.items, "");
    try testing.expectEql(n, 0);
    try testing.expectEql(cw.write_count, 0);
    try testing.expectEql(cw.byte_count, 0);

    try bw.flush();
    try testing.expectEqlStrs(buf.items, in);
    try testing.expectEql(cw.write_count, 1);
    try testing.expectEql(cw.byte_count, 13);
}

test "ntz.io.buffered_writer: Equal than buffer size" {
    const ally = testing.allocator;

    var buf = std.ArrayList(u8).init(ally);
    defer buf.deinit();
    const w = buf.writer();
    var cw = io.countingWriter(w);

    var bw = io.bufferedWriter(&cw, 13);

    const in = "hello, world!";
    const n = try bw.write(in);
    try testing.expectEqlStrs(buf.items, in);
    try testing.expectEql(n, in.len);
    try testing.expectEql(cw.write_count, 1);
    try testing.expectEql(cw.byte_count, 13);

    try bw.flush();
    try testing.expectEql(cw.write_count, 1);
    try testing.expectEql(cw.byte_count, 13);
}

test "ntz.io.buffered_writer: Bigger than buffer size" {
    const ally = testing.allocator;

    var buf = std.ArrayList(u8).init(ally);
    defer buf.deinit();
    const w = buf.writer();
    var cw = io.countingWriter(w);

    var bw = io.bufferedWriter(&cw, 4);

    const in = "hello, world!";
    const n = try bw.write(in);
    try testing.expectEqlStrs(buf.items, "hello, world");
    try testing.expectEql(n, 12);
    try testing.expectEql(cw.write_count, 3);
    try testing.expectEql(cw.byte_count, 12);

    try bw.flush();
    try testing.expectEqlStrs(buf.items, in);
    try testing.expectEql(cw.write_count, 4);
    try testing.expectEql(cw.byte_count, 13);
}
