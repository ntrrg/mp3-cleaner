// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");

const ntz = @import("ntz");
const testing = ntz.testing;

const io = ntz.io;

test "ntz.io.replace_writer" {
    const ally = testing.allocator;

    var buf = std.ArrayList(u8).init(ally);
    defer buf.deinit();
    const w = buf.writer();
    var cw = io.countingWriter(w);

    var dw = io.replaceWriter(&cw, '\n', " ");

    const in = "\nhello\nworld\n";
    const n = try dw.write(in);
    try testing.expectEqlStrs(buf.items, " hello world ");
    try testing.expectEql(n, 13);
    try testing.expectEql(cw.write_count, 5);
    try testing.expectEql(cw.byte_count, 13);
}

test "ntz.io.replace_writer: replace all" {
    const ally = testing.allocator;

    var buf = std.ArrayList(u8).init(ally);
    defer buf.deinit();
    const w = buf.writer();
    var cw = io.countingWriter(w);

    var dw = io.replaceWriter(&cw, "", "\x00");

    const in = "hello, world!";
    const n = try dw.write(in);
    try testing.expectEqlStrs(buf.items, &[_]u8{0} ** 13);
    try testing.expectEql(n, 13);
    try testing.expectEql(cw.write_count, 13);
    try testing.expectEql(cw.byte_count, 13);
}

test "ntz.io.replace_writer: single byte slice replace" {
    const ally = testing.allocator;

    var buf = std.ArrayList(u8).init(ally);
    defer buf.deinit();
    const w = buf.writer();
    var cw = io.countingWriter(w);

    var dw = io.replaceWriter(&cw, "\n", ", ");

    const in = "hello\nworld";
    const n = try dw.write(in);
    try testing.expectEqlStrs(buf.items, "hello, world");
    try testing.expectEql(n, 12);
    try testing.expectEql(cw.write_count, 3);
    try testing.expectEql(cw.byte_count, 12);
}

test "ntz.io.replace_writer: single byte slice sequence replace" {
    const ally = testing.allocator;

    var buf = std.ArrayList(u8).init(ally);
    defer buf.deinit();
    const w = buf.writer();
    var cw = io.countingWriter(w);

    var dw = io.replaceManyWriter(&cw, "\n", ", ", ally);
    defer dw.deinit();

    const in = "hello\nworld";
    const n = try dw.write(in);
    try testing.expectEqlStrs(buf.items, "hello, world");
    try testing.expectEql(n, 12);
    try testing.expectEql(cw.write_count, 3);
    try testing.expectEql(cw.byte_count, 12);
}

test "ntz.io.replace_writer: multiple byte sequence replace" {
    const ally = testing.allocator;

    var buf = std.ArrayList(u8).init(ally);
    defer buf.deinit();
    const w = buf.writer();
    var cw = io.countingWriter(w);

    var dw = io.replaceManyWriter(&cw, "___", "_-_", ally);
    defer dw.deinit();

    const in = "___hello,___worlld___!";
    const n = try dw.write(in);
    try testing.expectEqlStrs(buf.items, "_-_hello,_-_worlld_-_!");
    try testing.expectEql(n, 22);
    try testing.expectEql(cw.write_count, 6);
    try testing.expectEql(cw.byte_count, 22);
}

test "ntz.io.replace_writer: partially written sequence replace" {
    const ally = testing.allocator;

    var buf = std.ArrayList(u8).init(ally);
    defer buf.deinit();
    const w = buf.writer();
    var cw = io.countingWriter(w);

    var dw = io.replaceManyWriter(&cw, "abc", "--", ally);
    defer dw.deinit();

    var n = try dw.write("helloa");
    try testing.expectEqlStrs(buf.items, "hello");
    try testing.expectEql(n, 5);
    try testing.expectEql(cw.write_count, 1);
    try testing.expectEql(cw.byte_count, 5);

    n = try dw.write("bcworlda");
    try testing.expectEqlStrs(buf.items, "hello--world");
    try testing.expectEql(n, 7);
    try testing.expectEql(cw.write_count, 3);
    try testing.expectEql(cw.byte_count, 12);

    n = try dw.write("b");
    try testing.expectEqlStrs(buf.items, "hello--world");
    try testing.expectEql(n, 0);
    try testing.expectEql(cw.write_count, 3);
    try testing.expectEql(cw.byte_count, 12);

    n = try dw.write("c!");
    try testing.expectEqlStrs(buf.items, "hello--world--!");
    try testing.expectEql(n, 3);
    try testing.expectEql(cw.write_count, 5);
    try testing.expectEql(cw.byte_count, 15);

    n = try dw.write("a");
    try testing.expectEqlStrs(buf.items, "hello--world--!");
    try testing.expectEql(n, 0);
    try testing.expectEql(cw.write_count, 5);
    try testing.expectEql(cw.byte_count, 15);

    n = try dw.write("b");
    try testing.expectEqlStrs(buf.items, "hello--world--!");
    try testing.expectEql(n, 0);
    try testing.expectEql(cw.write_count, 5);
    try testing.expectEql(cw.byte_count, 15);

    n = try dw.write("d");
    try testing.expectEqlStrs(buf.items, "hello--world--!abd");
    try testing.expectEql(n, 3);
    try testing.expectEql(cw.write_count, 7);
    try testing.expectEql(cw.byte_count, 18);
}
