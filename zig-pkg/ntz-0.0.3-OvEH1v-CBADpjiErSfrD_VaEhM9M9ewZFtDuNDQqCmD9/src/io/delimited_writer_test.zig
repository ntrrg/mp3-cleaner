// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");
const testing = std.testing;

const ntz = @import("ntz");
const types = ntz.types;
const bytes = types.bytes;

const io_utils = ntz.io;

test "ntz.io.delimited_writer" {
    const ally = testing.allocator;

    var buf = bytes.buffer(ally);
    defer buf.deinit();
    var cw = io_utils.countingWriter(buf.writer());

    var dw = io_utils.delimitedWriter(cw.writer(), ally, "\n");
    defer dw.deinit();

    const in = "hello\nworld";
    var n = try dw.write(in);
    try testing.expectEqualStrings("hello\n", buf.bytes());
    try testing.expectEqual(11, n);
    try testing.expectEqual(1, cw.write_count);
    try testing.expectEqual(6, cw.byte_count);

    n = try dw.write("\n");
    try testing.expectEqualStrings(in ++ "\n", buf.bytes());
    try testing.expectEqual(1, n);
    try testing.expectEqual(2, cw.write_count);
    try testing.expectEqual(12, cw.byte_count);
}

test "ntz.io.delimited_writer: exclude delimiter" {
    const ally = testing.allocator;

    var buf = bytes.buffer(ally);
    defer buf.deinit();
    var cw = io_utils.countingWriter(buf.writer());

    var dw = io_utils.delimitedWriter(cw.writer(), ally, "\n");
    dw.include = false;
    defer dw.deinit();

    const in = "hello\nworld\n!";
    var n = try dw.write(in);
    try testing.expectEqualStrings("helloworld", buf.bytes());
    try testing.expectEqual(13, n);
    try testing.expectEqual(2, cw.write_count);
    try testing.expectEqual(10, cw.byte_count);

    n = try dw.write("\n");
    try testing.expectEqualStrings("helloworld!", buf.bytes());
    try testing.expectEqual(1, n);
    try testing.expectEqual(3, cw.write_count);
    try testing.expectEqual(11, cw.byte_count);
}

test "ntz.io.delimited_writer: empty delimiter" {
    const ally = testing.allocator;

    var buf = bytes.buffer(ally);
    defer buf.deinit();
    var cw = io_utils.countingWriter(buf.writer());

    var dw = io_utils.delimitedWriter(cw.writer(), ally, "");
    defer dw.deinit();

    const in = "hello, world!";
    const n = try dw.write(in);
    try testing.expectEqualStrings(in, buf.bytes());
    try testing.expectEqual(n, in.len);
    try testing.expectEqual(13, cw.write_count);
    try testing.expectEqual(13, cw.byte_count);
}

test "ntz.io.delimited_writer: byte sequence delimiter" {
    const ally = testing.allocator;

    var buf = bytes.buffer(ally);
    defer buf.deinit();
    var cw = io_utils.countingWriter(buf.writer());

    var dw = io_utils.delimitedWriter(cw.writer(), ally, "--");
    defer dw.deinit();

    const in = "hello--world--!";
    var n = try dw.write(in);
    try testing.expectEqualStrings("hello--world--", buf.bytes());
    try testing.expectEqual(15, n);
    try testing.expectEqual(2, cw.write_count);
    try testing.expectEqual(14, cw.byte_count);

    n = try dw.write("--");
    try testing.expectEqualStrings(in ++ "--", buf.bytes());
    try testing.expectEqual(2, n);
    try testing.expectEqual(3, cw.write_count);
    try testing.expectEqual(17, cw.byte_count);
}

test "ntz.io.delimited_writer: partially written sequence delimiter" {
    const ally = testing.allocator;

    var buf = bytes.buffer(ally);
    defer buf.deinit();
    var cw = io_utils.countingWriter(buf.writer());

    var dw = io_utils.delimitedWriter(cw.writer(), ally, "---");
    defer dw.deinit();

    const in = "hello---world--";
    var n = try dw.write(in);
    try testing.expectEqualStrings("hello---", buf.bytes());
    try testing.expectEqual(15, n);
    try testing.expectEqual(1, cw.write_count);
    try testing.expectEqual(8, cw.byte_count);

    n = try dw.write("-!");
    try testing.expectEqualStrings(in ++ "-", buf.bytes());
    try testing.expectEqual(2, n);
    try testing.expectEqual(2, cw.write_count);
    try testing.expectEqual(16, cw.byte_count);

    try dw.flush();
    try testing.expectEqualStrings(in ++ "-!", buf.bytes());
    try testing.expectEqual(3, cw.write_count);
    try testing.expectEqual(17, cw.byte_count);

    n = try dw.write("-");
    try testing.expectEqualStrings(in ++ "-!", buf.bytes());
    try testing.expectEqual(1, n);
    try testing.expectEqual(3, cw.write_count);
    try testing.expectEqual(17, cw.byte_count);

    n = try dw.write("-");
    try testing.expectEqualStrings(in ++ "-!", buf.bytes());
    try testing.expectEqual(1, n);
    try testing.expectEqual(3, cw.write_count);
    try testing.expectEqual(17, cw.byte_count);

    n = try dw.write("-");
    try testing.expectEqualStrings(in ++ "-!---", buf.bytes());
    try testing.expectEqual(1, n);
    try testing.expectEqual(4, cw.write_count);
    try testing.expectEqual(20, cw.byte_count);

    n = try dw.write("-");
    try testing.expectEqualStrings(in ++ "-!---", buf.bytes());
    try testing.expectEqual(1, n);
    try testing.expectEqual(4, cw.write_count);
    try testing.expectEqual(20, cw.byte_count);

    n = try dw.write("_");
    try testing.expectEqualStrings(in ++ "-!---", buf.bytes());
    try testing.expectEqual(1, n);
    try testing.expectEqual(4, cw.write_count);
    try testing.expectEqual(20, cw.byte_count);

    n = try dw.write("-");
    try testing.expectEqualStrings(in ++ "-!---", buf.bytes());
    try testing.expectEqual(1, n);
    try testing.expectEqual(4, cw.write_count);
    try testing.expectEqual(20, cw.byte_count);

    try dw.flush();
    try testing.expectEqualStrings(in ++ "-!----_-", buf.bytes());
    try testing.expectEqual(5, cw.write_count);
    try testing.expectEqual(23, cw.byte_count);
}

test "ntz.io.delimited_writer: remove partially written sequence delimiter" {
    const ally = testing.allocator;

    var buf = bytes.buffer(ally);
    defer buf.deinit();
    var cw = io_utils.countingWriter(buf.writer());

    var dw = io_utils.delimitedWriter(cw.writer(), ally, "---");
    dw.include = false;
    defer dw.deinit();

    const in = "hello---world--";
    var n = try dw.write(in);
    try testing.expectEqualStrings("hello", buf.bytes());
    try testing.expectEqual(15, n);
    try testing.expectEqual(1, cw.write_count);
    try testing.expectEqual(5, cw.byte_count);

    n = try dw.write("-!");
    try testing.expectEqualStrings("helloworld", buf.bytes());
    try testing.expectEqual(2, n);
    try testing.expectEqual(2, cw.write_count);
    try testing.expectEqual(10, cw.byte_count);

    try dw.flush();
    try testing.expectEqualStrings("helloworld!", buf.bytes());
    try testing.expectEqual(3, cw.write_count);
    try testing.expectEqual(11, cw.byte_count);

    n = try dw.write("-");
    try testing.expectEqualStrings("helloworld!", buf.bytes());
    try testing.expectEqual(1, n);
    try testing.expectEqual(3, cw.write_count);
    try testing.expectEqual(11, cw.byte_count);

    n = try dw.write("-");
    try testing.expectEqualStrings("helloworld!", buf.bytes());
    try testing.expectEqual(1, n);
    try testing.expectEqual(3, cw.write_count);
    try testing.expectEqual(11, cw.byte_count);

    n = try dw.write("-");
    try testing.expectEqualStrings("helloworld!", buf.bytes());
    try testing.expectEqual(1, n);
    try testing.expectEqual(3, cw.write_count);
    try testing.expectEqual(11, cw.byte_count);

    n = try dw.write("-");
    try testing.expectEqualStrings("helloworld!", buf.bytes());
    try testing.expectEqual(1, n);
    try testing.expectEqual(3, cw.write_count);
    try testing.expectEqual(11, cw.byte_count);

    n = try dw.write("_");
    try testing.expectEqualStrings("helloworld!", buf.bytes());
    try testing.expectEqual(1, n);
    try testing.expectEqual(3, cw.write_count);
    try testing.expectEqual(11, cw.byte_count);

    n = try dw.write("-");
    try testing.expectEqualStrings("helloworld!", buf.bytes());
    try testing.expectEqual(1, n);
    try testing.expectEqual(3, cw.write_count);
    try testing.expectEqual(11, cw.byte_count);

    try dw.flush();
    try testing.expectEqualStrings("helloworld!-_-", buf.bytes());
    try testing.expectEqual(4, cw.write_count);
    try testing.expectEqual(14, cw.byte_count);
}
