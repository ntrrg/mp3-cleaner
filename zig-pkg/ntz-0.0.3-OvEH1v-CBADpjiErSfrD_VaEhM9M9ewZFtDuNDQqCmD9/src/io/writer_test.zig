// Copyright 2025 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");
const testing = std.testing;

const ntz = @import("ntz");
const types = ntz.types;
const bytes = types.bytes;

const io_utils = ntz.io;

test "ntz.io.writer" {
    const ally = testing.allocator;

    var buf = bytes.buffer(ally);
    defer buf.deinit();

    const w = io_utils.writer(&buf, std.mem.Allocator.Error, bytes.Buffer.write);

    const n = try w.write("hello, world!");
    try testing.expectEqualStrings("hello, world!", buf.bytes());
    try testing.expectEqual(13, n);
}

test "ntz.io.Writer.toStd" {
    const ally = testing.allocator;

    var buf = bytes.buffer(ally);
    defer buf.deinit();

    const writer = io_utils.writer(&buf, std.mem.Allocator.Error, bytes.Buffer.write);
    var std_w = writer.toStd(&.{});
    var w = &std_w.interface;

    const n = try w.write("hello, world!");
    try testing.expectEqualStrings("hello, world!", buf.bytes());
    try testing.expectEqual(13, n);
}
