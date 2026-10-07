// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");
const testing = std.testing;

const ntz = @import("ntz");
const types = ntz.types;
const bytes = types.bytes;

const DynWriter = @import("DynWriter.zig");

test "ntz.io.Writer" {
    const ally = testing.allocator;

    var buf = bytes.buffer(ally);
    defer buf.deinit();

    const w = DynWriter.init(&buf);

    const n = try w.write("hello, world!");
    try testing.expectEqualStrings("hello, world!", buf.bytes());
    try testing.expectEqual(13, n);
}
