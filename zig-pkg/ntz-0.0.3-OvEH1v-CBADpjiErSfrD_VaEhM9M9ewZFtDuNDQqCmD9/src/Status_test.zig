// Copyright 2025 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");
const testing = std.testing;

const ntz = @import("ntz");

test "ntz.Status" {
    const ally = testing.allocator;
    const io = testing.io;

    var grand_parent = ntz.Status{ .io = io };
    defer grand_parent.deinit(ally);
    var parent = try grand_parent.sub(ally);
    defer parent.deinit(ally);
    var child = try parent.sub(ally);

    try testing.expect(!grand_parent.isDone());
    try testing.expect(!parent.isDone());
    try testing.expect(!child.isDone());

    parent.done();

    try testing.expect(!grand_parent.isDone());
    try testing.expect(parent.isDone());
    try testing.expect(child.isDone());
}
