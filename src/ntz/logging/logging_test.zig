// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");

const ntz = @import("ntz");
const testing = ntz.testing;

const logging = ntz.logging;

test "ntz.logging" {
    testing.refAllDecls(logging);

    _ = @import("level_test.zig");
    _ = @import("logger_test.zig");
}

test "ntz.logging.init" {
    const ally = testing.allocator;

    var buf = std.ArrayList(u8).init(ally);
    defer buf.deinit();
    const w = buf.writer();
    var mutex: std.Thread.Mutex = .{};
    const want = "key=1 group.key=\"1\" level=\"DBG\" msg=\"hello, world!\"\n";

    var log = logging.withWriter(w, &mutex, want.len, .{ .with_time = false })
        .withLevel(.debug)
        .with(u8, "key", 1)
        .withGroup("group")
        .with([]const u8, "key", "1");

    log.log(.debug, "hello, world!", .{});

    try testing.expectEqlStrs(buf.items, want);
}
