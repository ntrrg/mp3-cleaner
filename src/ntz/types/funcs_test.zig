// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const ntz = @import("ntz");
const testing = ntz.testing;

const funcs = ntz.types.funcs;

test "ntz.types.funcs" {
    testing.refAllDecls(funcs);
}

test "ntz.types.funcs.hasFn" {
    const Point = struct {
        const Self = @This();

        x: usize,
        y: usize,

        pub fn name(_: Self) []const u8 {
            return "Point";
        }
    };

    const p: Point = .{ .x = 10, .y = 11 };

    try testing.expect(funcs.hasFn(@TypeOf(p), "name"));
    try testing.expect(funcs.hasFn(@TypeOf(&p), "name"));
    try testing.expect(!funcs.hasFn(@TypeOf(p), "other"));
    try testing.expect(!funcs.hasFn(@TypeOf(&p), "other"));

    try testing.expect(!funcs.hasFn(u8, "name"));
    try testing.expect(!funcs.hasFn(*u8, "name"));
    try testing.expect(!funcs.hasFn([]const u8, "name"));
    try testing.expect(!funcs.hasFn(error{ Hello, World }, "name"));
    try testing.expect(!funcs.hasFn(struct {}, "name"));
    try testing.expect(!funcs.hasFn(union {}, "name"));
    try testing.expect(!funcs.hasFn(enum {}, "name"));
}
