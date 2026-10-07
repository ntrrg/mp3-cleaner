// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");
const testing = std.testing;

const ntz = @import("ntz");
const funcs = ntz.types.funcs;

test "ntz.types.funcs" {}

fn someFn() void {}

test "ntz.types.funcs.ErrorSet" {
    try testing.expectEqual(
        funcs.ErrorSet(ntz.types.bytes.append),
        std.mem.Allocator.Error,
    );

    try testing.expectEqual(
        funcs.ErrorSet(ntz.encoding.unicode.Codepoint.validate),
        ntz.encoding.unicode.Codepoint.ValidateError,
    );
}

test "ntz.types.funcs.Return" {
    try testing.expectEqual(type, funcs.Return(funcs.Return));
    try testing.expectEqual(bool, funcs.Return(funcs.hasFn));
    try testing.expectEqual(void, funcs.Return(someFn));

    try testing.expectEqual(?[]const u8, funcs.Return(ntz.types.bytes.as));
    try testing.expectEqual(usize, funcs.Return(ntz.types.bytes.copy));

    try testing.expectEqual(
        funcs.ErrorSet(ntz.types.bytes.append)![]u8,
        funcs.Return(ntz.types.bytes.append),
    );

    try testing.expectEqual(
        funcs.ErrorSet(ntz.encoding.unicode.Codepoint.validate)!void,
        funcs.Return(ntz.encoding.unicode.Codepoint.validate),
    );
}

test "ntz.types.funcs.hasFn" {
    const Point = struct {
        const Self = @This();

        x: usize,
        y: usize,

        pub fn name(_: Self) []const u8 {
            return "Point";
        }

        pub fn namePtr(_: *Self) []const u8 {
            return "Point";
        }
    };

    const p: Point = .{ .x = 10, .y = 11 };

    try testing.expect(funcs.hasFn(@TypeOf(p), "name"));
    try testing.expect(funcs.hasFn(@TypeOf(&p), "name"));
    try testing.expect(funcs.hasFn(@TypeOf(p), "namePtr"));
    try testing.expect(funcs.hasFn(@TypeOf(&p), "namePtr"));
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
