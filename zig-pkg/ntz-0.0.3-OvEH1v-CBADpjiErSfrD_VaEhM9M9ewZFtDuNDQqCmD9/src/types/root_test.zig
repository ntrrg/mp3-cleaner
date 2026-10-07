// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");
const testing = std.testing;

const ntz = @import("ntz");
const types = ntz.types;

test "ntz.types" {
    _ = @import("bytes_test.zig");
    _ = @import("enums_test.zig");
    _ = @import("errors_test.zig");
    _ = @import("funcs_test.zig");
    _ = @import("iterators_test.zig");
    _ = @import("slices_test.zig");
    //_ = @import("strings_test.zig");
    _ = @import("structs_test.zig");
}

const Point = struct {
    x: usize,
    y: usize,
};

const Line = struct {
    name: []const u8 = "",
    a: Point,
    b: Point,
};

const MaybeLine = struct {
    name: []const u8 = "",
    a: ?Point,
    b: ?Point,
};

const Triangle = struct {
    a: Line,
    b: Line,
    c: Line,
};

const MaybeTriangle = struct {
    const Self = @This();

    a: ?MaybeLine,
    b: ?MaybeLine,
    c: ?MaybeLine,
};

const Rectangle = struct {
    a: Line,
    b: Line,
    c: Line,
    d: Line,
};

const Figure = union(enum) {
    triangle: Triangle,
    rectangle: Rectangle,
};

// Child //

test "ntz.types.Child" {
    try testing.expectEqual(u8, types.Child([]u8));
    try testing.expectEqual(u8, types.Child([0]u8));
    try testing.expectEqual(u8, types.Child(*u8));
    try testing.expectEqual(u8, types.Child(*[0]u8));
    try testing.expectEqual(u8, types.Child(@Vector(0, u8)));
    try testing.expectEqual(@Vector(0, u8), types.Child(*@Vector(0, u8)));
    try testing.expectEqual(u8, types.Child([*]u8));
    try testing.expectEqual(u8, types.Child([*:0]u8));
    try testing.expectEqual(c_char, types.Child([*c]c_char));
    try testing.expectEqual(u8, types.Child(?u8));
    try testing.expectEqual(anyopaque, types.Child(*anyopaque));
}

// Field //

test "ntz.types.Field" {
    try testing.expectEqual(Line, types.Field(Triangle, "a"));
    try testing.expectEqual(Point, types.Field(Triangle, "b.a"));
    try testing.expectEqual(usize, types.Field(Rectangle, "c.b.x"));
    try testing.expectEqual(usize, types.Field(Figure, "rectangle.d.b.y"));
    try testing.expectEqual(?Point, types.Field(MaybeLine, "a"));
    try testing.expectEqual(?MaybeLine, types.Field(MaybeTriangle, "a"));
    try testing.expectEqual(?Point, types.Field(MaybeTriangle, "a.b"));
}

// field //

test "ntz.types.field" {
    const fig_tri = Figure{ .triangle = .{
        .a = .{ .a = .{ .x = 0, .y = 3 }, .b = .{ .x = 3, .y = 0 } },
        .b = .{ .a = .{ .x = 0, .y = 0 }, .b = .{ .x = 0, .y = 3 } },
        .c = .{ .a = .{ .x = 0, .y = 0 }, .b = .{ .x = 3, .y = 0 } },
    } };

    try testing.expectEqualDeep(
        Line{ .a = .{ .x = 0, .y = 3 }, .b = .{ .x = 3, .y = 0 } },
        types.field(fig_tri, "triangle.a"),
    );

    try testing.expectEqualDeep(
        Point{ .x = 0, .y = 3 },
        types.field(fig_tri, "triangle.b.b"),
    );

    try testing.expectEqual(3, types.field(fig_tri, "triangle.c.b.x"));

    const maybe_tri = MaybeTriangle{
        .a = .{ .a = .{ .x = 0, .y = 3 }, .b = .{ .x = 3, .y = 0 } },
        .b = .{ .a = .{ .x = 0, .y = 0 }, .b = .{ .x = 0, .y = 3 } },
        .c = null,
    };

    try testing.expectEqualDeep(
        MaybeLine{ .a = .{ .x = 0, .y = 3 }, .b = .{ .x = 3, .y = 0 } },
        types.field(maybe_tri, "a"),
    );

    try testing.expectEqualDeep(
        Point{ .x = 0, .y = 3 },
        types.field(maybe_tri, "b.b"),
    );

    try testing.expectEqual(0, types.field(maybe_tri, "c.b.x"));
}

// fields //

test "ntz.types.fields" {
    try testing.expectEqual(3, comptime types.fields(Triangle).names.len);
    try testing.expectEqual(3, comptime types.fields(Line).names.len);
    try testing.expectEqual(2, comptime types.fields(*Point).names.len);
    try testing.expectEqual(2, comptime types.fields(?Point).names.len);
    try testing.expectEqual(2, comptime types.fields(Figure).names.len);
    try testing.expectEqual(2, comptime types.fields(*Figure).names.len);
    try testing.expectEqual(2, comptime types.fields(?Figure).names.len);
}

// setField //

test "ntz.types.setField" {
    var fig_tri = Figure{ .triangle = .{
        .a = .{ .a = .{ .x = 0, .y = 3 }, .b = .{ .x = 3, .y = 0 } },
        .b = .{ .a = .{ .x = 0, .y = 0 }, .b = .{ .x = 0, .y = 3 } },
        .c = .{ .a = .{ .x = 0, .y = 0 }, .b = .{ .x = 3, .y = 0 } },
    } };

    try testing.expectEqual(3, fig_tri.triangle.a.b.x);
    types.setField(&fig_tri, "triangle.a.b.x", 2);
    try testing.expectEqual(2, fig_tri.triangle.a.b.x);

    try testing.expectEqualStrings("", fig_tri.triangle.a.name);
    types.setField(&fig_tri, "triangle.a.name", "Hypotenuse");
    try testing.expectEqualStrings("Hypotenuse", fig_tri.triangle.a.name);

    types.setField(&fig_tri, "triangle.c.name", "Opposite");
    try testing.expectEqualStrings("Opposite", fig_tri.triangle.c.name);
    types.setField(&fig_tri, "triangle.c.b", .{ .x = 2, .y = 0 });
    try testing.expectEqual(2, fig_tri.triangle.c.b.x);
    try testing.expectEqual(0, fig_tri.triangle.c.b.y);

    var maybe_tri = MaybeTriangle{
        .a = null,
        .b = null,
        .c = null,
    };

    types.setField(&maybe_tri, "a.a.y", 3);
    types.setField(&maybe_tri, "a.b.x", 2);
    types.setField(&maybe_tri, "a.name", "Hypotenuse");
    types.setField(&maybe_tri, "b", .{ .a = .{ .x = 0, .y = 0 }, .b = .{ .x = 0, .y = 3 } });
    types.setField(&maybe_tri, "c.name", "Opposite");
    types.setField(&maybe_tri, "c.a", .{ .x = 0, .y = 0 });
    types.setField(&maybe_tri, "c.b", .{ .x = 2, .y = 0 });

    try testing.expectEqual(fig_tri.triangle.a.a, maybe_tri.a.?.a.?);
    try testing.expectEqual(fig_tri.triangle.a.b, maybe_tri.a.?.b.?);
    try testing.expectEqual(fig_tri.triangle.b.a, maybe_tri.b.?.a.?);
    try testing.expectEqual(fig_tri.triangle.b.b, maybe_tri.b.?.b.?);
    try testing.expectEqual(fig_tri.triangle.c.a, maybe_tri.c.?.a.?);
    try testing.expectEqual(fig_tri.triangle.c.b, maybe_tri.c.?.b.?);
}
