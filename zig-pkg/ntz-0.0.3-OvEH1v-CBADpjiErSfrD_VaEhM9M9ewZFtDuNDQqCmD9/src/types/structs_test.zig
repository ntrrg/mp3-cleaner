// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");
const testing = std.testing;

const ntz = @import("ntz");
const structs = ntz.types.structs;

test "ntz.types.structs" {}

const Point = struct {
    x: usize,
    y: usize,
};

const Line = struct {
    a: Point,
    b: Point,
};

// init //

test "ntz.types.structs.init" {
    const line = structs.init(Line);
    try testing.expectEqualDeep(Point{ .x = 0, .y = 0 }, line.a);
    try testing.expectEqual(0, line.b.x);
    try testing.expectEqual(0, line.b.y);
}

// initWith //

test "ntz.types.structs.initWith" {
    const line = structs.initWith(Line, .{ .b = .{ .x = 2, .y = 3 } });
    try testing.expectEqualDeep(Point{ .x = 0, .y = 0 }, line.a);
    try testing.expectEqual(2, line.b.x);
    try testing.expectEqual(3, line.b.y);
}

//// //////////
//// Builder //
//// //////////
//
//test "ntz.types.structs.Builder" {
//    const Base = struct {
//        name: [:0]const u8,
//    };
//
//    const Point = comptime blk: {
//        var fields: [3]structs.Field = undefined;
//        var b = structs.Builder.initWith(Base, &fields);
//
//        b.addFields(.{
//            .{ .name = "x", .type = u8 },
//            .{ .name = "y", .type = u16 },
//        });
//
//        break :blk b.Type();
//    };
//
//    const point_ti = @typeInfo(Point).@"struct";
//    try testing.expectEql(point_ti.fields.len, 3);
//    try testing.expectEqlStrs(point_ti.fields[0].name, "name");
//    try testing.expectEql(point_ti.fields[0].type, [:0]const u8);
//    try testing.expectEqlStrs(point_ti.fields[1].name, "x");
//    try testing.expectEql(point_ti.fields[1].type, u8);
//    try testing.expectEqlStrs(point_ti.fields[2].name, "y");
//    try testing.expectEql(point_ti.fields[2].type, u16);
//
//    const p = Point{ .name = "PointA", .x = 10, .y = 11 };
//    try testing.expectEqlStrs(p.name, "PointA");
//    try testing.expectEql(p.x, 10);
//    try testing.expectEql(p.y, 11);
//}
//
//// ////////////
//// WithField //
//// ////////////
//
//test "ntz.types.structs.WithField" {
//    const Point_X = structs.WithField(struct {}, "x", usize);
//    const Point = structs.WithField(Point_X, "y", usize);
//    const Line_A = structs.WithField(struct {}, "a", Point);
//    const Line = structs.WithField(Line_A, "b", Point);
//
//    const line = structs.initWith(Line, .{
//        .a = .{ .x = 0, .y = 1 },
//        .b = .{ .x = 10, .y = 11 },
//    });
//
//    try testing.expectEql(line.a.x, 0);
//    try testing.expectEql(line.a.y, 1);
//    try testing.expectEql(line.b.x, 10);
//    try testing.expectEql(line.b.y, 11);
//
//    const Triangle_Hypo = structs.WithField(struct {}, "h", Line);
//    const Triangle_Opp = structs.WithField(Triangle_Hypo, "o", Line);
//    const Triangle = structs.WithField(Triangle_Opp, "a", Line);
//
//    const triangle = structs.initWith(Triangle, .{
//        .h = .{ .a = .{ .x = 0, .y = 0 }, .b = .{ .x = 4, .y = 3 } },
//        .o = .{ .a = .{ .x = 0, .y = 0 }, .b = .{ .x = 4, .y = 0 } },
//        .a = .{ .a = .{ .x = 4, .y = 0 }, .b = .{ .x = 4, .y = 3 } },
//    });
//
//    try testing.expectEql(triangle.h.a.x, 0);
//    try testing.expectEql(triangle.h.a.y, 0);
//    try testing.expectEql(triangle.h.b.x, 4);
//    try testing.expectEql(triangle.h.b.y, 3);
//
//    try testing.expectEql(triangle.o.a.x, 0);
//    try testing.expectEql(triangle.o.a.y, 0);
//    try testing.expectEql(triangle.o.b.x, 4);
//    try testing.expectEql(triangle.o.b.y, 0);
//
//    try testing.expectEql(triangle.a.a.x, 4);
//    try testing.expectEql(triangle.a.a.y, 0);
//    try testing.expectEql(triangle.a.b.x, 4);
//    try testing.expectEql(triangle.a.b.y, 3);
//}
//
//// //////////////
//// WithFieldAt //
//// //////////////
//
//test "ntz.types.structs.WithFieldAt" {
//    const Person = structs.WithFieldAt(struct {}, "", "name", [:0]const u8);
//    var person = structs.init(Person);
//    const name = "Miguel Angel Rivera Notararigo";
//    person.name = name;
//    try testing.expectEqlStrs(person.name, name);
//
//    const Dev = structs.WithFieldAt(Person, "lang", "name", [:0]const u8);
//    var dev = structs.initWith(Dev, person);
//    const lang = "Zig";
//    dev.lang.name = lang;
//    try testing.expectEqlStrs(dev.lang.name, lang);
//}
//
//test "ntz.types.structs.WithFieldAt: complex" {
//    const Triangle_Hypo_A_X = structs.WithFieldAt(
//        struct {},
//        "h.a",
//        "x",
//        usize,
//    );
//
//    const Triangle_Hypo_A_Y = structs.WithFieldAt(
//        Triangle_Hypo_A_X,
//        "h.a",
//        "y",
//        usize,
//    );
//
//    const Triangle_Hypo_B_X = structs.WithFieldAt(
//        Triangle_Hypo_A_Y,
//        "h.b",
//        "x",
//        usize,
//    );
//
//    const Triangle_Hypo_B_Y = structs.WithFieldAt(
//        Triangle_Hypo_B_X,
//        "h.b",
//        "y",
//        usize,
//    );
//
//    const Triangle_Opp_A_X = structs.WithFieldAt(
//        Triangle_Hypo_B_Y,
//        "o.a",
//        "x",
//        usize,
//    );
//
//    const Triangle_Opp_A_Y = structs.WithFieldAt(
//        Triangle_Opp_A_X,
//        "o.a",
//        "y",
//        usize,
//    );
//
//    const Triangle_Opp_B_X = structs.WithFieldAt(
//        Triangle_Opp_A_Y,
//        "o.b",
//        "x",
//        usize,
//    );
//
//    const Triangle_Opp_B_Y = structs.WithFieldAt(
//        Triangle_Opp_B_X,
//        "o.b",
//        "y",
//        usize,
//    );
//
//    const Triangle_Adj_A_X = structs.WithFieldAt(
//        Triangle_Opp_B_Y,
//        "a.a",
//        "x",
//        usize,
//    );
//
//    const Triangle_Adj_A_Y = structs.WithFieldAt(
//        Triangle_Adj_A_X,
//        "a.a",
//        "y",
//        usize,
//    );
//
//    const Triangle_Adj_B_X = structs.WithFieldAt(
//        Triangle_Adj_A_Y,
//        "a.b",
//        "x",
//        usize,
//    );
//
//    const Triangle = structs.WithFieldAt(
//        Triangle_Adj_B_X,
//        "a.b",
//        "y",
//        usize,
//    );
//
//    const triangle = structs.initWith(Triangle, .{
//        .h = .{ .a = .{ .x = 0, .y = 0 }, .b = .{ .x = 4, .y = 3 } },
//        .o = .{ .a = .{ .x = 0, .y = 0 }, .b = .{ .x = 4, .y = 0 } },
//        .a = .{ .a = .{ .x = 4, .y = 0 }, .b = .{ .x = 4, .y = 3 } },
//    });
//
//    try testing.expectEql(triangle.h.a.x, 0);
//    try testing.expectEql(triangle.h.a.y, 0);
//    try testing.expectEql(triangle.h.b.x, 4);
//    try testing.expectEql(triangle.h.b.y, 3);
//
//    try testing.expectEql(triangle.o.a.x, 0);
//    try testing.expectEql(triangle.o.a.y, 0);
//    try testing.expectEql(triangle.o.b.x, 4);
//    try testing.expectEql(triangle.o.b.y, 0);
//
//    try testing.expectEql(triangle.a.a.x, 4);
//    try testing.expectEql(triangle.a.a.y, 0);
//    try testing.expectEql(triangle.a.b.x, 4);
//    try testing.expectEql(triangle.a.b.y, 3);
//}
//
//test "ntz.types.structs.WithFieldAt: deep field path" {
//    const Deep = structs.WithFieldAt(
//        struct {},
//        "n.t.r.r.g",
//        "name",
//        [:0]const u8,
//    );
//
//    const name = "Miguel Angel Rivera Notararigo";
//    var deep = structs.init(Deep);
//    deep.n.t.r.r.g.name = name;
//    try testing.expectEqlStrs(deep.n.t.r.r.g.name, name);
//}
//
//// /////////////
//// WithFields //
//// /////////////
//
//test "ntz.types.structs.WithFields" {
//    const Point = structs.WithFields(structs.Empty, .{
//        .{ .name = "x", .type = usize },
//        .{ .name = "y", .type = usize },
//    });
//
//    const p = Point{ .x = 0, .y = 1 };
//    try testing.expectEql(p.x, 0);
//    try testing.expectEql(p.y, 1);
//
//    const Line = structs.WithFields(structs.Empty, .{
//        .{ .name = "a", .type = Point },
//        .{ .name = "b", .type = Point },
//    });
//
//    const line: Line = .{
//        .a = .{ .x = 0, .y = 1 },
//        .b = .{ .x = 10, .y = 11 },
//    };
//
//    try testing.expectEql(line.a.x, 0);
//    try testing.expectEql(line.a.y, 1);
//    try testing.expectEql(line.b.x, 10);
//    try testing.expectEql(line.b.y, 11);
//
//    const Triangle = structs.WithFields(structs.Empty, .{
//        .{ .name = "h", .type = Line },
//        .{ .name = "o", .type = Line },
//        .{ .name = "a", .type = Line },
//    });
//
//    const triangle: Triangle = .{
//        .h = .{ .a = .{ .x = 0, .y = 0 }, .b = .{ .x = 4, .y = 3 } },
//        .o = .{ .a = .{ .x = 0, .y = 0 }, .b = .{ .x = 4, .y = 0 } },
//        .a = .{ .a = .{ .x = 4, .y = 0 }, .b = .{ .x = 4, .y = 3 } },
//    };
//
//    try testing.expectEql(triangle.h.a.x, 0);
//    try testing.expectEql(triangle.h.a.y, 0);
//    try testing.expectEql(triangle.h.b.x, 4);
//    try testing.expectEql(triangle.h.b.y, 3);
//
//    try testing.expectEql(triangle.o.a.x, 0);
//    try testing.expectEql(triangle.o.a.y, 0);
//    try testing.expectEql(triangle.o.b.x, 4);
//    try testing.expectEql(triangle.o.b.y, 0);
//
//    try testing.expectEql(triangle.a.a.x, 4);
//    try testing.expectEql(triangle.a.a.y, 0);
//    try testing.expectEql(triangle.a.b.x, 4);
//    try testing.expectEql(triangle.a.b.y, 3);
//}
