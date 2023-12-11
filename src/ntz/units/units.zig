const std = @import("std");

const ntz = @import("../ntz.zig");
const enums = ntz.types.enums;

const Unit = struct {
    symbol: []const u8,
    type: []const u8,
};

const Reference = struct {
    from: Unit,
    to: Unit,
    value: f64,
};

const Scale = struct {
    power: u8,
    units: []const Unit,
};

const Prefix = struct {
    prefix: []const u8,
    symbol: []const u8,
    base: u8,
    power: u8,
};

fn humanize(comptime T: type, comptime factor: f64, n: usize) struct {
    value: f64,
    unit: T,
} {
    var v: f64 = @floatFromInt(n);
    var i: u4 = 0;

    while (v >= factor and i < @intFromEnum(enums.max(T))) : ({
        v /= factor;
        i += 1;
    }) {}

    return .{ .value = v, .unit = @enumFromInt(i) };
}

//const testing = std.testing;
//
//test "humanize" {
//    const Abc = enum {
//        A,
//        B,
//        C,
//        D,
//        E,
//        F,
//    };
//
//    testing.expect(humanize(Abc, 1000, 1000000) == .{ .value = 1, .unit = .C });
//}
