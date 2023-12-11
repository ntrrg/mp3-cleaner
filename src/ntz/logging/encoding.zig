// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");

const slices = @import("../types/slices.zig");
const types = @import("../types/types.zig");
const funcs = types.funcs;

/// Simplified contextal logging encoding. Use `encodeStr` for strings.
///
/// If `val` has a method `.asLog`, it will be used instead of default
/// encoding. This method must be of the following type:
///
/// ```zig
/// pub fn asLog(_: T, log: anytype, comptime key: []const u8) void
/// ```
pub fn encode(log: anytype, comptime key: []const u8, val: anytype) void {
    const T = @TypeOf(val);

    if (comptime funcs.hasFn(T, "asLog")) {
        val.asLog(log, key);
        return;
    }

    const value_ti = @typeInfo(T);

    if (key.len > 0 and value_ti != .Struct and value_ti != .Union)
        log.write(key ++ "=");

    const w = log.stdWriter();

    switch (value_ti) {
        .Bool => {
            log.write(if (val) "true" else "false");
        },

        .Int, .ComptimeInt => {
            std.fmt.format(w, "{d}", .{val}) catch unreachable;
        },

        .Float, .ComptimeFloat => {
            std.fmt.format(w, "{d}", .{val}) catch unreachable;
        },

        .Enum, .EnumLiteral => {
            log.write("\"");
            log.write(@tagName(val));
            log.write("\"");
        },

        .Struct => |struct_ti| {
            inline for (struct_ti.fields, 0..) |field, i| {
                if (i > 0) log.write(" ");

                encode(
                    log,
                    key ++ "." ++ field.name,
                    @field(val, field.name),
                );
            }
        },

        .Union => |union_ti| {
            if (union_ti.tag_type) |_| {
                switch (val) {
                    inline else => |v| {
                        encode(log, key, v);
                    },
                }
            } else {
                std.fmt.format(w, "\"{any}\"", .{val}) catch unreachable;
            }
        },

        .Pointer => |ptr_ti| {
            if (ptr_ti.size == .Slice) {
                if (ptr_ti.is_const and ptr_ti.child == u8 and std.unicode.utf8ValidateSlice(val)) {
                    log.write("\"");
                    log.write(val);
                    log.write("\"");
                } else {
                    log.write("[");

                    for (val, 0..) |item, i| {
                        if (i > 0) log.write(", ");
                        encode(log, "", item);
                    }

                    log.write("]");
                }
            } else {
                std.fmt.format(w, "\"{*}\"", .{val}) catch unreachable;
            }
        },

        .Optional => {
            if (val) |v| {
                encode(log, "", v);
            } else {
                log.write("null");
            }
        },

        .ErrorUnion => {
            if (val) |v| {
                encode(log, "", v);
            } else |e| {
                encode(log, "", e);
            }
        },

        .ErrorSet => {
            log.write("\"");
            log.write(@errorName(val));
            log.write("\"");
        },

        .Void => {
            log.write("void");
        },

        .Type => {
            log.write("\"");
            log.write(@typeName(val));
            log.write("\"");
        },

        else => {
            std.fmt.format(w, "\"{any}\"", .{val}) catch unreachable;
        },
    }
}

pub fn encodeStr(w: anytype, comptime key: []const u8, val: []const u8) void {
    if (key.len > 0)
        w.write(key ++ "=");

    w.write("\"");

    var i: usize = 0;

    while (slices.findAt(u8, i, val, '"')) |j| : (i = j) {
        w.write(val[i..j]);
        w.write("\\");
        w.write(val[j .. j + 1]);
        j += 1;
    }

    if (i < val.len)
        w.write(val[i..]);

    w.write("\"");
}

pub fn encodeRawStr(w: anytype, comptime key: []const u8, val: []const u8) void {
    if (key.len > 0)
        w.write(key ++ "=");

    w.write("\"");
    w.write(val);
    w.write("\"");
}

//fn formatInt(w: anytype, base: u8, value: anytype) !void {
//    const int_value = if (@TypeOf(value) == comptime_int) blk: {
//        const Int = std.math.IntFittingRange(value, value);
//        break :blk @as(Int, value);
//    } else value;
//
//    const value_info = @typeInfo(@TypeOf(int_value)).Int;
//
//    // The type must have the same size as `base` or be wider in order for the
//    // division to work
//    const min_int_bits = comptime @max(value_info.bits, 8);
//    const MinInt = std.meta.Int(.unsigned, min_int_bits);
//
//    const abs_value = @abs(int_value);
//    // The worst case in terms of space needed is base 2, plus 1 for the sign
//    var buf: [1 + @max(@as(comptime_int, value_info.bits), 1)]u8 = undefined;
//
//    var a: MinInt = abs_value;
//    var index: usize = buf.len;
//
//    while (true) {
//        const digit = a % base;
//        index -= 1;
//        buf[index] = digitToChar(@as(u8, @intCast(digit)), case);
//        a /= base;
//        if (a == 0) break;
//    }
//
//    if (value_info.signedness == .signed) {
//        if (value < 0) {
//            // Negative integer
//            index -= 1;
//            buf[index] = '-';
//        } else if (options.width == null or options.width.? == 0) {
//            // Positive integer, omit the plus sign
//        } else {
//            // Positive integer
//            index -= 1;
//            buf[index] = '+';
//        }
//    }
//
//    return formatBuf(buf[index..], options, w);
//}
//
//pub fn digitToChar(digit: u8, case: Case) u8 {
//    return switch (digit) {
//        0...9 => digit + '0',
//        10...35 => digit + ((if (case == .upper) @as(u8, 'A') else @as(u8, 'a')) - 10),
//        else => unreachable,
//    };
//}
//
//fn formatPtr(
//    value: anytype,
//    base: u8,
//    case: Case,
//    options: FormatOptions,
//    writer: anytype,
//) !void {
//    assert(base >= 2);
//
//    const int_value = if (@TypeOf(value) == comptime_int) blk: {
//        const Int = math.IntFittingRange(value, value);
//        break :blk @as(Int, value);
//    } else value;
//
//    const value_info = @typeInfo(@TypeOf(int_value)).Int;
//
//    // The type must have the same size as `base` or be wider in order for the
//    // division to work
//    const min_int_bits = comptime @max(value_info.bits, 8);
//    const MinInt = std.meta.Int(.unsigned, min_int_bits);
//
//    const abs_value = @abs(int_value);
//    // The worst case in terms of space needed is base 2, plus 1 for the sign
//    var buf: [1 + @max(@as(comptime_int, value_info.bits), 1)]u8 = undefined;
//
//    var a: MinInt = abs_value;
//    var index: usize = buf.len;
//
//    if (base == 10) {
//        while (a >= 100) : (a = @divTrunc(a, 100)) {
//            index -= 2;
//            buf[index..][0..2].* = digits2(@as(usize, @intCast(a % 100)));
//        }
//
//        if (a < 10) {
//            index -= 1;
//            buf[index] = '0' + @as(u8, @intCast(a));
//        } else {
//            index -= 2;
//            buf[index..][0..2].* = digits2(@as(usize, @intCast(a)));
//        }
//    } else {
//        while (true) {
//            const digit = a % base;
//            index -= 1;
//            buf[index] = digitToChar(@as(u8, @intCast(digit)), case);
//            a /= base;
//            if (a == 0) break;
//        }
//    }
//
//    if (value_info.signedness == .signed) {
//        if (value < 0) {
//            // Negative integer
//            index -= 1;
//            buf[index] = '-';
//        } else if (options.width == null or options.width.? == 0) {
//            // Positive integer, omit the plus sign
//        } else {
//            // Positive integer
//            index -= 1;
//            buf[index] = '+';
//        }
//    }
//
//    return formatBuf(buf[index..], options, writer);
//}
