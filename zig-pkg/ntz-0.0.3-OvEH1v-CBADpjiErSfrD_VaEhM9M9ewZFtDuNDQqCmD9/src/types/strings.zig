// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.types.strings`
//!
//! Utilities for working with Unicode UTF-8 encoded strings.

const bytes = @import("bytes.zig");
const utf8 = @import("../encoding/unicode/utf8.zig");

pub const String = struct {
    const Self = @This();

    data: []const u8,

    //pub fn iterator(s: Self) utf8.Iterator {
    //    return .init(s.data);
    //}

    pub fn len(s: Self) utf8.LenError!usize {
        return utf8.len(s.data);
    }
};

/// Creates a new string using the given bytes.
pub fn init(data: []const u8) String {
    return .{ .data = data };
}

const testing = @import("../testing/testing.zig");

/// Creates a new string that contains all characters from `this` and `that`.
pub fn concat(allocator: anytype, this: anytype, that: anytype) !String {
    testing.print("this: {}\n", .{@typeInfo(@TypeOf(this))});
    testing.print("that: {}\n", .{@typeInfo(@TypeOf(that))});
    const _this = if (@TypeOf(this) == String) this.data else this;
    const _that = if (@TypeOf(that) == String) that.data else that;
    return .{ .data = try bytes.concat(allocator, _this, _that) };
}

/// Creates a new string that contains all characters from the given strings.
pub fn concatMany(allocator: anytype, these: anytype) !String {
    var len: usize = 0;
    for (these) |s| len += if (is(s)) s.data.len else s.len;

    var new = try allocator.alloc(u8, len);
    errdefer allocator.free(new);

    var i: usize = 0;

    for (these) |s| {
        @memcpy(new[i .. i + s.len], s.data);
        i += s.data.len;
    }

    return .{ .data = new };
}

/// Checks if `this` ends with `suffix`.
pub fn endsWith(this: []const u8, suffix: []const u8) bool {
    return bytes.endsWith(this, suffix);
}

/// Checks if `this` is equal to `that`.
pub fn equal(this: []const u8, that: []const u8) bool {
    return bytes.equal(this, that);
}

/// Checks if `this` is equal to all the given strings.
pub fn equalAll(this: []const u8, all: []const []const u8) bool {
    return bytes.equalAll(this, all);
}

/// Checks if `this` is equal to any of the given strings.
pub fn equalAny(this: []const u8, any: []const []const u8) bool {
    return bytes.equalAny(this, any);
}

/// Finds the first appearance of `that` in `this` and returns its index.
pub fn find(this: []const u8, that: []const u8) ?usize {
    return bytes.findSeq(this, that);
}

/// Finds the first appearance of `that` in `this`, starting from index `at`,
/// and returns its index.
pub fn findAt(at: usize, this: []const u8, that: []const u8) ?usize {
    return bytes.findSeqAt(at, this, that);
}

/// Finds the first appearance of `that` in `this` and returns its index.
pub fn findByte(this: []const u8, that: u8) ?usize {
    return bytes.find(this, that);
}

/// Finds the first appearance of `that` in `this`, starting from index `at`,
/// and returns its index.
pub fn findByteAt(at: usize, this: []const u8, that: u8) ?usize {
    return bytes.findAt(at, this, that);
}

/// Checks if `val` is a `String`.
pub fn is(val: anytype) bool {
    return isStringType(@TypeOf(val));
}

/// Checks if `vals` is a group of `String`.
pub fn isStrings(vals: anytype) bool {
    const these_t = @TypeOf(vals);
    const these_ti = @typeInfo(these_t);

    switch (these_ti) {
        .pointer => |ptr| {
            switch (ptr.size) {
                .slice => {
                    return isStringType(ptr.child);
                },

                .one => {
                    const child_ti = @typeInfo(ptr.child);
                    if (child_ti != .array) return false;
                    return isStringType(child_ti.array.child);
                },

                else => return false,
            }
        },

        .array => |arr| {
            return isStringType(arr.child);
        },

        .@"struct" => |strt| {
            if (!strt.is_tuple) return false;

            inline for (strt.fields) |field| {
                if (!isStringType(field.type)) return false;
            } else return true;
        },

        else => return false,
    }
}

fn isStringType(t: type) bool {
    return switch (t) {
        String, *String, *const String => true,
        else => false,
    };
}

/// Checks if `this` starts with `prefix`.
pub fn startsWith(this: []const u8, prefix: []const u8) bool {
    return bytes.startsWith(this, prefix);
}
