// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.types.strings`
//!
//! Utilities for working with strings.

const errors = @import("errors.zig");
const slices = @import("slices.zig");

/// Creates a new string that contains all characters from `a` and `b`.
pub fn concat(
    a: []const u8,
    b: []const u8,
    allocator: anytype,
) errors.From(@TypeOf(allocator))![]u8 {
    var new = try allocator.alloc(u8, a.len + b.len);
    @memcpy(new[0..a.len], a);
    @memcpy(new[a.len..], b);
    return new;
}

/// Creates a new string that contains all characters from given strings.
pub fn concatMany(
    strings: []const []const u8,
    allocator: anytype,
) errors.From(@TypeOf(allocator))![]u8 {
    var len: usize = 0;
    for (strings) |items| len += items.len;

    var new = try allocator.alloc(u8, len);
    var i: usize = 0;

    for (strings) |items| {
        @memcpy(new[i .. i + items.len], items);
        i += items.len;
    }

    return new;
}

/// Checks if `s` ends with `suffix`.
pub fn endsWith(s: []const u8, suffix: []const u8) bool {
    return slices.endsWith(u8, s, suffix);
}

/// Checks if `a` is equal to `b`.
pub fn eql(a: []const u8, b: []const u8) bool {
    return slices.eql(u8, a, b);
}

/// Checks if `a` is equal to all given strings.
pub fn eqlAll(a: []const u8, strings: []const []const u8) bool {
    return slices.eqlAll(u8, a, strings);
}

/// Checks if `a` is equal to any of the given strings.
pub fn eqlAny(a: []const u8, strings: []const []const u8) bool {
    return slices.eqlAny(u8, a, strings);
}

/// Finds the first appearance of `item` in `s` and returns its index.
pub fn findByte(s: []const u8, byte: u8) ?usize {
    return slices.findAt(u8, 0, s, byte);
}

/// Finds the first appearance of `item` in `s`, starting from index `at`, and
/// returns its index.
pub fn findByteAt(at: usize, s: []const u8, byte: u8) ?usize {
    return slices.findAt(u8, at, s, byte);
}

/// Checks if `s` starts with `prefix`.
pub fn startsWith(s: []const u8, prefix: []const u8) bool {
    return slices.startsWith(u8, s, prefix);
}
