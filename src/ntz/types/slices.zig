// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.types.slices`
//!
//! Utilities for working with slices.

const errors = @import("errors.zig");

/// Creates a new slice that contains all items from `s` and adds `val` at the
/// end of it.
pub fn append(
    comptime T: type,
    allocator: anytype,
    s: []const T,
    val: T,
) errors.From(@TypeOf(allocator))![]T {
    var new = try allocator.alloc(T, s.len + 1);
    @memcpy(new[0..s.len], s);
    new[s.len] = val;
    return new;
}

/// Creates a new slice that contains all items from `a` and `b`.
pub fn concat(
    comptime T: type,
    allocator: anytype,
    a: []const T,
    b: []const T,
) errors.From(@TypeOf(allocator))![]T {
    var new = try allocator.alloc(T, a.len + b.len);
    @memcpy(new[0..a.len], a);
    @memcpy(new[a.len..], b);
    return new;
}

/// Creates a new slice that contains all items from given slices.
pub fn concatMany(
    comptime T: type,
    allocator: anytype,
    many: []const []const T,
) errors.From(@TypeOf(allocator))![]T {
    var len: usize = 0;
    for (many) |s| len += s.len;

    var new = try allocator.alloc(T, len);
    var i: usize = 0;

    for (many) |s| {
        @memcpy(new[i .. i + s.len], s);
        i += s.len;
    }

    return new;
}

/// Checks if `s` ends with `suffix`.
pub fn endsWith(comptime T: type, s: []const T, suffix: []const T) bool {
    if (suffix.len == 0) return false;
    if (suffix.len > s.len) return false;
    return eql(T, suffix, s[s.len - suffix.len ..]);
}

/// Checks if `a` is equal to `b`.
pub fn eql(comptime T: type, a: []const T, b: []const T) bool {
    if (a.len != b.len) return false;
    if (a.ptr == b.ptr) return true;

    for (0..a.len) |i|
        if (a[i] != b[i]) return false;

    return true;
}

/// Checks if `a` is equal to all given slices.
pub fn eqlAll(comptime T: type, a: []const T, many: []const []const T) bool {
    if (many.len == 0) return false;

    for (many) |b|
        if (!eql(T, a, b)) return false;

    return true;
}

/// Checks if `a` is equal to any of the given slices.
pub fn eqlAny(comptime T: type, a: []const T, many: []const []const T) bool {
    if (many.len == 0) return false;

    for (many) |b|
        if (eql(T, a, b)) return true;

    return false;
}

/// Finds the first appearance of `val` in `s` and returns its index.
pub fn find(comptime T: type, s: []const T, val: T) ?usize {
    return findAt(T, 0, s, val);
}

/// Finds the first appearance of `val` in `s`, starting from index `at`, and
/// returns its index.
pub fn findAt(comptime T: type, at: usize, s: []const T, val: T) ?usize {
    var j = at;

    while (j < s.len) : (j += 1)
        if (s[j] == val) return j;

    return null;
}

/// Checks if `s` starts with `prefix`.
pub fn startsWith(comptime T: type, s: []const T, prefix: []const T) bool {
    if (prefix.len == 0) return false;
    if (prefix.len > s.len) return false;
    return eql(T, prefix, s[0..prefix.len]);
}
