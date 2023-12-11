// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.types.slices`
//!
//! Utilities for working with slices.

const errors = @import("errors.zig");

/// Creates a new slice that contains all items from `s` and adds `v` at the
/// end of it.
pub fn append(
    comptime T: type,
    s: []const T,
    v: T,
    allocator: anytype,
) errors.From(@TypeOf(allocator))![]T {
    var new = try allocator.alloc(T, s.len + 1);
    @memcpy(new[0..s.len], s);
    new[s.len] = v;
    return new;
}

/// Creates a new slice that contains all items from `a` and `b`.
pub fn concat(
    comptime T: type,
    a: []const T,
    b: []const T,
    allocator: anytype,
) errors.From(@TypeOf(allocator))![]T {
    var new = try allocator.alloc(T, a.len + b.len);
    @memcpy(new[0..a.len], a);
    @memcpy(new[a.len..], b);
    return new;
}

/// Creates a new slice that contains all items from given slices.
pub fn concatMany(
    comptime T: type,
    slices: []const []const T,
    allocator: anytype,
) errors.From(@TypeOf(allocator))![]T {
    var len: usize = 0;
    for (slices) |items| len += items.len;

    var new = try allocator.alloc(T, len);
    var i: usize = 0;

    for (slices) |items| {
        @memcpy(new[i .. i + items.len], items);
        i += items.len;
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
pub fn eqlAll(comptime T: type, a: []const T, slices: []const []const T) bool {
    if (slices.len == 0) return false;

    for (slices) |b|
        if (!eql(T, a, b)) return false;

    return true;
}

/// Checks if `a` is equal to any of the given slices.
pub fn eqlAny(comptime T: type, a: []const T, slices: []const []const T) bool {
    if (slices.len == 0) return false;

    for (slices) |b|
        if (eql(T, a, b)) return true;

    return false;
}

/// Finds the first appearance of `item` in `s` and returns its index.
pub fn find(comptime T: type, s: []const T, item: T) ?usize {
    return findAt(T, 0, s, item);
}

/// Finds the first appearance of `item` in `s`, starting from index `at`, and
/// returns its index.
pub fn findAt(comptime T: type, at: usize, s: []const T, item: T) ?usize {
    var j = at;

    while (j < s.len) : (j += 1)
        if (s[j] == item) return j;

    return null;
}

/// Checks if `s` starts with `prefix`.
pub fn startsWith(comptime T: type, s: []const T, prefix: []const T) bool {
    if (prefix.len == 0) return false;
    if (prefix.len > s.len) return false;
    return eql(T, prefix, s[0..prefix.len]);
}
