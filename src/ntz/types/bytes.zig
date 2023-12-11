// Copyright 2024 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.types.bytes`
//!
//! Utilities for working with slices of bytes.

const errors = @import("errors.zig");
const slices = @import("slices.zig");

/// Creates a new slice that contains all bytes from `s` and adds `val` at the
/// end of it.
pub fn append(
    allocator: anytype,
    s: []const u8,
    val: u8,
) errors.From(@TypeOf(allocator))![]u8 {
    return slices.append(u8, allocator, s, val);
}

/// Creates a new slice that contains all bytes from `a` and `b`.
pub fn concat(
    allocator: anytype,
    a: []const u8,
    b: []const u8,
) errors.From(@TypeOf(allocator))![]u8 {
    return slices.concat(u8, allocator, a, b);
}

/// Creates a new slice that contains all bytes from given slices.
pub fn concatMany(
    allocator: anytype,
    many: []const []const u8,
) errors.From(@TypeOf(allocator))![]u8 {
    return slices.concatMany(u8, allocator, many);
}

/// Checks if `s` ends with `suffix`.
pub fn endsWith(s: []const u8, suffix: []const u8) bool {
    return slices.endsWith(u8, s, suffix);
}

/// Checks if `a` is equal to `b`.
pub fn eql(a: []const u8, b: []const u8) bool {
    return slices.eql(u8, a, b);
}

/// Checks if `a` is equal to all given slices.
pub fn eqlAll(a: []const u8, many: []const []const u8) bool {
    return slices.eqlAll(u8, a, many);
}

/// Checks if `a` is equal to any of the given slices.
pub fn eqlAny(a: []const u8, many: []const []const u8) bool {
    return slices.eqlAny(u8, a, many);
}

/// Finds the first appearance of `val` in `s` and returns its index.
pub fn find(s: []const u8, val: u8) ?usize {
    return slices.findAt(u8, 0, s, val);
}

/// Finds the first appearance of `val` in `s`, starting from index `at`, and
/// returns its index.
pub fn findAt(at: usize, s: []const u8, val: u8) ?usize {
    return slices.findAt(u8, at, s, val);
}

/// Checks if `s` starts with `prefix`.
pub fn startsWith(s: []const u8, prefix: []const u8) bool {
    return slices.startsWith(u8, s, prefix);
}
