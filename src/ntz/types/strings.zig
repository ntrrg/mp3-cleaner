// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.types.strings`
//!
//! Utilities for working with strings.

const errors = @import("errors.zig");
const bytes = @import("bytes.zig");

pub const Str = struct {
    const Self = @This();

    data: []const u8,

    pub fn init(data: []const u8) Self {
        return .{ .data = data };
    }

    pub fn fromCodepoint(p: u21) Self {
        return .{
            .data = .{p},
        };
    }

    pub fn bytes(s: Self) []const u8 {
        return s.data;
    }

    pub fn len(s: Self) usize {
        return s.data.len;
    }
};

/// Creates a new string that contains all characters from `a` and `b`.
pub fn concat(
    allocator: anytype,
    a: []const u8,
    b: []const u8,
) errors.From(@TypeOf(allocator))![]u8 {
    return bytes.concat(allocator, a, b);
}

/// Creates a new string that contains all characters from given strings.
pub fn concatMany(
    allocator: anytype,
    many: []const []const u8,
) errors.From(@TypeOf(allocator))![]u8 {
    return bytes.concatMany(allocator, many);
}

/// Checks if `s` ends with `suffix`.
pub fn endsWith(s: []const u8, suffix: []const u8) bool {
    return bytes.endsWith(s, suffix);
}

/// Checks if `a` is equal to `b`.
pub fn eql(a: []const u8, b: []const u8) bool {
    return bytes.eql(a, b);
}

/// Checks if `a` is equal to all given strings.
pub fn eqlAll(a: []const u8, many: []const []const u8) bool {
    return bytes.eqlAll(a, many);
}

/// Checks if `a` is equal to any of the given strings.
pub fn eqlAny(a: []const u8, many: []const []const u8) bool {
    return bytes.eqlAny(a, many);
}

/// Finds the first appearance of `byte` in `s` and returns its index.
pub fn findByte(s: []const u8, byte: u8) ?usize {
    return bytes.findAt(0, s, byte);
}

/// Finds the first appearance of `byte` in `s`, starting from index `at`, and
/// returns its index.
pub fn findByteAt(at: usize, s: []const u8, byte: u8) ?usize {
    return bytes.findAt(at, s, byte);
}

/// Checks if `s` starts with `prefix`.
pub fn startsWith(s: []const u8, prefix: []const u8) bool {
    return bytes.startsWith(s, prefix);
}
