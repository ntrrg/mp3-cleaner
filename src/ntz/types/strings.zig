// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.types.strings`
//!
//! Utilities for working with Unicode UTF-8 encoded strings.

const bytes = @import("bytes.zig");
const unicode = @import("../encoding/unicode/unicode.zig");
const utf8 = unicode.utf8;

pub const String = struct {
    const Self = @This();

    data: []const u8,

    pub inline fn init(data: []const u8) Self {
        return .{ .data = data };
    }

    pub inline fn iterator(s: Self) utf8.Iterator {
        return .init(s.data);
    }

    pub inline fn len(s: Self) utf8.CountError!usize {
        return utf8.count(s.data);
    }
};

/// Creates a new string using the given bytes.
pub inline fn str(data: []const u8) String {
    return .init(data);
}

/// Creates a new string that contains all characters from `this` and `that`.
pub inline fn concat(
    allocator: anytype,
    this: []const u8,
    that: []const u8,
) ![]u8 {
    return bytes.concat(allocator, this, that);
}

/// Creates a new string that contains all characters from the given strings.
pub inline fn concatMany(
    allocator: anytype,
    these: []const []const u8,
) ![]u8 {
    return bytes.concatMany(allocator, these);
}

/// Checks if `this` ends with `suffix`.
pub inline fn endsWith(this: []const u8, suffix: []const u8) bool {
    return bytes.endsWith(this, suffix);
}

/// Checks if `this` is equal to `that`.
pub inline fn equal(this: []const u8, that: []const u8) bool {
    return bytes.equal(this, that);
}

/// Checks if `this` is equal to all the given strings.
pub inline fn equalAll(this: []const u8, all: []const []const u8) bool {
    return bytes.equalAll(this, all);
}

/// Checks if `this` is equal to any of the given strings.
pub inline fn equalAny(this: []const u8, any: []const []const u8) bool {
    return bytes.equalAny(this, any);
}

/// Finds the first appearance of `that` in `this` and returns its index.
pub inline fn find(this: []const u8, that: []const u8) ?usize {
    return bytes.findSeq(this, that);
}

/// Finds the first appearance of `that` in `this`, starting from index `at`,
/// and returns its index.
pub inline fn findAt(at: usize, this: []const u8, that: []const u8) ?usize {
    return bytes.findSeqAt(at, this, that);
}

/// Finds the first appearance of `that` in `this` and returns its index.
pub inline fn findByte(this: []const u8, that: u8) ?usize {
    return bytes.find(this, that);
}

/// Finds the first appearance of `that` in `this`, starting from index `at`,
/// and returns its index.
pub inline fn findByteAt(at: usize, this: []const u8, that: u8) ?usize {
    return bytes.findAt(at, this, that);
}

/// Checks if `this` starts with `prefix`.
pub inline fn startsWith(this: []const u8, prefix: []const u8) bool {
    return bytes.startsWith(this, prefix);
}
