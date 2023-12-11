// Copyright 2024 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.types.bytes`
//!
//! Utilities for working with slices of bytes.

const slices = @import("slices.zig");

/// Creates a new slice that contains all bytes from `these` and adds `that` at
/// the end of it.
pub inline fn append(
    allocator: anytype,
    these: []const u8,
    that: u8,
) ![]u8 {
    return slices.append(u8, allocator, these, that);
}

/// Creates a new slice that contains all bytes from `these` and `those`.
pub inline fn concat(
    allocator: anytype,
    these: []const u8,
    those: []const u8,
) ![]u8 {
    return slices.concat(u8, allocator, these, those);
}

/// Creates a new slice that contains all bytes from the given slices.
pub inline fn concatMany(
    allocator: anytype,
    these: []const []const u8,
) ![]u8 {
    return slices.concatMany(u8, allocator, these);
}

/// Checks if `these` ends with `suffix`.
pub inline fn endsWith(these: []const u8, suffix: []const u8) bool {
    return slices.endsWith(u8, these, suffix);
}

/// Checks if `these` is equal to `those`.
pub inline fn equal(these: []const u8, those: []const u8) bool {
    return slices.equal(u8, these, those);
}

/// Checks if `these` is equal to all the given slices.
pub inline fn equalAll(these: []const u8, all: []const []const u8) bool {
    return slices.equalAll(u8, these, all);
}

/// Checks if `these` is equal to any of the given slices.
pub inline fn equalAny(these: []const u8, any: []const []const u8) bool {
    return slices.equalAny(u8, these, any);
}

/// Finds the first appearance of `that` in `these` and returns its index.
pub inline fn find(these: []const u8, that: u8) ?usize {
    return slices.find(u8, these, that);
}

/// Finds the first appearance of `that` in `these`, starting from index `at`,
/// and returns its index.
pub inline fn findAt(at: usize, these: []const u8, that: u8) ?usize {
    return slices.findAt(u8, at, these, that);
}

/// Finds the first appearance of `those` in `these` and returns its index.
pub inline fn findSeq(these: []const u8, those: []const u8) ?usize {
    return slices.findSeq(u8, these, those);
}

/// Finds the first appearance of `those` in `these`, starting from index `at`,
/// and returns its index.
pub inline fn findSeqAt(at: usize, these: []const u8, those: []const u8) ?usize {
    return slices.findSeqAt(u8, at, these, those);
}

/// Checks if `these` starts with `prefix`.
pub inline fn startsWith(these: []const u8, prefix: []const u8) bool {
    return slices.startsWith(u8, these, prefix);
}
