// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.types.slices`
//!
//! Utilities for working with slices.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("root.zig");
const iterators = types.iterators;

/// Returns the child type of the given slice-able type.
pub fn Child(comptime T: type) type {
    const err_msg = @typeName(T) ++ " is not a slice-able type";

    return switch (@typeInfo(T)) {
        .pointer => |ti| switch (ti.size) {
            .slice => ti.child,

            .one => switch (@typeInfo(ti.child)) {
                .array => |child_ti| return child_ti.child,
                else => @compileError(err_msg),
            },

            .many => if (ti.sentinel()) |_|
                ti.child
            else
                @compileError(err_msg),

            else => @compileError(err_msg),
        },

        .array => |ti| ti.child,
        else => @compileError(err_msg),
    };
}

/// Creates a new slice that contains all items from `these` and adds `that` at
/// the end of it.
pub fn append(
    comptime T: type,
    allocator: Allocator,
    these: []const T,
    that: T,
) Allocator.Error![]T {
    var new = try allocator.alloc(T, these.len + 1);
    errdefer allocator.free(new);
    @memcpy(new[0..these.len], these);
    new[these.len] = that;
    return new;
}

/// Coerces the given slice-able type (arrays and pointers) to a slice.
///
/// This is normally done by the compiler, but for functions receiving
/// `anytype` arguments, it cannot be enforced.
pub fn as(value: anytype) ?[]const types.Child(@TypeOf(value)) {
    return switch (@typeInfo(@TypeOf(value))) {
        .array => &value,

        .pointer => |ti| switch (ti.size) {
            .slice => value,

            .many => blk: {
                if (ti.sentinel()) |sent| {
                    var l: usize = 0;
                    while (value[l] != sent) l += 1;
                    break :blk value[0..l];
                } else {
                    break :blk null;
                }
            },

            .one => switch (@typeInfo(ti.child)) {
                .array => value,
                else => null,
            },

            .c => null,
        },

        else => null,
    };
}

/// Creates a new slice that contains all items from `these` and `those`.
pub fn concat(
    comptime T: type,
    allocator: Allocator,
    these: []const T,
    those: []const T,
) Allocator.Error![]T {
    var new = try allocator.alloc(T, these.len + those.len);
    errdefer allocator.free(new);
    _ = copyMany(T, new[0..], &.{ these, those });
    return new;
}

/// Creates a new slice that contains all items from the given slices.
pub fn concatMany(
    comptime T: type,
    allocator: Allocator,
    these: []const []const T,
) Allocator.Error![]T {
    var n: usize = 0;
    for (these) |s| n += s.len;
    var new = try allocator.alloc(T, n);
    errdefer allocator.free(new);
    _ = copyMany(T, new[0..], these);
    return new;
}

/// Copies up to `dst.len` elements from `src` into `dst`.
///
/// Cannot copy overlapping slices, use `copyLtr` and `copyRtl` instead.
///
/// The actual number of elements copied is returned.
pub fn copy(comptime T: type, dst: []T, src: []const T) usize {
    return copyAt(T, 0, dst, src);
}

/// Copies up to `dst.len - at` elements from `src` into `dst[at..]`.
///
/// Cannot copy overlapping slices, use `copyLtr` and `copyRtl` instead.
///
/// The actual number of elements copied is returned.
pub fn copyAt(comptime T: type, at: usize, dst: []T, src: []const T) usize {
    if (at > dst.len) return 0;
    const n = @min(dst.len - at, src.len);
    const j = @min(at + n, dst.len);
    @memcpy(dst[at..j], src[0..n]);
    return n;
}

/// Copies elements from `src` into `dst`. Elements are copied from left to
/// right one by one.
///
/// ```
/// src = [1 2 3]
/// dst = [4 5 6]
///
/// src[0] = dst[0]
/// src[1] = dst[1]
/// src[2] = dst[2]
/// ```
///
/// The actual number of elements copied is returned.
pub fn copyLtr(comptime T: type, dst: []T, src: []const T) usize {
    const l = @min(dst.len, src.len);
    for (0..l) |i| dst[i] = src[i];
    return l;
}

/// Copies up to `dst.len` elements from various sources into `dst`.
///
/// The actual number of elements copied is returned.
pub fn copyMany(comptime T: type, dst: []T, srcs: []const []const T) usize {
    var i: usize = 0;

    for (srcs) |src| {
        i += copyAt(T, i, dst, src);
        if (i == dst.len) break;
    }

    return i;
}

/// Copies elements from `src` into `dst`. Elements are copied from right to
/// left one by one.
///
/// ```
/// src = [1 2 3]
/// dst = [4 5 6]
///
/// src[2] = dst[2]
/// src[1] = dst[1]
/// src[0] = dst[0]
/// ```
///
/// The actual number of elements copied is returned.
pub fn copyRtl(comptime T: type, dst: []T, src: []const T) usize {
    const l = @min(dst.len, src.len);
    var i = l;
    while (i > 0) : (i -= 1) dst[i - 1] = src[i - 1];
    return l;
}

/// Counts how many times `that` appears in `these`.
pub fn count(comptime T: type, these: []const T, that: T) usize {
    return countAt(T, 0, these, that);
}

/// Counts how many times `that` appears in `these`, starting from index `at`.
pub fn countAt(comptime T: type, at: usize, these: []const T, that: T) usize {
    var i = at;
    var n: usize = 0;

    while (findAt(T, i, these, that)) |j| {
        n += 1;
        i = j + 1;
    }

    return n;
}

/// Checks if `these` ends with `suffix`.
pub fn endsWith(comptime T: type, these: []const T, suffix: []const T) bool {
    if (suffix.len == 0) return false;
    if (suffix.len > these.len) return false;
    return equal(T, suffix, these[these.len - suffix.len ..]);
}

/// Checks if `these` is equal to `those`.
pub fn equal(comptime T: type, these: []const T, those: []const T) bool {
    if (these.len != those.len) return false;
    if (these.ptr == those.ptr) return true;

    for (0..these.len) |i|
        if (these[i] != those[i]) return false;

    return true;
}

/// Checks if `these` is equal to all the given slices.
pub fn equalAll(comptime T: type, these: []const T, all: []const []const T) bool {
    if (all.len == 0) return false;

    for (all) |those|
        if (!equal(T, these, those)) return false;

    return true;
}

/// Checks if `these` is equal to any of the given slices.
pub fn equalAny(comptime T: type, these: []const T, any: []const []const T) bool {
    if (any.len == 0) return false;

    for (any) |those|
        if (equal(T, these, those)) return true;

    return false;
}

/// Finds the first appearance of `that` in `these` and returns its index.
pub fn find(comptime T: type, these: []const T, that: T) ?usize {
    return findAt(T, 0, these, that);
}

/// Finds the first appearance of `that` in `these`, starting from index `at`,
/// and returns its index.
pub fn findAt(comptime T: type, at: usize, these: []const T, that: T) ?usize {
    if (at > these.len) return null;

    for (at..these.len) |i|
        if (these[i] == that) return i;

    return null;
}

pub fn FindAnyResult(comptime T: type) type {
    return struct {
        index: usize,
        value: T,
    };
}

/// Finds the first appearance of any element from `those` in `these`, and
/// returns its index and the matching element.
pub fn findAny(
    comptime T: type,
    these: []const T,
    those: []const T,
) ?FindAnyResult(T) {
    return findAnyAt(T, 0, these, those);
}

/// Finds the first appearance of any element from `those` in `these`, starting
/// from index `at`, and returns its index and the matching element.
pub fn findAnyAt(
    comptime T: type,
    at: usize,
    these: []const T,
    those: []const T,
) ?FindAnyResult(T) {
    if (at > these.len) return null;

    for (at..these.len) |i|
        for (those) |that|
            if (these[i] == that) return .{ .index = i, .value = that };

    return null;
}

/// Finds the first appearance of `those` in `these` and returns its index.
pub fn findSeq(comptime T: type, these: []const T, those: []const T) ?usize {
    return findSeqAt(T, 0, these, those);
}

/// Finds the first appearance of `those` in `these`, starting from index `at`,
/// and returns its index.
pub fn findSeqAt(comptime T: type, at: usize, these: []const T, those: []const T) ?usize {
    if (those.len == 0) return null;
    if (those.len > these.len) return null;

    var i = at;

    while (i < these.len) {
        i = findAt(T, i, these, those[0]) orelse return null;
        if (startsWith(T, these[i..], those)) return i;
        i += 1;
    }

    return null;
}

/// Checks if the given value is a slice-able type (arrays and pointers).
///
/// If `value` is a type, this will check if the given type may be coerced to a
/// slice.
pub fn is(value: anytype) bool {
    return switch (@typeInfo(@TypeOf(value))) {
        .array => true,

        .pointer => |ti| switch (ti.size) {
            .slice => true,

            .one => switch (@typeInfo(ti.child)) {
                .array => true,
                else => false,
            },

            .many => if (ti.sentinel()) |_| true else false,
            .c => false,
        },

        else => false,
    };
}

/// Splits `these` in 2 at the first appearance of `that`. If `that` is not
/// found, `these` will be returned as the first part, and an empty slice as
/// the rest.
pub fn split(comptime T: type, these: []const T, that: T) [2][]const T {
    return splitAt(T, 0, these, that);
}

/// Splits `these` in 2 at the first appearance of `that`, starting from index
/// `at`. If `that` is not found, `these` will be returned as the first part,
/// and an empty slice as the rest.
pub fn splitAt(comptime T: type, at: usize, these: []const T, that: T) [2][]const T {
    const i = findAt(T, at, these, that) orelse return .{ these[at..], &.{} };
    return .{ these[at..i], these[i + 1 ..] };
}

/// Counts how many slices may be sliced out of `these` using `that` as
/// separator.
pub fn splitCount(comptime T: type, these: []const T, that: T) usize {
    if (these.len == 0) return 1;
    var i: usize = 0;
    var n: usize = 0;

    while (findAt(T, i, these, that)) |j| {
        n += 1;
        i = j + 1;
    }

    if (i < these.len or endsWith(T, these, &.{that})) n += 1;
    return n;
}

/// Creates an iterator that splits `these` in any appearance of `that`.
pub fn splitIterator(
    comptime T: type,
    these: []const T,
    that: T,
) SplitIterator(T).Iterator {
    const it = SplitIterator(T){ .data = these, .sep = that };
    return it.iterator();
}

pub const SplitError = error{
    OutOfMemory,
};

/// Splits `these` at the appearances of `that` up to `n` times, the resulting
/// slices are stored in `out`. If `that` is not found, `these` will be
/// returned as the only item.
pub fn splitn(
    comptime T: type,
    n: usize,
    out: [][]const T,
    these: []const T,
    that: T,
) SplitError![]const []const T {
    return splitnAt(T, 0, n, out, these, that);
}

/// Splits `these` at the appearances of `that` up to `n` times, starting from
/// index `at`, the resulting slices are stored in `out`. If `that` is not
/// found, `these` will be returned as the only item.
pub fn splitnAt(
    comptime T: type,
    at: usize,
    n: usize,
    out: [][]const T,
    these: []const T,
    that: T,
) SplitError![]const []const T {
    if (out.len == 0) return error.OutOfMemory;

    if (these.len == 0 or n == 0) {
        out[0] = these;
        return out[0..1];
    }

    var i = at;
    var out_i: usize = 0;
    var split_count: usize = 0;

    while (findAt(T, i, these, that)) |j| {
        if (out_i >= out.len) return error.OutOfMemory;
        out[out_i] = these[i..j];
        out_i += 1;

        i = j + 1;
        split_count += 1;
        if (split_count >= n) break;
    }

    if (i < these.len or endsWith(T, these, &.{that})) {
        if (out_i >= out.len) return error.OutOfMemory;
        out[out_i] = these[i..these.len];
        out_i += 1;
    }

    return out[0..out_i];
}

/// Checks if `these` starts with `prefix`.
pub fn startsWith(comptime T: type, these: []const T, prefix: []const T) bool {
    if (prefix.len == 0) return false;
    if (prefix.len > these.len) return false;
    return equal(T, these[0..prefix.len], prefix);
}

// ///////////
// Iterator //
// ///////////

fn iteratorNextIndex(comptime T: type) fn (slc: *[]const T, index: usize) usize {
    return struct {
        pub fn nextIndex(_: *[]const T, index: usize) usize {
            return index +| 1;
        }
    }.nextIndex;
}

fn iteratorGetItem(comptime T: type) fn (slc: *[]const T, index: usize) ?T {
    return struct {
        pub fn getItem(slc: *[]const T, index: usize) ?T {
            return if (index < slc.len) slc.*[index] else null;
        }
    }.getItem;
}

/// An `iterators.Iterator` implementation for slices.
pub fn Iterator(comptime T: type) type {
    return iterators.Iterator(
        []const T,
        usize,
        T,
        null,
        iteratorNextIndex(T),
        iteratorGetItem(T),
    );
}

/// Creates an iterator from the given slice-able value.
pub fn iterator(value: anytype) Iterator(Child(@TypeOf(value))) {
    return .{ .ctx = value, .index = 0 };
}

// ////////
// Slice //
// ////////

/// Self growable slice.
///
/// Allocated memory is owned by the caller.
pub fn Slice(comptime T: type) type {
    return struct {
        const Self = @This();

        /// Underlying memory.
        ptr: [*]T = undefined,

        /// Number of items the slice may contain without memory allocations.
        cap: usize = 0,

        /// Number of items the slice contain.
        len: usize = 0,

        pub fn deinit(slc: *Self, allocator: Allocator) void {
            if (slc.cap == 0) return;
            allocator.free(slc.ptr[0..slc.cap]);
            slc.ptr = undefined;
            slc.cap = 0;
            slc.len = 0;
        }

        /// Adds the given item at the end of the slice.
        ///
        /// This only allocates memory when there is not enough capacity.
        pub fn append(
            slc: *Self,
            allocator: Allocator,
            elem: T,
        ) Allocator.Error!void {
            try slc.ensureCapacity(allocator, slc.len + 1);
            slc.ptr[slc.len] = elem;
            slc.len += 1;
        }

        /// Adds the given item at the end of the slice and returns its
        /// pointer.
        ///
        /// This only allocates memory when there is not enough capacity.
        pub fn appendAndReturn(
            slc: *Self,
            allocator: Allocator,
            elem: T,
        ) Allocator.Error!*T {
            try slc.append(allocator, elem);
            return &slc.ptr[slc.len - 1];
        }

        /// Adds the given items at the end of the slice.
        ///
        /// This only allocates memory when there is not enough capacity.
        pub fn appendMany(
            slc: *Self,
            allocator: Allocator,
            elems: []const T,
        ) Allocator.Error!void {
            const new_len: usize = slc.len + elems.len;
            try slc.ensureCapacity(allocator, new_len);
            slc.len += copy(T, slc.ptr[slc.len..slc.cap], elems);
        }

        /// Adds the items from all the given slices and the end of the slice.
        ///
        /// This only allocates memory when there is not enough capacity.
        pub fn appendSlices(
            slc: *Self,
            allocator: Allocator,
            slcs: []const []const T,
        ) Allocator.Error!void {
            var new_len: usize = slc.len;
            for (slcs) |s| new_len += s.len;
            try slc.ensureCapacity(allocator, new_len);
            for (slcs) |s| slc.len += copy(T, slc.ptr[slc.len..slc.cap], s);
        }

        /// Available slots to be used without memory allocations.
        pub fn available(slc: Self) usize {
            return slc.cap - slc.len;
        }

        /// Sets the slice as empty.
        ///
        /// This doesn't deallocate memory, use `.deinit` instead.
        pub fn clear(slc: *Self) void {
            slc.len = 0;
        }

        /// Creates a copy of the slice using the given allocator.
        pub fn clone(slc: Self, allocator: Allocator) Allocator.Error!Self {
            const ptr: [*]T = if (slc.cap > 0)
                (try allocator.dupe(T, slc.ptr[0..slc.cap])).ptr
            else
                undefined;

            return .{
                .ptr = ptr,
                .cap = slc.cap,
                .len = slc.len,
            };
        }

        /// Checks if the slice is capable of storing `size` elements.
        ///
        /// This only allocates memory if the given size is greater than the
        /// slice capacity. If the slice has a capacity greater than 0, the
        /// allocated size will be the maximum between `size` and the double of
        /// the slice capacity.
        pub fn ensureCapacity(
            slc: *Self,
            allocator: Allocator,
            size: usize,
        ) Allocator.Error!void {
            if (size <= slc.cap) return;
            const new_size = @max(slc.cap * 2, size);
            try slc.setCapacity(allocator, new_size);
        }

        /// Returns the items in the slice.
        pub fn items(slc: Self) []T {
            return slc.ptr[0..slc.len];
        }

        /// Converts the slice to a managed one that uses the given allocator.
        pub fn managed(
            slc: Self,
            allocator: Allocator,
        ) SliceManaged(T) {
            return .{
                .ally = allocator,
                .slc = slc,
            };
        }

        /// Sets the number of items in the slice to the given size.
        ///
        /// This doesn't reduce the capacity. If `size` is greater than the
        /// capacity, memory will be allocated. If `size` is lower than the
        /// capacity, extra slots will be set as `undefined`.
        pub fn resize(
            slc: *Self,
            allocator: Allocator,
            size: usize,
        ) Allocator.Error!void {
            try slc.ensureCapacity(allocator, size);

            if (size > slc.len) {
                for (slc.len..size) |i| slc.ptr[i] = undefined;
            }

            slc.len = size;
        }

        /// Sets the slice capacity to the given size.
        pub fn setCapacity(
            slc: *Self,
            allocator: Allocator,
            size: usize,
        ) Allocator.Error!void {
            if (size == 0) return slc.deinit(allocator);

            if (slc.cap > 0 and allocator.resize(slc.ptr[0..slc.cap], size)) {
                slc.cap = size;
                if (slc.len > size) slc.len = size;
                return;
            }

            var new_ptr = try allocator.alloc(T, size);
            if (slc.len > 0) _ = copy(T, new_ptr[0..], slc.ptr[0..slc.len]);
            if (slc.cap > 0) allocator.free(slc.ptr[0..slc.cap]);

            slc.ptr = new_ptr.ptr;
            slc.cap = size;
            if (slc.len > size) slc.len = size;
        }
    };
}

/// Fixed capacity slice.
pub fn SliceFixed(comptime T: type) type {
    return struct {
        const Self = @This();
        pub const Error = error{OutOfMemory};

        data: []T = undefined,
        len: usize = 0,

        /// Creates a self growable copy of the slice.
        pub fn alloc(slc: Self, allocator: Allocator) Allocator.Error!Slice(T) {
            return .{
                .ptr = (try allocator.dupe(T, slc.ptr[0..slc.cap()])).ptr,
                .cap = slc.cap(),
                .len = slc.len,
            };
        }

        /// Creates a self growable copy of the slice.
        pub fn allocManaged(
            slc: Self,
            allocator: Allocator,
        ) Allocator.Error!SliceManaged(T) {
            const new_slc = try slc.alloc(allocator);
            return new_slc.managed(allocator);
        }

        /// Adds the given item at the end of the slice.
        pub fn append(slc: *Self, elem: T) Error!void {
            try slc.ensureCapacity(slc.len + 1);
            slc.data[slc.len] = elem;
            slc.len += 1;
        }

        /// Adds the given item at the end of the slice and returns its
        /// pointer.
        pub fn appendAndReturn(slc: *Self, elem: T) Error!*T {
            try slc.append(elem);
            return &slc.data[slc.len - 1];
        }

        /// Adds the given items at the end of the slice.
        pub fn appendMany(slc: *Self, elems: []const T) Error!void {
            const new_len: usize = slc.len + elems.len;
            try slc.ensureCapacity(new_len);
            slc.len += copy(T, slc.data[slc.len..], elems);
        }

        /// Adds the items from all the given slices and the end of the slice.
        pub fn appendSlices(slc: *Self, slcs: []const []const T) Error!void {
            var new_len: usize = slc.len;
            for (slcs) |s| new_len += s.len;
            try slc.ensureCapacity(new_len);
            for (slcs) |s| slc.len += copy(T, slc.data[slc.len..], s);
        }

        /// Available slots to be used.
        pub fn available(slc: Self) usize {
            return slc.data.len - slc.len;
        }

        /// Returns number of items the slice may contain.
        pub fn cap(slc: Self) usize {
            return slc.data.len;
        }

        /// Sets the slice as empty.
        pub fn clear(slc: *Self) void {
            slc.len = 0;
        }

        /// Checks if the slice is capable of storing `size` elements.
        pub fn ensureCapacity(slc: *Self, size: usize) Error!void {
            if (size > slc.data.len) return error.OutOfMemory;
        }

        /// Returns the items in the slice.
        pub fn items(slc: Self) []T {
            return slc.data[0..slc.len];
        }
    };
}

/// Self growable slice.
///
/// Allocated memory is owned by the slice.
pub fn SliceManaged(comptime T: type) type {
    return struct {
        const Self = @This();

        ally: Allocator,
        slc: Slice(T),

        pub fn deinit(slc: *Self) void {
            slc.slc.deinit(slc.ally);
        }

        /// Adds the given item at the end of the slice.
        ///
        /// This only allocates memory when there is not enough capacity.
        pub fn append(slc: *Self, elem: T) Allocator.Error!void {
            return slc.slc.append(slc.ally, elem);
        }

        /// Adds the given item at the end of the slice and returns its
        /// pointer.
        ///
        /// This only allocates memory when there is not enough capacity.
        pub fn appendAndReturn(slc: *Self, elem: T) Allocator.Error!*T {
            return slc.slc.appendAndReturn(slc.ally, elem);
        }

        /// Adds the given items at the end of the slice.
        ///
        /// This only allocates memory when there is not enough capacity.
        pub fn appendMany(slc: *Self, elems: []const T) Allocator.Error!void {
            return slc.slc.appendMany(slc.ally, elems);
        }

        /// Adds the items from all the given slices and the end of the slice.
        ///
        /// This only allocates memory when there is not enough capacity.
        pub fn appendSlices(
            slc: *Self,
            slcs: []const []const T,
        ) Allocator.Error!void {
            return slc.slc.appendSlices(slc.ally, slcs);
        }

        /// Available slots to be used without memory allocations.
        pub fn available(slc: Self) usize {
            return slc.slc.available();
        }

        /// Returns number of items the slice may contain without memory
        /// allocations.
        pub fn cap(slc: Self) usize {
            return slc.slc.cap;
        }

        /// Sets the slice as empty.
        ///
        /// This doesn't deallocate memory, use `.deinit` instead.
        pub fn clear(slc: *Self) void {
            slc.slc.clear();
        }

        /// Creates a copy of the slice using the given allocator.
        pub fn clone(
            slc: Self,
            allocator: Allocator,
        ) Allocator.Error!SliceManaged(@TypeOf(allocator), T) {
            return .{
                .ally = allocator,
                .slc = try slc.slc.clone(allocator),
            };
        }

        /// Checks if the slice is capable of storing `size` elements.
        ///
        /// This only allocates memory if the given size is greater than the
        /// slice capacity. If the slice has a capacity greater than 0, the
        /// allocated size will be the maximum between `size` and the double of
        /// the slice capacity.
        pub fn ensureCapacity(slc: *Self, size: usize) Allocator.Error!void {
            return slc.slc.ensureCapacity(slc.ally, size);
        }

        /// Returns the items in the slice.
        pub fn items(slc: Self) []T {
            return slc.slc.items();
        }

        /// Returns the number of items in the slice.
        pub fn len(slc: Self) usize {
            return slc.slc.len;
        }

        /// Sets the number of items in the slice to the given size.
        ///
        /// This doesn't reduce the capacity. If `size` is greater than the
        /// capacity, memory will be allocated. If `size` is lower than the
        /// capacity, extra slots will be set as `undefined`.
        pub fn resize(slc: *Self, size: usize) Allocator.Error!void {
            try slc.slc.resize(slc.ally, size);
        }

        /// Sets the slice capacity to the given size.
        pub fn setCapacity(slc: *Self, size: usize) Allocator.Error!void {
            return slc.slc.setCapacity(slc.ally, size);
        }
    };
}

// /////////////////
// Split iterator //
// /////////////////

/// An `iterators.Iterator` implementation for spliting slices.
pub fn SplitIterator(comptime T: type) type {
    return struct {
        const Self = @This();

        data: []const T,
        sep: T,
        done: bool = false,

        fn nextIndex(it: *Self, index: usize) usize {
            return if (findAt(T, index, it.data, it.sep)) |i|
                i + 1
            else
                it.data.len;
        }

        fn getItem(it: *Self, index: usize) ?[]const T {
            if (index >= it.data.len) {
                if (it.done) return null;

                if (it.data.len == 0 or endsWith(T, it.data, &.{it.sep})) {
                    it.done = true;
                    return &.{};
                }

                return null;
            }

            const j = findAt(T, index, it.data, it.sep) orelse it.data.len;
            return it.data[index..j];
        }

        pub const Iterator = iterators.Iterator(
            Self,
            usize,
            []const T,
            null,
            nextIndex,
            getItem,
        );

        pub fn iterator(it: Self) Self.Iterator {
            return .{ .ctx = it, .index = 0 };
        }
    };
}
