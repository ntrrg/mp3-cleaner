// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.types.funcs`
//!
//! Utilities for working with funcions and methods.

/// Returns the infered error set from the return type of the given function.
pub fn ErrorSet(comptime func: anytype) type {
    const T = Return(func);
    const ti = @typeInfo(T);
    if (ti != .error_union) @compileError("function has no error set");

    return ti.error_union.error_set;
}

/// Returns the return type of the given function.
pub fn Return(comptime func: anytype) type {
    const T = @TypeOf(func);
    const ti = @typeInfo(T);

    if (ti == .pointer and ti.pointer.size == .one)
        return Return(ti.pointer.child);

    if (ti != .@"fn") @compileError("argument is not a function");

    return ti.@"fn".return_type orelse void;
}

/// Returns true if `T` has a `name` public method. If `T` is a pointer `*T`,
/// its child type will be used.
pub fn hasFn(comptime T: type, comptime name: [:0]const u8) bool {
    const ti = @typeInfo(T);

    if (ti == .pointer and ti.pointer.size == .one)
        return hasFn(ti.pointer.child, name);

    switch (ti) {
        .@"struct", .@"union", .@"enum", .@"opaque" => {},
        else => return false,
    }

    if (!@hasDecl(T, name))
        return false;

    return @typeInfo(@TypeOf(@field(T, name))) == .@"fn";
}
