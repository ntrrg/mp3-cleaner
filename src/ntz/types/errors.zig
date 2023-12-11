// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.types.errors`
//!
//! Utilities for working with errors.

/// Gets internal error set `Error` from the given type.
pub fn From(comptime T: type) type {
    return FromDecl(T, "Error");
}

/// Gets specific internal error set from given type. `T` may be pointer `*T`,
/// in which case, its child type will be used.
pub fn FromDecl(comptime T: type, comptime decl: [:0]const u8) type {
    const t_ti = @typeInfo(T);

    if (t_ti == .pointer and t_ti.pointer.size == .One)
        return FromDecl(t_ti.pointer.child, decl);

    const set = @field(T, decl);
    const set_ti = @typeInfo(set);

    if (set_ti != .error_set)
        @compileError("'" ++ decl ++ "'" ++ " is not an error set, it is '" ++ @typeName(@Type(set_ti)) ++ "'");

    return set;
}
