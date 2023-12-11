// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.types.errors`
//!
//! Utilities for working with errors.

/// Gets internal error set from given type. `T` may be pointer `*T`, in which
/// case, its child type will be used.
///
/// If no `Error` declaration is found, `anyerror` will be returned.
pub fn From(comptime T: type) type {
    return FromDecl(T, "Error");
}

/// Gets specific internal error set from given type. `T` may be pointer `*T`,
/// in which case, its child type will be used.
///
/// If no `decl` is found, `anyerror` will be returned.
pub fn FromDecl(comptime T: type, comptime decl: []const u8) type {
    const t_ti = @typeInfo(T);

    if (t_ti == .Pointer and t_ti.Pointer.size == .One)
        return FromDecl(t_ti.Pointer.child, decl);

    if (@hasDecl(T, decl)) return @field(T, decl);
    return anyerror;
}
