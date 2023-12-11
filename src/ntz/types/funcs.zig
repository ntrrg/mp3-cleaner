// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.types.funcs`
//!
//! Utilities for working with funcions and methods.

/// Returns true if `T` has a `name` public method. `T` may be pointer `*T`, in
/// which case, its child type will be used.
pub fn hasFn(comptime T: type, comptime name: []const u8) bool {
    const t_ti = @typeInfo(T);

    if (t_ti == .Pointer and t_ti.Pointer.size == .One)
        return hasFn(t_ti.Pointer.child, name);

    switch (t_ti) {
        .Struct, .Union, .Enum, .Opaque => {},
        else => return false,
    }

    if (!@hasDecl(T, name))
        return false;

    return @typeInfo(@TypeOf(@field(T, name))) == .Fn;
}
