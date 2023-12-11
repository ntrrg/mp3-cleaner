// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.types.enums`
//!
//! Utilities for working with enums.

/// Returns the enum member at the given index.
pub fn at(comptime T: type, comptime i: usize) T {
    const fields = @typeInfo(T).@"enum".fields;
    return @enumFromInt(fields[i].value);
}

/// Returns the bigger enum member.
pub fn max(comptime T: type) T {
    const fields = @typeInfo(T).@"enum".fields;
    return @enumFromInt(fields[fields.len - 1].value);
}

/// Returns the smaller enum member.
pub fn min(comptime T: type) T {
    return at(T, 0);
}
