// Copyright 2024 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.encoding.unicode`
//!
//! Unicode text encoding.

pub const utf8 = @import("utf8.zig");

pub const replacement_cp = Codepoint{ .value = 0xFFFD };

pub const Codepoint = struct {
    const Self = @This();

    pub const Error = InitError || ValidationError;

    value: u21,

    pub const InitError = ValidationError;

    pub fn init(value: u21) InitError!Self {
        const cp = Self{ .value = value };
        try cp.validate();
        return cp;
    }

    // /////////////
    // Validation //
    // /////////////

    pub const ValidationError = ValidateError;

    pub const ValidateError = error{
        OutOfBounds,
        SurrogateCharacter,
    };

    pub fn validate(cp: Self) ValidateError!void {
        if (!isCodepoint(cp.value)) return error.OutOfBounds;
        if (isSurrogateCharacter(cp.value)) return error.SurrogateCharacter;
    }
};

pub fn isCodepoint(value: anytype) bool {
    if (value >= 0 and value <= 0x10FFFF) return true;
    return false;
}

pub fn isSurrogateCharacter(value: anytype) bool {
    if (value >= 0xD800 and value <= 0xDFFF) return true;
    return false;
}
