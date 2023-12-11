// Copyright 2024 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.encoding.unicode`
//!
//! Unicode text encoding.

pub const utf8 = @import("utf8.zig");

pub const replacement_cp = Codepoint.must(0xFFFD);

pub const Codepoint = struct {
    const Self = @This();

    pub const Error = error{
        SurrogateCharacter,
    };

    val: u21,

    /// Creates a Unicode codepoint from the given number.
    pub fn init(val: u21) Error!Self {
        const cp = Self{ .val = val };
        try cp.validate();
        return cp;
    }

    /// Like `.init`, but panics if the given value is invalid.
    pub fn must(val: u21) Self {
        return Self.init(val) catch unreachable;
    }

    // /////////////
    // Validation //
    // /////////////

    /// Checks if the codepoint data is valid.
    pub fn validate(cp: Self) Error!void {
        try Self.validateCodepoint(cp.val);
    }

    /// Validates if the given value is valid to be used as a codepoint.
    pub fn validateCodepoint(val: u21) Error!void {
        if (val >= 0xD800 and val <= 0xDFFF)
            return Error.SurrogateCharacter;
    }
};
