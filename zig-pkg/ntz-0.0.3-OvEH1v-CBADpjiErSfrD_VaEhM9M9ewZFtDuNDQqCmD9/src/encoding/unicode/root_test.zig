// Copyright 2024 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");
const testing = std.testing;

const ntz = @import("ntz");
const unicode = ntz.encoding.unicode;

test "ntz.encoding.unicode" {
    _ = @import("utf8_test.zig");
}

// ////////////
// Codepoint //
// ////////////

test "ntz.encoding.unicode.Codepoint.init" {
    _ = try unicode.Codepoint.init(0);

    try testing.expectError(
        unicode.Codepoint.InitError.OutOfBounds,
        unicode.Codepoint.init(0x110000),
    );

    _ = try unicode.Codepoint.init(0x10FFFF);

    // Surrogate charaters.

    _ = try unicode.Codepoint.init(0xD7FF);

    try testing.expectError(
        unicode.Codepoint.InitError.SurrogateCharacter,
        unicode.Codepoint.init(0xD800),
    );

    try testing.expectError(
        unicode.Codepoint.InitError.SurrogateCharacter,
        unicode.Codepoint.init(0xDB88),
    );

    try testing.expectError(
        unicode.Codepoint.InitError.SurrogateCharacter,
        unicode.Codepoint.init(0xDFFF),
    );

    _ = try unicode.Codepoint.init(0xE000);
}
