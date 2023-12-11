// Copyright 2024 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const ntz = @import("ntz");
const testing = ntz.testing;

const unicode = ntz.encoding.unicode;

test "ntz.encoding.unicode" {
    testing.refAllDecls(unicode);

    _ = @import("utf8_test.zig");
}

// ////////////
// Codepoint //
// ////////////

test "ntz.encoding.unicode.Codepoint.init" {
    _ = try unicode.Codepoint.init(0);

    try testing.expectErr(
        unicode.Codepoint.init(0x110000),
        unicode.Codepoint.InitError.OutOfRange,
    );

    _ = try unicode.Codepoint.init(0x10FFFF);

    // Surrogate charaters.

    _ = try unicode.Codepoint.init(0xD7FF);

    try testing.expectErr(
        unicode.Codepoint.init(0xD800),
        unicode.Codepoint.InitError.SurrogateCharacter,
    );

    try testing.expectErr(
        unicode.Codepoint.init(0xDB88),
        unicode.Codepoint.InitError.SurrogateCharacter,
    );

    try testing.expectErr(
        unicode.Codepoint.init(0xDFFF),
        unicode.Codepoint.InitError.SurrogateCharacter,
    );

    _ = try unicode.Codepoint.init(0xE000);
}
