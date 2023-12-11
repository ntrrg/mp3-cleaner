// Copyright 2024 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const ntz = @import("ntz");
const testing = ntz.testing;

const unicode = ntz.encoding.unicode;

test "ntz.encoding.unicode" {
    testing.refAllDecls(unicode);

    _ = @import("utf8_test.zig");
}
