// Copyright 2024 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const ntz = @import("ntz");
const testing = ntz.testing;

const encoding = ntz.encoding;

test "ntz.encoding" {
    testing.refAllDecls(encoding);

    //_ = @import("ctxlog/ctxlog_test.zig");
    _ = @import("unicode/unicode_test.zig");
}
