// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const ntz = @import("ntz");
const testing = ntz.testing;

const types = ntz.types;

test "ntz.types" {
    testing.refAllDecls(types);

    _ = @import("bytes_test.zig");
    _ = @import("enums_test.zig");
    _ = @import("errors_test.zig");
    _ = @import("funcs_test.zig");
    _ = @import("slices_test.zig");
    _ = @import("strings_test.zig");
    //_ = @import("structs_test.zig");
}
