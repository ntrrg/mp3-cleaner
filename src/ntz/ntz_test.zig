// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const ntz = @import("ntz");

test "ntz" {
    ntz.testing.refAllDecls(ntz);

    _ = @import("encoding/encoding_test.zig");
    _ = @import("io/io_test.zig");
    _ = @import("logging/logging_test.zig");
    //_ = @import("math/math_test.zig");
    //_ = @import("mem/mem_test.zig");
    //_ = @import("testing/testing_test.zig");
    _ = @import("types/types_test.zig");
    //_ = @import("units/units_test.zig");
}
