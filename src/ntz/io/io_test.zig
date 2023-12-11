// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const ntz = @import("ntz");
const testing = ntz.testing;

test "ntz.io" {
    testing.refAllDecls(ntz.io);

    //_ = @import("Writer_test.zig");
    _ = @import("buffered_writer_test.zig");
    _ = @import("counting_writer_test.zig");
    _ = @import("delimited_writer_test.zig");
    _ = @import("limited_writer_test.zig");
    _ = @import("replace_writer_test.zig");
}
