const std = @import("std");
const testing = std.testing;

const Writer = @import("Writer.zig");

test "ntz.io.Writer" {
    const ally = testing.allocator;

    var buf = std.ArrayList(u8).init(ally);
    defer buf.deinit();

    var bw = buf.writer();
    const w = Writer.init(&bw);

    const in = "hello, world";
    _ = try w.write(in);
    try testing.expectEqualStrings(in, buf.items);
}
