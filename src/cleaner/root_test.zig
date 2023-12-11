const std = @import("std");
const testing = std.testing;

const cleaner = @import("root.zig");

test "humanizeBytes" {
    var got: cleaner.HumanizeResult = undefined;

    // 0 B.
    got = cleaner.humanizeBytes(0);
    try testing.expectEqualDeep(got, .{ .value = 0, .prefix = .B });

    // 42 B.
    got = cleaner.humanizeBytes(42);
    try testing.expectEqualDeep(got, .{ .value = 42, .prefix = .B });

    // 1023 B.
    got = cleaner.humanizeBytes(1023);
    try testing.expectEqualDeep(got, .{ .value = 1023, .prefix = .B });

    // 1 KiB.
    got = cleaner.humanizeBytes(1024);
    try testing.expectEqualDeep(got, .{ .value = 1, .prefix = .KiB });

    // 42 KiB.
    got = cleaner.humanizeBytes(42 * 1024);
    try testing.expectEqualDeep(got, .{ .value = 42, .prefix = .KiB });

    // 120.56 KiB.
    got = cleaner.humanizeBytes(123456);
    try testing.expectEqualDeep(got, .{ .value = 120.5625, .prefix = .KiB });

    // 1023 KiB.
    got = cleaner.humanizeBytes(1023 * 1024);
    try testing.expectEqualDeep(got, .{ .value = 1023, .prefix = .KiB });

    // 1 MiB.
    got = cleaner.humanizeBytes(1024 * 1024);
    try testing.expectEqualDeep(got, .{ .value = 1, .prefix = .MiB });
}
