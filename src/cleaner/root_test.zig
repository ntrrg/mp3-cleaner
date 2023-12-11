const std = @import("std");
const testing = std.testing;

const cleaner = @import("root.zig");

test "humanizeBytes" {
    var got: cleaner.HumanizedResult = undefined;

    // 0 B.
    got = cleaner.humanizeBytes(0);

    try testing.expectEqualDeep(
        cleaner.HumanizedResult{ .value = 0, .prefix = .B },
        got,
    );

    // 42 B.
    got = cleaner.humanizeBytes(42);

    try testing.expectEqualDeep(
        cleaner.HumanizedResult{ .value = 42, .prefix = .B },
        got,
    );

    // 1023 B.
    got = cleaner.humanizeBytes(1023);

    try testing.expectEqualDeep(
        cleaner.HumanizedResult{ .value = 1023, .prefix = .B },
        got,
    );

    // 1 KiB.
    got = cleaner.humanizeBytes(1024);

    try testing.expectEqualDeep(
        cleaner.HumanizedResult{ .value = 1, .prefix = .KiB },
        got,
    );

    // 42 KiB.
    got = cleaner.humanizeBytes(42 * 1024);

    try testing.expectEqualDeep(
        cleaner.HumanizedResult{ .value = 42, .prefix = .KiB },
        got,
    );

    // 120.56 KiB.
    got = cleaner.humanizeBytes(123456);

    try testing.expectEqualDeep(
        cleaner.HumanizedResult{ .value = 120.5625, .prefix = .KiB },
        got,
    );

    // 1023 KiB.
    got = cleaner.humanizeBytes(1023 * 1024);

    try testing.expectEqualDeep(
        cleaner.HumanizedResult{ .value = 1023, .prefix = .KiB },
        got,
    );

    // 1 MiB.
    got = cleaner.humanizeBytes(1024 * 1024);

    try testing.expectEqualDeep(
        cleaner.HumanizedResult{ .value = 1, .prefix = .MiB },
        got,
    );
}
