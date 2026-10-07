// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");
const testing = std.testing;

const ntz = @import("ntz");
const logging = ntz.logging;

test "ntz.logging" {
    _ = @import("logger_test.zig");
}

test "ntz.logging.Level.key" {
    try testing.expectEqualStrings("DEBUG", logging.Level.debug.key());
    try testing.expectEqualStrings("INFO", logging.Level.info.key());
    try testing.expectEqualStrings("WARN", logging.Level.warn.key());
    try testing.expectEqualStrings("ERROR", logging.Level.@"error".key());
    try testing.expectEqualStrings("FATAL", logging.Level.fatal.key());
}

test "ntz.logging.Level.fromKey" {
    try testing.expectEqual(
        logging.Level.debug,
        try logging.Level.fromKey("DEBUG"),
    );

    try testing.expectEqual(
        logging.Level.debug,
        try logging.Level.fromKey("debug"),
    );

    try testing.expectEqual(
        logging.Level.info,
        try logging.Level.fromKey("INFO"),
    );

    try testing.expectEqual(
        logging.Level.info,
        try logging.Level.fromKey("info"),
    );

    try testing.expectEqual(
        logging.Level.warn,
        try logging.Level.fromKey("WARN"),
    );

    try testing.expectEqual(
        logging.Level.warn,
        try logging.Level.fromKey("warn"),
    );

    try testing.expectEqual(
        logging.Level.@"error",
        try logging.Level.fromKey("ERROR"),
    );

    try testing.expectEqual(
        logging.Level.@"error",
        try logging.Level.fromKey("error"),
    );

    try testing.expectEqual(
        logging.Level.fatal,
        try logging.Level.fromKey("FATAL"),
    );

    try testing.expectEqual(
        logging.Level.fatal,
        try logging.Level.fromKey("fatal"),
    );

    try testing.expectEqual(
        logging.Level.disabled,
        try logging.Level.fromKey("DISABLED"),
    );

    try testing.expectEqual(
        logging.Level.disabled,
        try logging.Level.fromKey("disabled"),
    );

    try testing.expectError(
        logging.Level.FromKeyError.InvalidSeverity,
        logging.Level.fromKey("DDEBUG"),
    );
}
