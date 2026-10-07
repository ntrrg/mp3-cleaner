// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");
const testing = std.testing;

const ntz = @import("ntz");
const errors = ntz.types.errors;

test "ntz.types.errors" {}

const Point = struct {
    pub const Error = error{SomeError};

    x: usize,
    y: usize,
};

test "ntz.types.errors.From" {
    const p: Point = .{ .x = 10, .y = 11 };

    const Error = errors.From(@TypeOf(p));
    try testing.expectEqual(Point.Error, Error);

    const ErrorFromPointer = errors.From(@TypeOf(&p));
    try testing.expectEqual(Point.Error, ErrorFromPointer);
}

test "ntz.types.errors.FromDecl" {
    const p: Point = .{ .x = 10, .y = 11 };

    const Error = errors.FromDecl(@TypeOf(p), "Error");
    try testing.expectEqual(Point.Error, Error);

    const ErrorFromPointer = errors.FromDecl(@TypeOf(&p), "Error");
    try testing.expectEqual(Point.Error, ErrorFromPointer);
}

test "ntz.types.errors.of" {
    const Error = error{SomeError};
    try testing.expect(errors.of(Error, error.SomeError));
    try testing.expect(!errors.of(Error, error.SomeOtherError));
    try testing.expect(errors.of(anyerror, error.SomeOtherError));
}
