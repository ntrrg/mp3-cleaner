// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const ntz = @import("ntz");
const testing = ntz.testing;

const errors = ntz.types.errors;

test "ntz.types.errors" {
    testing.refAllDecls(errors);
}

test "ntz.types.errors.From" {
    const Point = struct {
        pub const Error = error{SomeError};

        x: usize,
        y: usize,
    };

    const p: Point = .{ .x = 10, .y = 11 };

    const Error = errors.From(@TypeOf(p));
    try testing.expectEql(Error, Point.Error);

    const ErrorFromPointer = errors.From(@TypeOf(&p));
    try testing.expectEql(ErrorFromPointer, Point.Error);
}

test "ntz.types.errors.FromDecl" {
    const Point = struct {
        pub const Error = error{SomeError};

        x: usize,
        y: usize,
    };

    const p: Point = .{ .x = 10, .y = 11 };

    const Error = errors.FromDecl(@TypeOf(p), "Error");
    try testing.expectEql(Error, Point.Error);

    const ErrorFromPointer = errors.FromDecl(@TypeOf(&p), "Error");
    try testing.expectEql(ErrorFromPointer, Point.Error);
}
