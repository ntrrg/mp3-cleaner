// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");
const testing = std.testing;

const ntz = @import("ntz");
const enums = ntz.types.enums;

test "ntz.types.enums" {}

test "ntz.types.enums.min" {
    try testing.expectEqual(Abc.a, enums.min(Abc));
    try testing.expectEqual(Single.a, enums.min(Single));
}

test "ntz.types.enums.at" {
    try testing.expectEqual(Abc.d, enums.at(Abc, 3));
    try testing.expectEqual(Single.a, enums.at(Single, 0));
}

test "ntz.types.enums.max" {
    try testing.expectEqual(Abc.f, enums.max(Abc));
    try testing.expectEqual(Single.a, enums.max(Single));
}

const Abc = enum {
    a,
    b,
    c,
    d,
    e,
    f,
};

const Single = enum {
    a,
};
