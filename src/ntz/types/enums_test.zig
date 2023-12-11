// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const ntz = @import("ntz");
const testing = ntz.testing;

const enums = ntz.types.enums;

test "ntz.types.enums" {
    testing.refAllDecls(enums);
}

test "ntz.types.enums.min" {
    try testing.expectEql(enums.min(Abc), .a);
    try testing.expectEql(enums.min(Single), .a);
}

test "ntz.types.enums.at" {
    try testing.expectEql(enums.at(Abc, 3), .d);
    try testing.expectEql(enums.at(Single, 0), .a);
}

test "ntz.types.enums.max" {
    try testing.expectEql(enums.max(Abc), .f);
    try testing.expectEql(enums.max(Single), .a);
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
