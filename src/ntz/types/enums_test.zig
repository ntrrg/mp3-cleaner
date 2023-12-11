// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const ntz = @import("ntz");
const testing = ntz.testing;

const enums = ntz.types.enums;

test "ntz.types.enums" {
    testing.refAllDecls(enums);
}

test "ntz.types.enums.min" {
    try testing.expectEql(enums.min(Abc), .A);
    try testing.expectEql(enums.min(Single), .A);
}

test "ntz.types.enums.at" {
    try testing.expectEql(enums.at(Abc, 3), .D);
    try testing.expectEql(enums.at(Single, 0), .A);
}

test "ntz.types.enums.max" {
    try testing.expectEql(enums.max(Abc), .F);
    try testing.expectEql(enums.max(Single), .A);
}

const Abc = enum {
    A,
    B,
    C,
    D,
    E,
    F,
};

const Single = enum {
    A,
};
