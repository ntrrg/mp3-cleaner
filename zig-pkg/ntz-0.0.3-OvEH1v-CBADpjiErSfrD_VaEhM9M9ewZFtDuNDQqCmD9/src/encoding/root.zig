// Copyright 2024 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.encoding`
//!
//! Multiple encoding and decoding formats.

pub const ctxlog = @import("ctxlog/root.zig");
pub const unicode = @import("unicode/root.zig");

//pub const Value = union(enum) {
//    const Self = @This();
//
//    pub const Bool = struct {
//        parent: ?*Self = null,
//        data: []const u8 = "",
//        name: []const u8 = "",
//        value: bool,
//    };
//
//    pub const Enum = struct {
//        pub const Mode = enum(u1) {
//            value,
//            tag,
//        };
//
//        pub const Tag = struct {
//            name: []const u8,
//            value: isize,
//        };
//
//        parent: ?*Self = null,
//        data: []const u8 = "",
//        name: []const u8 = "",
//        mode: Mode,
//        tags: []const Tag,
//    };
//
//    pub const Float = struct {
//        pub const Mode = enum(u1) {
//            decimal,
//            scientific,
//        };
//
//        mode: Mode,
//        size: u16,
//        precision: usize,
//    };
//
//    pub const Int = struct {
//        is_signed: bool,
//        size: u16,
//        base: u8,
//    };
//
//    pub const Optional = struct {
//        type: ?*Self,
//    };
//
//    bool: Bool,
//    int: Int,
//    float: Float,
//    string,
//    bytes,
//    @"enum": Enum,
//    optional: Optional,
//
//    pub fn from(value: anytype) Self {
//        const T = @TypeOf(value);
//        const ti = @typeInfo(T);
//
//        switch (ti) {
//            .bool => return .{ .bool = .{ .value = value } },
//            else => unreachable,
//        }
//    }
//};
