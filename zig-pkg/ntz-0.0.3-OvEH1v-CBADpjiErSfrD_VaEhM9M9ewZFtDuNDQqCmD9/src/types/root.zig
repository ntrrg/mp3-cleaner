// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.types`
//!
//! Utilities for working with data types.

const std = @import("std");

pub const bytes = @import("bytes.zig");
pub const enums = @import("enums.zig");
pub const errors = @import("errors.zig");
pub const funcs = @import("funcs.zig");
pub const iterators = @import("iterators.zig");
pub const slices = @import("slices.zig");
//pub const strings = @import("strings.zig");
pub const structs = @import("structs.zig");

/// Returns the child type of the given type.
///
/// Single pointer to array returns the array child type.
pub fn Child(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .pointer => |ti| switch (ti.size) {
            .one => switch (@typeInfo(ti.child)) {
                .array => |child_ti| return child_ti.child,
                else => ti.child,
            },

            else => ti.child,
        },

        .array => |ti| ti.child,
        .vector => |ti| ti.child,
        .optional => |ti| ti.child,
        else => @compileError(@typeName(T) ++ " has no child type"),
    };
}

/// Returns the type of the given field.
///
/// `fp` may be a field name or a field path. A field path is a list of fields
/// separated by periods (`.`). All elements in the field path must be structs
/// or unions, except for the last one.
pub fn Field(comptime T: type, comptime fp: []const u8) type {
    var field_T = T;
    var field_name, var rest = bytes.split(fp, '.');

    loop: while (true) {
        const _fields = fields(field_T);

        for (_fields.names, _fields.types) |f_name, f_type| {
            if (!bytes.equal(f_name, field_name)) continue;
            field_T = f_type;
            if (rest.len == 0) break :loop;
            field_name, rest = bytes.split(rest, '.');
            break;
        } else {
            @compileError("no field '" ++ field_name ++ "' on type " ++ @typeName(field_T));
        }
    }

    return field_T;
}

pub const Fields = struct {
    names: []const []const u8,
    types: []const type,
};

/// Returns the type of fields `T` contains. If `T` is a single pointer to a
/// struct or a union, this will use its child type.
//pub fn Fields(comptime T: type) type {
//    return sw: switch (@typeInfo(T)) {
//        .@"struct" => std.builtin.Type.StructField,
//        .@"union" => std.builtin.Type.UnionField,
//
//        .pointer => |ti| switch (ti.size) {
//            .one => continue :sw @typeInfo(ti.child),
//            else => @compileError(@typeName(T) ++ " doesn't have fields"),
//        },
//
//        .optional => |ti| continue :sw @typeInfo(ti.child),
//        else => @compileError(@typeName(T) ++ " doesn't have fields"),
//    };
//}

/// Returns the value of a field in `val`.
///
/// This is equivalent to `x.a` or `x.a.b`, but it can be done
/// programmatically.
///
/// `fp` may be a field name or a field path. A field path is a list of fields
/// separated by periods (`.`). All elements in the field path must be structs
/// or unions, except for the last one.
pub fn field(value: anytype, comptime fp: []const u8) Field(@TypeOf(value), fp) {
    const T = @TypeOf(value);
    const ti = @typeInfo(T);

    if (ti == .optional and @typeInfo(ti.optional.child) == .@"struct")
        return field(value orelse structs.init(ti.optional.child), fp);

    const field_name, const rest = comptime bytes.split(fp, '.');
    const field_val = @field(value, field_name);
    if (rest.len == 0) return field_val;
    return field(field_val, rest);
}

/// Returns the list of fields on `T`.
///
/// If `T` is a single pointer to a struct or a union, this will use its child
/// type.
pub fn fields(comptime T: type) Fields {
    if (!has_fields(T)) @compileError(@typeName(T) ++ " doesn't have fields");

    return sw: switch (@typeInfo(T)) {
        .@"struct" => |ti| .{ .names = ti.field_names, .types = ti.field_types },
        .@"union" => |ti| .{ .names = ti.field_names, .types = ti.field_types },

        .pointer => |ti| switch (ti.size) {
            .one => continue :sw @typeInfo(ti.child),
            else => unreachable,
        },

        .optional => |ti| continue :sw @typeInfo(ti.child),
        else => unreachable,
    };
}

/// Checks if `T` has fields.
///
/// If `T` is a single pointer to a struct or a union, this will use its child
/// type.
pub fn has_fields(comptime T: type) bool {
    return sw: switch (@typeInfo(T)) {
        .@"struct" => true,
        .@"union" => true,

        .pointer => |ti| switch (ti.size) {
            .one => continue :sw @typeInfo(ti.child),
            else => false,
        },

        .optional => |ti| continue :sw @typeInfo(ti.child),
        else => false,
    };
}

/// Sets the value of a field in `orig` to `val`.
///
/// This is equivalent to `x.a = val` or `x.a.b = val`, but it can be done
/// programmatically.
///
/// `fp` may be a field name or a field path. A field path is a list of fields
/// separated by periods (`.`). All elements in the field path must be structs
/// or unions, except for the last one.
pub fn setField(
    orig: anytype,
    comptime fp: []const u8,
    value: Field(@TypeOf(orig), fp),
) void {
    const T = @TypeOf(orig);
    const ti = @typeInfo(T);

    if (ti != .pointer)
        @compileError(@typeName(T) ++ " is not a pointer to a struct or a union");

    const child_ti = @typeInfo(ti.pointer.child);

    if (child_ti == .optional and @typeInfo(child_ti.optional.child) == .@"struct") {
        var _orig = orig.* orelse structs.init(child_ti.optional.child);
        setField(&_orig, fp, value);
        orig.* = _orig;
        return;
    }

    const field_name, const rest = comptime bytes.split(fp, '.');

    if (rest.len == 0) {
        @field(orig, field_name) = value;
        return;
    }

    return setField(&@field(orig, field_name), rest, value);
}
