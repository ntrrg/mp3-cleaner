// Copyright 2026 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");

const types = @import("../../types/root.zig");
const bytes = types.bytes;

const cli = @import("root.zig");

pub fn Option(comptime Command: type, comptime Context: type) type {
    return struct {
        const Self = @This();

        id: []const u8,
        flags: []const []const u8 = &.{},
        env: []const u8 = "",
        help: []const u8,
        longHelp: []const u8 = "",
        placeholder: []const u8 = "value",
        is_required: bool = false,
        is_boolean: bool = false,
        is_repeatable: bool = false,
        has_optional_value: bool = false,
        default: []const u8 = "",
        valid_values: []const []const u8 = &.{},

        //validValues: ?*const fn (
        //    ctx: *const Context,
        //    cmd: Command,
        //) anyerror![]const []const u8 = null,

        readAction: ?*const fn (
            ctx: *Context,
            arena: std.mem.Allocator,
            cmd: Command,
            entries: *cli.Entries,
            entry: cli.Entry,
        ) anyerror!void = null,

        action: *const fn (
            ctx: *Context,
            arena: std.mem.Allocator,
            cmd: Command,
            value: []const u8,
        ) anyerror!void,

        const LoadError = error{
            CannotRunAction,
            MissingEntry,
            RepeatedFlag,
        } || ValidateError;

        pub fn load(
            opt: Self,
            arena: std.mem.Allocator,
            cmd: Command,
            ctx: *Context,
            entries: []const cli.Entry,
        ) LoadError!void {
            var action_entry: ?cli.Entry = null;
            var loaded_from_flag = false;

            for (entries) |entry| {
                if (!bytes.equal(entry.command, cmd.id))
                    continue;

                switch (entry.kind) {
                    .env => {
                        if (loaded_from_flag) continue;

                        const prefix = cmd.env_prefix;

                        if (prefix.len > 0 and
                            !bytes.startsWith(entry.key, prefix))
                            continue;

                        const key = entry.key[prefix.len..];
                        if (!bytes.equal(key, opt.env)) continue;

                        action_entry = .{
                            .kind = entry.kind,
                            .command = entry.command,
                            .key = key,
                            .value = entry.value,
                        };
                    },

                    .flag => {
                        if (cmd.flags_prefix.len > 0 and
                            !bytes.startsWith(entry.key, cmd.flags_prefix))
                            continue;

                        const key = entry.key[cmd.flags_prefix.len..];
                        if (!bytes.equalAny(key, opt.flags)) continue;

                        if (loaded_from_flag and !opt.is_repeatable) {
                            const msg = "repeated flag '{s}'";
                            cmd.log.errf(arena, msg, .{entry.key});
                            return error.RepeatedFlag;
                        }

                        const value = entry.value;

                        if (value.len > 0)
                            opt.validate(value) catch |err| {
                                const msg = "invalid value '{s}' for flag '{s}'";
                                cmd.log.withError(err).errf(arena, msg, .{ value, entry.key });
                                return err;
                            };

                        opt.action(ctx, arena, cmd, value) catch |err| {
                            const msg = "cannot load value '{s}' from flag '{s}'";
                            cmd.log.withError(err).errf(arena, msg, .{ value, entry.key });
                            return error.CannotRunAction;
                        };

                        loaded_from_flag = true;
                    },

                    .command, .argument => break,
                }
            }

            if (loaded_from_flag) return;

            if (opt.is_required and action_entry == null) {
                cmd.log.err("option not specified");
                return error.MissingEntry;
            }

            if (action_entry == null) return;

            const entry = action_entry.?;

            const from = if (entry.kind == .env)
                "environment variable"
            else
                "manual entry";

            const prefix = if (entry.kind == .env)
                cmd.env_prefix
            else
                "";

            const key = entry.key;
            const value = entry.value;

            opt.validate(value) catch |err| {
                const msg = "invalid value '{s}' for {s} '{s}{s}'";
                cmd.log.withError(err).errf(arena, msg, .{ value, from, prefix, key });
                return err;
            };

            opt.action(ctx, arena, cmd, value) catch |err| {
                const msg = "cannot load value '{s}' from {s} '{s}{s}'";
                cmd.log.withError(err).errf(arena, msg, .{ value, from, prefix, key });
                return error.CannotRunAction;
            };
        }

        const ValidateError = error{InvalidValue};

        fn validate(opt: Self, value: []const u8) ValidateError!void {
            if (opt.valid_values.len == 0) return;

            if (!bytes.equalAny(value, opt.valid_values))
                return error.InvalidValue;
        }
    };
}
