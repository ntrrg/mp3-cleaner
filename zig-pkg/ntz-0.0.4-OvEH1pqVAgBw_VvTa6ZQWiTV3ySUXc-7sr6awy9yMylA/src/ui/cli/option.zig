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
            entry: cli.Entry,
        ) anyerror!void,

        pub const LoadError = error{
            MissingEntry,
            RepeatedFlag,
        } || LoadEntryError;

        pub fn load(
            opt: Self,
            arena: std.mem.Allocator,
            cmd: Command,
            ctx: *Context,
            entries: []const cli.Entry,
        ) LoadError!void {
            var action_entry: ?cli.Entry = null;
            var loaded_from_env = false;
            var loaded_from_flag = false;

            for (entries) |entry| {
                if (!bytes.equal(entry.command, cmd.id))
                    continue;

                switch (entry.kind) {
                    .config => {
                        if (loaded_from_flag or loaded_from_env) continue;
                        opt.shouldLoad(cmd, entry) catch continue;
                        action_entry = entry;
                    },

                    .env => {
                        if (loaded_from_flag) continue;
                        opt.shouldLoad(cmd, entry) catch continue;
                        action_entry = entry;
                        loaded_from_env = true;
                    },

                    .flag => {
                        opt.shouldLoad(cmd, entry) catch continue;

                        if (loaded_from_flag and !opt.is_repeatable) {
                            const msg = "repeated flag '{s}'";
                            cmd.log.errf(arena, msg, .{entry.key});
                            return error.RepeatedFlag;
                        }

                        try opt.loadEntry(arena, cmd, ctx, entry);
                        loaded_from_flag = true;
                    },

                    .command, .argument, .arbitrary => break,
                }
            }

            if (loaded_from_flag) return;

            if (opt.is_required and action_entry == null) {
                cmd.log.err("option not specified");
                return error.MissingEntry;
            }

            if (action_entry == null) return;
            try opt.loadEntry(arena, cmd, ctx, action_entry.?);
        }

        pub const LoadEntryError = error{CannotRunAction} || ValidateError;

        fn loadEntry(
            opt: Self,
            arena: std.mem.Allocator,
            cmd: Command,
            ctx: *Context,
            entry: cli.Entry,
        ) LoadEntryError!void {
            const from = switch (entry.kind) {
                .config => "configuration entry",
                .env => "environment variable",
                .flag => "flag",
                else => unreachable,
            };

            opt.validate(entry.value) catch |err| {
                cmd.log.withError(err).errf(
                    arena,
                    "invalid value '{s}' for {s} '{s}'",
                    .{ entry.value, from, entry.key },
                );

                return err;
            };

            opt.action(ctx, arena, cmd, entry) catch |err| {
                cmd.log.withError(err).errf(
                    arena,
                    "cannot load value '{s}' from {s} '{s}'",
                    .{ entry.value, from, entry.key },
                );

                return error.CannotRunAction;
            };
        }

        const ShouldLoadError = error{
            InvalidEntryKind,
            InvalidPrefix,
            InvalidEntry,
        };

        fn shouldLoad(
            opt: Self,
            cmd: Command,
            entry: cli.Entry,
        ) ShouldLoadError!void {
            const prefix = switch (entry.kind) {
                .config => "",
                .env => cmd.env_prefix,
                .flag => cmd.flags_prefix,
                else => return error.InvalidEntryKind,
            };

            if (prefix.len > 0 and !bytes.startsWith(entry.key, prefix))
                return error.InvalidPrefix;

            const key = entry.key[prefix.len..];

            switch (entry.kind) {
                .config => if (bytes.equal(key, opt.id)) return,
                .env => if (bytes.equal(key, opt.env)) return,
                .flag => if (bytes.equalAny(key, opt.flags)) return,
                else => {},
            }

            return error.InvalidEntry;
        }

        pub const ValidateError = error{InvalidValue};

        fn validate(opt: Self, value: []const u8) ValidateError!void {
            if (opt.valid_values.len == 0) return;

            if (!bytes.equalAny(value, opt.valid_values))
                return error.InvalidValue;
        }
    };
}
